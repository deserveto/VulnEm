"""Docker-backed sandbox: all agent commands run inside a disposable container.

The container is built from ``containers/Dockerfile`` (Debian + pentest
tooling, non-root ``pentester`` user). For lab runs the container is attached
to an internal Docker network that hosts the target, so the agent physically
cannot reach anything outside the lab.

Phase 3: the sandbox optionally routes its HTTP traffic through the mitmproxy
sidecar (``proxy_url``) — exec'd clients that honor http_proxy/https_proxy
(curl, requests, Go tools, the browser daemon) are captured and scope-checked
by the proxy's allowlist addon. The internal lab network stays the hard
backstop for everything that ignores proxy env vars.
"""

from __future__ import annotations

import io
import logging
import shlex
import tarfile
import time
import uuid
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

import docker
from docker.errors import ImageNotFound, NotFound

logger = logging.getLogger(__name__)


class SandboxError(RuntimeError):
    """Sandbox lifecycle or execution failure."""


@dataclass(slots=True)
class ExecResult:
    exit_code: int
    stdout: str
    stderr: str
    duration: float


class Sandbox:
    """One disposable container per scan."""

    def __init__(
        self,
        *,
        image: str,
        user: str,
        network: str | None = None,
        name_prefix: str = "vulnem-sandbox",
        proxy_url: str | None = None,
        source_dir: str | None = None,
    ) -> None:
        self._image = image
        self._user = user
        self._network = network
        self._proxy_url = proxy_url
        self._source_dir = source_dir
        self._name = f"{name_prefix}-{uuid.uuid4().hex[:8]}"
        self._client: docker.DockerClient | None = None
        self._container = None

    @property
    def proxy_url(self) -> str | None:
        """The HTTP proxy every sandbox client is pointed at (or None)."""
        return self._proxy_url

    @property
    def source_mount(self) -> str | None:
        """In-sandbox path where --source is mounted read-only (or None)."""
        return f"/home/{self._user}/source" if self._source_dir else None

    # -- lifecycle ---------------------------------------------------------

    def start(self) -> None:
        """Create and start the sandbox container."""
        try:
            self._client = docker.from_env()
        except docker.errors.DockerException as exc:  # pragma: no cover - env specific
            raise SandboxError(f"Could not connect to Docker: {exc}") from exc
        try:
            self._client.images.get(self._image)
        except ImageNotFound as exc:
            raise SandboxError(
                f"Sandbox image {self._image!r} not found. Run `vulnem build` first."
            ) from exc

        kwargs: dict = {
            "name": self._name,
            "detach": True,
            # Keep the container alive; the agent drives it via exec.
            "command": ["/bin/bash", "-lc", "exec sleep infinity"],
            "user": self._user,
            "working_dir": f"/home/{self._user}",
            "tty": False,
        }
        if self._network:
            kwargs["network"] = self._network
        if self._source_dir:
            # White-box mode: the target's source rides along read-only, so
            # agents can read code and run semgrep but never modify the repo.
            src = Path(self._source_dir).resolve()
            if not src.is_dir():
                raise SandboxError(f"--source directory not found: {src}")
            kwargs["volumes"] = {str(src): {
                "bind": f"/home/{self._user}/source", "mode": "ro"}}
        logger.info("starting sandbox container %s (image=%s network=%s)",
                    self._name, self._image, self._network or "default")
        self._container = self._client.containers.run(self._image, **kwargs)

    def stop(self) -> None:
        """Remove the container (best effort — never raises)."""
        if self._container is None:
            return
        try:
            self._container.remove(force=True, v=True)
            logger.info("removed sandbox container %s", self._name)
        except NotFound:
            pass
        except Exception:  # pragma: no cover - teardown must not fail the scan
            logger.exception("failed to remove sandbox container %s", self._name)
        finally:
            self._container = None

    @property
    def container_name(self) -> str:
        return self._name

    # -- execution ---------------------------------------------------------

    def exec(self, command: str, *, timeout: int = 120) -> ExecResult:
        """Run a shell command inside the sandbox.

        The command is wrapped in ``timeout`` so runaway processes are killed;
        the whole call is additionally bounded client-side.
        """
        if self._container is None:
            raise SandboxError("Sandbox is not running")
        script = f"timeout -k 5 {max(1, int(timeout))} bash -c {shlex.quote(command)}"
        started = time.monotonic()
        env = {"HOME": f"/home/{self._user}"}
        if self._proxy_url:
            # Route HTTP clients through the mitmproxy sidecar (scope-checked).
            # Localhost (the browser daemon) is never proxied.
            env.update({
                "http_proxy": self._proxy_url,
                "https_proxy": self._proxy_url,
                "HTTP_PROXY": self._proxy_url,
                "HTTPS_PROXY": self._proxy_url,
                "no_proxy": "localhost,127.0.0.1",
                "NO_PROXY": "localhost,127.0.0.1",
            })
        result = self._container.exec_run(
            ["/bin/bash", "-lc", script],
            user=self._user,
            environment=env,
            demux=True,
        )
        duration = time.monotonic() - started
        stdout = (result.output[0] or b"").decode("utf-8", errors="replace")
        stderr = (result.output[1] or b"").decode("utf-8", errors="replace")
        exit_code = result.exit_code
        if exit_code == 124:
            stderr += f"\n[vulnem] command exceeded {timeout}s timeout and was killed"
        return ExecResult(
            exit_code=exit_code if exit_code is not None else -1,
            stdout=stdout,
            stderr=stderr,
            duration=duration,
        )

    # -- file transfer ------------------------------------------------------

    def put_file(self, data: bytes, container_path: str) -> None:
        """Write bytes to an absolute path inside the sandbox container."""
        if self._container is None:
            raise SandboxError("Sandbox is not running")
        path = PurePosixPath(container_path)  # container paths are always POSIX
        tar_bytes = _tar_member(path.name, data)
        ok = self._container.put_archive(str(path.parent), tar_bytes)
        if not ok:
            raise SandboxError(f"put_archive failed for {container_path}")

    def get_file(self, container_path: str) -> bytes:
        """Read a file's bytes out of the sandbox container."""
        if self._container is None:
            raise SandboxError("Sandbox is not running")
        stream, _stat = self._container.get_archive(container_path)
        data = b"".join(chunk for chunk in stream if isinstance(chunk, bytes))
        with tarfile.open(fileobj=io.BytesIO(data)) as tar:
            for member in tar.getmembers():
                if member.isfile():
                    fh = tar.extractfile(member)
                    if fh is not None:
                        return fh.read()
        raise SandboxError(f"{container_path} is not a regular file in the sandbox")

    # -- helpers -----------------------------------------------------------

    def wait_for_http(self, url: str, *, attempts: int = 60, delay: float = 2.0) -> bool:
        """Poll a URL from inside the sandbox until it answers (or give up)."""
        for attempt in range(attempts):
            res = self.exec(f"curl -sf -o /dev/null -m 5 {shlex.quote(url)}", timeout=30)
            if res.exit_code == 0:
                return True
            if attempt < attempts - 1:
                time.sleep(delay)
        return False


def _tar_member(name: str, data: bytes) -> bytes:
    """Build a one-member tar archive in memory (for put_archive)."""
    info = tarfile.TarInfo(name=name)
    info.size = len(data)
    info.mode = 0o644
    info.mtime = int(time.time())
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def build_image(*, dockerfile_dir: Path, tag: str) -> None:
    """Build the sandbox image, printing progress lines as they arrive."""
    client = docker.from_env()
    print(f"[vulnem] building sandbox image {tag} from {dockerfile_dir} ...")
    build_log = client.api.build(path=str(dockerfile_dir), tag=tag, decode=True, rm=True)
    for chunk in build_log:
        if "stream" in chunk:
            line = chunk["stream"].rstrip()
            if line:
                print(f"  {line}")
        elif "error" in chunk:
            raise SandboxError(f"image build failed: {chunk['error']}")
    print(f"[vulnem] image {tag} ready")
