"""Host-side manager for the mitmproxy sidecar.

One sidecar container per scan, attached to the sandbox's network. The
sandbox's HTTP clients are pointed at it (Sandbox(proxy_url=...)); its
addon (``scope_guard.py``) enforces the scan scope at the network layer and
writes two JSON-line logs inside the container:

- ``flows.jsonl`` — every proxied request/response (the proxy tools' data)
- ``blocked.jsonl`` — every out-of-scope attempt (also surfaced in the
  transcript + run dir by the poller)

The host reads both via docker get_archive; no shared volume needed.
"""

from __future__ import annotations

import asyncio
import contextlib
import io
import json
import logging
import tarfile
import time
import uuid
from pathlib import Path
from typing import Any

from vulnem.scope import Scope

logger = logging.getLogger(__name__)

SIDECAR_IMAGE = "mitmproxy/mitmproxy:latest"
FLOW_DIR = "/tmp/vulnem-flows"
POLL_INTERVAL_S = 3.0


class ProxyError(RuntimeError):
    """Sidecar lifecycle failure."""


class ProxyManager:
    """Owns the mitmproxy sidecar for one scan."""

    def __init__(self, *, scope: Scope, network: str | None = None,
                 image: str = SIDECAR_IMAGE) -> None:
        self._scope = scope
        self._network = network
        self._image = image
        self._name = f"vulnem-proxy-{uuid.uuid4().hex[:8]}"
        self._container = None
        self._client = None
        self._coordinator: Any = None
        self._run_dir: Path | None = None
        self._emitted_flows = 0
        self._emitted_blocked = 0

    # -- lifecycle ---------------------------------------------------------

    @property
    def name(self) -> str:
        return self._name

    @property
    def sandbox_proxy_url(self) -> str:
        """The proxy address as the sandbox reaches it (container-name DNS)."""
        return f"http://{self._name}:8080"

    def start(self) -> None:
        """Create + start the sidecar (sync; call from a worker thread)."""
        import docker
        from docker.errors import ImageNotFound

        try:
            self._client = docker.from_env()
        except docker.errors.DockerException as exc:
            raise ProxyError(f"could not connect to Docker: {exc}") from exc
        try:
            self._client.images.get(self._image)
        except ImageNotFound:
            logger.info("pulling sidecar image %s", self._image)
            self._client.images.pull(self._image)

        addon_src = Path(__file__).with_name("scope_guard.py").read_bytes()
        self._container = self._client.containers.create(
            self._image,
            name=self._name,
            detach=True,
            network=self._network,
            entrypoint=["sh", "-c",
                        f"mkdir -p {FLOW_DIR} && exec mitmdump --listen-host 0.0.0.0 "
                        f"--listen-port 8080 -s /tmp/scope_guard.py --set flow_detail=0 "
                        f"--set termlog_verbosity=warn"],
            environment={
                "VULNEM_SCOPE_HOSTS": ",".join(self._scope.allowed_hosts),
                "VULNEM_FLOW_DIR": FLOW_DIR,
            },
            labels={"vulnem": "proxy-sidecar"},
        )
        # Ship the addon before start so mitmdump loads it on boot.
        self._container.put_archive("/tmp", _tar_one("scope_guard.py", addon_src))
        self._container.start()
        logger.info("proxy sidecar %s started (network=%s scope=%s)",
                    self._name, self._network or "default", self._scope.allowed_hosts)
        if not self._wait_listening():
            logs = ""
            with contextlib.suppress(Exception):
                logs = self._container.logs(tail=20).decode("utf-8", "replace")
            self.stop()
            raise ProxyError(f"mitmproxy sidecar never came up. Logs:\n{logs}")

    def _wait_listening(self, attempts: int = 30, delay: float = 1.0) -> bool:
        probe = (
            "import socket; socket.create_connection(('127.0.0.1', 8080), 3).close()"
        )
        for _ in range(attempts):
            try:
                res = self._container.exec_run(["python3", "-c", probe])
                if res.exit_code == 0:
                    return True
            except Exception:
                pass
            time.sleep(delay)
        return False

    def stop(self) -> None:
        """Remove the sidecar (best effort — never raises)."""
        if self._container is None:
            return
        try:
            self._container.remove(force=True, v=True)
            logger.info("removed proxy sidecar %s", self._name)
        except Exception:  # teardown must not fail the scan
            logger.exception("failed to remove proxy sidecar %s", self._name)
        finally:
            self._container = None

    async def start_async(self) -> None:
        await asyncio.to_thread(self.start)

    async def stop_async(self) -> None:
        await asyncio.to_thread(self.stop)

    # -- log readers ---------------------------------------------------------

    def _read_log(self, name: str) -> list[dict]:
        """Pull one JSONL log out of the sidecar (missing → empty)."""
        if self._container is None:
            return []
        try:
            stream, _stat = self._container.get_archive(f"{FLOW_DIR}/{name}")
        except Exception:
            return []  # not created yet — no traffic / no blocks
        data = b"".join(c for c in stream if isinstance(c, bytes))
        records: list[dict] = []
        try:
            with tarfile.open(fileobj=io.BytesIO(data)) as tar:
                for member in tar.getmembers():
                    if not member.isfile():
                        continue
                    fh = tar.extractfile(member)
                    if fh is None:
                        continue
                    for line in fh.read().decode("utf-8", "replace").splitlines():
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            records.append(json.loads(line))
                        except ValueError:
                            continue  # torn tail line mid-write
        except tarfile.TarError:
            return records
        return records

    def read_flows(self) -> list[dict]:
        return self._read_log("flows.jsonl")

    def read_blocked(self) -> list[dict]:
        return self._read_log("blocked.jsonl")

    def snapshot_evidence(self, run_dir: Path) -> None:
        """Copy the full flow log into the run dir as report evidence."""
        try:
            flows = self.read_flows()
            blocked = self.read_blocked()
            (run_dir / "proxy-flows.jsonl").write_text(
                "".join(json.dumps(f, ensure_ascii=False) + "\n" for f in flows),
                encoding="utf-8",
            )
            (run_dir / "proxy-blocked.jsonl").write_text(
                "".join(json.dumps(b, ensure_ascii=False) + "\n" for b in blocked),
                encoding="utf-8",
            )
        except Exception:
            logger.exception("could not snapshot proxy logs into %s", run_dir)

    # -- transcript bridge ------------------------------------------------------

    def bind(self, coordinator: Any, run_dir: Path) -> None:
        """Give the poller a coordinator (transcript) + run dir to write to."""
        self._coordinator = coordinator
        self._run_dir = run_dir

    async def poll_loop(self) -> None:
        """Emit proxy events into the transcript until cancelled."""
        try:
            while True:
                await asyncio.sleep(POLL_INTERVAL_S)
                flows, blocked = await asyncio.to_thread(
                    lambda: (self.read_flows(), self.read_blocked())
                )
                self._emit_new(flows, blocked)
        except asyncio.CancelledError:
            raise

    def _emit_new(self, flows: list[dict], blocked: list[dict]) -> None:
        if self._coordinator is None:
            return
        for record in flows[self._emitted_flows:]:
            self._coordinator.emit({
                "type": "proxy_flow",
                "i": record.get("i"),
                "method": record.get("method"),
                "host": record.get("host"),
                "path": (record.get("path") or "")[:300],
                "status": record.get("status"),
            })
        self._emitted_flows = len(flows)
        blocked_path = self._run_dir / "proxy-blocked.jsonl" if self._run_dir else None
        for record in blocked[self._emitted_blocked:]:
            self._coordinator.emit({
                "type": "scope_blocked",
                "layer": "proxy",
                "host": record.get("host"),
                "method": record.get("method"),
                "client": record.get("client"),
                "reason": record.get("reason"),
            })
            if blocked_path is not None:
                try:
                    blocked_path.parent.mkdir(parents=True, exist_ok=True)
                    with blocked_path.open("a", encoding="utf-8") as fh:
                        fh.write(json.dumps(record, ensure_ascii=False) + "\n")
                except OSError:
                    logger.exception("could not append blocked log")
        self._emitted_blocked = len(blocked)

    def drain_final_events(self) -> None:
        """One last read when the scan ends, so the transcript is complete."""
        try:
            self._emit_new(self.read_flows(), self.read_blocked())
        except Exception:
            logger.exception("final proxy event drain failed")


def _tar_one(name: str, data: bytes) -> bytes:
    info = tarfile.TarInfo(name=name)
    info.size = len(data)
    info.mode = 0o644
    info.mtime = int(time.time())
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()
