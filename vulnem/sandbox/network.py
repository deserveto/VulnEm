"""Per-scan user-defined Docker networks.

Container-name DNS — how the sandbox reaches the mitmproxy sidecar as
``http://vulnem-proxy-<hex>:8080`` — only exists on USER-DEFINED networks.
The default bridge has no embedded DNS, so live-target scans (no
``--network``) that land both containers there break the proxy path
silently: every proxied request dies with "Could not resolve proxy" and
agents learn to bypass the proxy.

When no network is configured we therefore create an ephemeral
user-defined bridge and attach BOTH the sidecar and the sandbox to it.
It is a normal bridge (``internal`` is NOT set): the sandbox still NATs
outbound to reach live targets on the internet — only lab networks are
internal.
"""

from __future__ import annotations

import logging
import uuid

logger = logging.getLogger(__name__)


def ensure_scan_network(requested: str | None) -> str | None:
    """Return the Docker network a scan should run on.

    A configured network (lab runs via ``--network``) is passed through
    unchanged. ``None`` (live-target runs) gets a fresh ephemeral
    user-defined bridge. Returns ``None`` if creation fails — the scan
    then continues on the default bridge, where the proxy healthcheck
    will (honestly) report the network scope layer as down.
    """
    if requested:
        return requested
    import docker

    name = f"vulnem-net-{uuid.uuid4().hex[:8]}"
    try:
        client = docker.from_env()
        # NOT internal: the sandbox must reach live targets on the internet.
        client.networks.create(name, driver="bridge")
        logger.info("created ephemeral scan network %s", name)
        return name
    except Exception:
        logger.exception("could not create ephemeral scan network; "
                         "continuing on the default bridge")
        return None


def connect_container(network: str, container_name: str) -> bool:
    """Attach a RUNNING container to a user-defined network (best effort).

    Used for the sandbox, which is created by the caller before the proxy
    sidecar's ephemeral network is known; Docker updates the container's
    resolver so container-name DNS works for later execs.
    """
    import docker

    try:
        client = docker.from_env()
        client.networks.get(network).connect(container_name)
        logger.info("connected %s to network %s", container_name, network)
        return True
    except Exception:
        logger.exception("could not connect %s to network %s", container_name, network)
        return False


def teardown_scan_network(name: str | None) -> None:
    """Remove an ephemeral network (best effort — never raises).

    Call only after the containers on it are removed, so the network
    deletes cleanly instead of being left dangling.
    """
    if not name:
        return
    import docker

    try:
        client = docker.from_env()
        client.networks.get(name).remove()
        logger.info("removed scan network %s", name)
    except Exception:
        logger.exception("could not remove scan network %s", name)
