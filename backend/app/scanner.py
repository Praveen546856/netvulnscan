"""TCP connect scanner (standard library `socket` only).

HOW A TCP CONNECTION TEST WORKS
-------------------------------
TCP starts with a 3-way handshake: client SYN -> server SYN/ACK -> client ACK.
We simply ask the operating system to open a normal connection to ip:port:
  * Handshake completes            -> port is OPEN (something is listening).
  * Server answers with RST        -> port is CLOSED (host is up, nothing listens;
                                      Python raises ConnectionRefusedError).
  * No answer before the timeout   -> UNKNOWN (a firewall may be dropping packets,
                                      or the host is down). We cannot tell which.
  * Any other network error        -> UNKNOWN.
This is the polite, normal "connect scan". There is no stealth, no spoofing,
no exploitation and no flooding: limited threads, one connection per port.

Only validated targets (see target_validation.py) ever reach this module, and
we connect to the validated IP address, never to a hostname.
"""
import socket
import time
from concurrent.futures import ThreadPoolExecutor

from . import config
from .schemas import PortResult
from .services import service_hint
from .target_validation import ValidatedTarget


def _sanitize_banner(data: bytes) -> str | None:
    """Keep printable ASCII only, collapse whitespace, truncate."""
    chars = [chr(b) if 32 <= b < 127 else " " for b in data]
    text = " ".join("".join(chars).split())[: config.MAX_BANNER_CHARS]
    return text or None


def check_port(
    ip: str,
    port: int,
    timeout: float,
    grab_banner: bool = False,
    connect=socket.create_connection,
) -> PortResult:
    """Test one TCP port. Never raises for network problems."""
    hint = service_hint(port)
    try:
        sock = connect((ip, port), timeout)
    except ConnectionRefusedError:
        return PortResult(
            port=port, state="closed", service_hint=hint,
            reason="Connection actively refused (host replied that nothing is listening).",
        )
    except (socket.timeout, TimeoutError):
        return PortResult(
            port=port, state="unknown", service_hint=hint,
            reason="No response before the timeout (port may be filtered, or host unavailable).",
        )
    except OSError as exc:
        code = f" (error code {exc.errno})" if exc.errno is not None else ""
        return PortResult(
            port=port, state="unknown", service_hint=hint,
            reason=f"Network error while connecting{code}.",
        )

    banner = None
    with sock:
        if grab_banner:
            # Passive only: we send nothing, just read what the service volunteers.
            try:
                sock.settimeout(min(timeout, config.BANNER_TIMEOUT))
                banner = _sanitize_banner(sock.recv(config.MAX_BANNER_BYTES))
            except OSError:
                banner = None
    return PortResult(
        port=port, state="open", service_hint=hint,
        reason="TCP handshake completed (something accepted the connection).",
        banner=banner,
    )


def scan_ports(
    target: ValidatedTarget,
    ports: list[int],
    timeout: float,
    grab_banner: bool = False,
    deadline_seconds: float = config.SCAN_DEADLINE_SECONDS,
    max_workers: int = config.MAX_WORKERS,
) -> list[PortResult]:
    """Scan ports with a small thread pool and an overall time limit."""
    end_time = time.monotonic() + deadline_seconds
    workers = max(1, min(max_workers, config.MAX_WORKERS))

    def worker(port: int) -> PortResult:
        if time.monotonic() > end_time:
            return PortResult(
                port=port, state="unknown", service_hint=service_hint(port),
                reason="Scan time limit reached before this port was tested.",
            )
        return check_port(target.ip, port, timeout, grab_banner)

    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = list(pool.map(worker, ports))
    return sorted(results, key=lambda r: r.port)
