"""Scanner tests. Network is mocked, plus one real test on 127.0.0.1 (no internet needed)."""
import socket
import threading
import time

import pytest

from app import scanner
from app.scanner import check_port, scan_ports
from app.target_validation import ValidatedTarget

TARGET = ValidatedTarget(label="127.0.0.1", ip="127.0.0.1")


class FakeSocket:
    def __init__(self, data=b""):
        self.data = data
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.closed = True

    def settimeout(self, t):
        pass

    def recv(self, n):
        return self.data[:n]


def raising(exc):
    def connect(addr, timeout):
        raise exc
    return connect


def test_open_port():
    r = check_port("127.0.0.1", 80, 1, connect=lambda a, t: FakeSocket())
    assert r.state == "open" and r.service_hint == "HTTP" and r.banner is None


def test_closed_port_connection_refused():
    r = check_port("127.0.0.1", 81, 1, connect=raising(ConnectionRefusedError()))
    assert r.state == "closed"


def test_timeout_is_unknown_not_closed():
    r = check_port("127.0.0.1", 82, 1, connect=raising(socket.timeout()))
    assert r.state == "unknown" and "timeout" in r.reason.lower()


def test_builtin_timeout_error_is_unknown():
    assert check_port("127.0.0.1", 82, 1, connect=raising(TimeoutError())).state == "unknown"


def test_other_os_error_is_unknown_and_does_not_crash():
    r = check_port("127.0.0.1", 83, 1, connect=raising(OSError(101, "Network is unreachable")))
    assert r.state == "unknown" and "101" in r.reason


def test_os_error_without_errno():
    assert check_port("127.0.0.1", 83, 1, connect=raising(OSError())).state == "unknown"


def test_banner_is_not_collected_by_default():
    r = check_port("127.0.0.1", 22, 1, connect=lambda a, t: FakeSocket(b"SSH-2.0-Test\r\n"))
    assert r.banner is None


def test_banner_collected_and_sanitized_when_enabled():
    data = b"SSH-2.0-Test\r\n\x00\x01\xff  extra" + b"A" * 500
    r = check_port("127.0.0.1", 22, 1, grab_banner=True, connect=lambda a, t: FakeSocket(data))
    assert r.banner.startswith("SSH-2.0-Test")
    assert len(r.banner) <= 100
    assert all(32 <= ord(c) < 127 for c in r.banner)


def test_banner_read_error_still_open():
    class Broken(FakeSocket):
        def recv(self, n):
            raise socket.timeout()
    r = check_port("127.0.0.1", 22, 1, grab_banner=True, connect=lambda a, t: Broken())
    assert r.state == "open" and r.banner is None


def test_scan_ports_sorted_and_mixed(monkeypatch):
    def fake_check(ip, port, timeout, grab_banner=False, connect=None):
        state = {80: "open", 81: "closed"}.get(port, "unknown")
        return scanner.PortResult(port=port, state=state, reason="x")
    monkeypatch.setattr(scanner, "check_port", fake_check)
    results = scan_ports(TARGET, [82, 80, 81], 1)
    assert [r.port for r in results] == [80, 81, 82]
    assert [r.state for r in results] == ["open", "closed", "unknown"]


def test_scan_deadline_marks_remaining_unknown(monkeypatch):
    called = []
    monkeypatch.setattr(scanner, "check_port", lambda *a, **k: called.append(1))
    results = scan_ports(TARGET, [80, 81], 1, deadline_seconds=-1)
    assert called == []
    assert all(r.state == "unknown" and "time limit" in r.reason for r in results)


def test_concurrency_is_capped(monkeypatch):
    active, peak, lock = 0, 0, threading.Lock()

    def slow_check(ip, port, timeout, grab_banner=False, connect=None):
        nonlocal active, peak
        with lock:
            active += 1
            peak = max(peak, active)
        time.sleep(0.02)
        with lock:
            active -= 1
        return scanner.PortResult(port=port, state="closed", reason="x")

    monkeypatch.setattr(scanner, "check_port", slow_check)
    scan_ports(TARGET, list(range(1, 41)), 1, max_workers=1000)
    assert peak <= scanner.config.MAX_WORKERS


def test_real_localhost_open_and_closed_ports():
    """Real sockets on 127.0.0.1 only: one listening port, one closed port."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    open_port = server.getsockname()[1]

    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    closed_port = probe.getsockname()[1]
    probe.close()  # nothing listens here now
    try:
        assert check_port("127.0.0.1", open_port, 3).state == "open"
        assert check_port("127.0.0.1", closed_port, 3).state == "closed"
    finally:
        server.close()
