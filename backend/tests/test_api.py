"""API tests. Scanning is mocked, so no real connections are made."""
import csv
import io
import json

import pytest
from fastapi.testclient import TestClient

from app import scanner
from app.main import app
from app.schemas import PortResult

client = TestClient(app, raise_server_exceptions=False)


@pytest.fixture
def fake_network(monkeypatch):
    calls = []

    def fake_check(ip, port, timeout, grab_banner=False, connect=None):
        calls.append((ip, port))
        if port == 23:
            return PortResult(port=23, state="open", reason="ok")
        if port == 22:
            return PortResult(port=22, state="open", reason="ok", banner="=cmd|' /C calc'!A0")
        return PortResult(port=port, state="closed", reason="refused")

    monkeypatch.setattr(scanner, "check_port", fake_check)
    return calls


def post(body):
    return client.post("/api/scan", json=body)


def test_health():
    assert client.get("/api/health").json() == {"status": "ok"}


def test_config_endpoint():
    data = client.get("/api/scan/config").json()
    assert data["default_target"] == "127.0.0.1"
    assert "127.0.0.1" in data["allowed_targets"] and "localhost" in data["allowed_targets"]
    assert data["limits"]["max_port"] == 10000


def test_scan_default_localhost(fake_network):
    r = post({})
    assert r.status_code == 200
    body = r.json()
    assert body["target"] == "127.0.0.1"
    assert body["summary"]["ports_scanned"] == len(body["ports"]) == len(body["settings"]["ports"])
    assert body["summary"]["open"] == 2  # the fake network opens only ports 22 and 23
    assert {p["port"] for p in body["ports"]} >= {22, 23}
    assert any(f["id"] == "NVS-PORT-23" for f in body["findings"])
    assert body["limitations"]


def test_scan_uses_validated_ip_for_localhost(fake_network):
    post({"target": "LOCALHOST", "ports": [80]})
    assert fake_network == [("127.0.0.1", 80)]


@pytest.mark.parametrize("target,status", [
    ("8.8.8.8", 403), ("example.com", 422), ("http://127.0.0.1", 422),
    ("192.168.1.10", 403), ("2130706433", 422), ("127.0.0.1:22", 422),
])
def test_rejected_targets_never_touch_network(fake_network, target, status):
    r = post({"target": target})
    assert r.status_code == status
    assert fake_network == []
    assert target not in r.json()["detail"]


@pytest.mark.parametrize("ports", [[0], [-1], [10001], [65536], ["abc"], [1.5], list(range(1, 52))])
def test_invalid_ports_rejected(fake_network, ports):
    r = post({"ports": ports})
    assert r.status_code == 422
    assert fake_network == []


@pytest.mark.parametrize("timeout", [0, 0.01, 6, -1, "x"])
def test_invalid_timeout_rejected(fake_network, timeout):
    assert post({"timeout_seconds": timeout}).status_code == 422


def test_duplicate_ports_removed(fake_network):
    body = post({"ports": [80, 80, 81]}).json()
    assert body["settings"]["ports"] == [80, 81]


def test_extra_fields_rejected(fake_network):
    assert post({"target": "127.0.0.1", "command": "whoami"}).status_code == 422


def test_invalid_json_and_missing_body():
    r = client.post("/api/scan", content="not json", headers={"Content-Type": "application/json"})
    assert r.status_code == 422
    assert "not json" not in r.text
    assert client.post("/api/scan").status_code == 422


def test_wrong_method():
    assert client.get("/api/health", params={}).status_code == 200
    assert client.put("/api/scan").status_code == 405


def test_get_scan_and_unknown_id(fake_network):
    sid = post({"ports": [23]}).json()["scan_id"]
    assert client.get(f"/api/scan/{sid}").json()["scan_id"] == sid
    assert client.get("/api/scan/" + "0" * 32).status_code == 404
    assert client.get("/api/scan/..%2F..%2Fetc%2Fpasswd").status_code in (404, 422)
    assert client.get("/api/scan/not-a-valid-id").status_code == 422


def test_json_report(fake_network):
    sid = post({"ports": [22, 23]}).json()["scan_id"]
    r = client.get(f"/api/scan/{sid}/report?format=json")
    assert r.status_code == 200
    assert "attachment" in r.headers["content-disposition"]
    assert json.loads(r.text)["scan_id"] == sid


def test_csv_report_and_formula_injection_protection(fake_network):
    sid = post({"ports": [22, 23], "grab_banner": True}).json()["scan_id"]
    r = client.get(f"/api/scan/{sid}/report?format=csv")
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/csv")
    rows = list(csv.DictReader(io.StringIO(r.text)))
    kinds = {row["record_type"] for row in rows}
    assert kinds == {"port", "finding"}
    for row in rows:
        for value in row.values():
            assert not value.startswith(("=", "+", "-", "@"))
    assert any(row["severity"] == "High" for row in rows)


def test_report_bad_format_and_unknown_scan():
    assert client.get("/api/scan/" + "0" * 32 + "/report?format=exe").status_code == 422
    assert client.get("/api/scan/" + "0" * 32 + "/report").status_code == 404


def test_history_endpoint(fake_network):
    post({"ports": [80]})
    post({"ports": [81]})
    assert len(client.get("/api/scans").json()) == 2


def test_rate_limit(fake_network):
    codes = [post({"ports": [80]}).status_code for _ in range(11)]
    assert codes[:10] == [200] * 10 and codes[10] == 429


def test_busy_scan_returns_429(fake_network):
    from app.store import limiter
    assert limiter.try_start() is None  # simulate a running scan
    r = post({"ports": [80]})
    assert r.status_code == 429


def test_unexpected_error_is_generic(monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("secret internal path /etc/hidden")
    monkeypatch.setattr(scanner, "scan_ports", boom)
    r = post({"ports": [80]})
    assert r.status_code == 500
    assert "secret" not in r.text and "Traceback" not in r.text
    # a failed scan must not leave the limiter locked
    from app.store import limiter
    assert not limiter._running.locked()


def test_cors_allowed_and_blocked_origins():
    ok = client.options("/api/scan", headers={"Origin": "http://localhost:5173",
                                              "Access-Control-Request-Method": "POST"})
    assert ok.headers.get("access-control-allow-origin") == "http://localhost:5173"
    bad = client.options("/api/scan", headers={"Origin": "http://evil.example",
                                               "Access-Control-Request-Method": "POST"})
    assert "access-control-allow-origin" not in bad.headers
