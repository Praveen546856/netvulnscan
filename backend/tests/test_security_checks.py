from app.schemas import PortResult
from app.security_checks import evaluate, severity_counts


def pr(port, state="open", banner=None):
    return PortResult(port=port, state=state, reason="test", banner=banner)


def ids(findings):
    return {f.id for f in findings}


def test_open_telnet_is_high_with_evidence():
    f = evaluate([pr(23)])
    telnet = next(x for x in f if x.id == "NVS-PORT-23")
    assert telnet.severity == "High"
    for field in ("evidence", "explanation", "remediation", "limitations"):
        assert getattr(telnet, field)
    assert telnet.confidence in ("High", "Medium", "Low")


def test_closed_port_creates_no_port_finding():
    assert "NVS-PORT-23" not in ids(evaluate([pr(23, "closed")]))


def test_open_ordinary_port_is_not_called_a_vulnerability():
    f = evaluate([pr(8000)])
    assert all("vulnerab" not in x.title.lower() for x in f)
    assert "NVS-PORT-8000" not in ids(f)


def test_unexpected_port_only_when_expected_list_given():
    assert not any(x.id.startswith("NVS-UNEXPECTED") for x in evaluate([pr(8000)]))
    f = evaluate([pr(8000), pr(80)], expected_ports=[80])
    assert "NVS-UNEXPECTED-8000" in ids(f) and "NVS-UNEXPECTED-80" not in ids(f)


def test_http_without_https():
    assert "NVS-HTTP-NO-HTTPS" in ids(evaluate([pr(80), pr(443, "closed")]))
    assert "NVS-HTTP-NO-HTTPS" not in ids(evaluate([pr(80), pr(443)]))
    assert "NVS-HTTP-NO-HTTPS" not in ids(evaluate([pr(80), pr(443, "unknown")]))


def test_banner_finding_never_claims_outdated():
    f = evaluate([pr(22, banner="SSH-2.0-OpenSSH_8.9")])
    text = " ".join(x.title + x.explanation for x in f).lower()
    assert "outdated" not in text
    assert "NVS-BANNER-22" in ids(f)


def test_ssh_protocol_1_detected_but_199_is_not():
    assert "NVS-SSH1-22" in ids(evaluate([pr(22, banner="SSH-1.5-Old")]))
    assert "NVS-SSH1-22" not in ids(evaluate([pr(22, banner="SSH-1.99-Compat")]))


def test_inconclusive_scan():
    assert "NVS-INCONCLUSIVE" in ids(evaluate([pr(1, "unknown"), pr(2, "unknown"), pr(3, "closed")]))


def test_no_open_ports_info():
    assert "NVS-NO-OPEN" in ids(evaluate([pr(1, "closed"), pr(2, "closed")]))


def test_sorted_by_severity_and_counts():
    f = evaluate([pr(22), pr(23), pr(3306)])
    assert [x.severity for x in f] == sorted([x.severity for x in f],
                                            key=["High", "Medium", "Low", "Info"].index)
    assert severity_counts(f) == {"High": 1, "Medium": 1, "Low": 1, "Info": 0}


def test_empty_results():
    assert evaluate([]) == []
