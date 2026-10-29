"""Target validation: no network needed."""
import pytest

from app import config
from app.target_validation import ConfigError, TargetValidationError, validate_target

ALLOWED = ["127.0.0.1", "localhost"]


def code_of(raw, allowed=ALLOWED):
    with pytest.raises(TargetValidationError) as info:
        validate_target(raw, allowed)
    return info.value.code


def test_valid_loopback_ip():
    t = validate_target("127.0.0.1", ALLOWED)
    assert (t.label, t.ip) == ("127.0.0.1", "127.0.0.1")


@pytest.mark.parametrize("name", ["localhost", "LOCALHOST", "LocalHost"])
def test_localhost_maps_to_loopback_without_dns(name):
    t = validate_target(name, ALLOWED)
    assert t.label == "localhost" and t.ip == "127.0.0.1"


def test_configured_private_lab_target_allowed():
    t = validate_target("192.168.56.101", ALLOWED + ["192.168.56.101"])
    assert t.ip == "192.168.56.101"


def test_private_address_not_in_allowlist_rejected():
    assert code_of("192.168.56.101") == "target_not_allowed"


@pytest.mark.parametrize("ip", ["8.8.8.8", "1.1.1.1", "93.184.216.34", "100.64.0.1"])
def test_public_ips_rejected(ip):
    assert code_of(ip, ALLOWED + [ip]) == "target_not_private"


@pytest.mark.parametrize("ip", ["169.254.1.1", "0.0.0.0", "224.0.0.1", "255.255.255.255"])
def test_special_ranges_rejected(ip):
    assert code_of(ip, ALLOWED + [ip]) == "target_not_private"


@pytest.mark.parametrize("bad", [
    "", " ", "example.com", "www.google.com", "http://127.0.0.1", "https://localhost",
    "127.0.0.1:80", "127.0.0.1/24", "127.0.0.1/path", "user@127.0.0.1",
    "127.0.0.1 ", " 127.0.0.1", "127.0.0.1\n", "127.1", "127.0.0",
    "127.0.0.1.1", "256.1.1.1", "localhost.", "localhost:8000",
    "::1", "[::1]", "0x7f.0.0.1", "0x7f000001", "2130706433",
    "0177.0.0.1", "127.000.000.001", "127.0.0.01", "-127.0.0.1",
    "１２７.０.０.１",  # full-width unicode digits
    "127.0.0.1; ls", "127.0.0.1 && whoami", "a" * 100,
])
def test_invalid_or_tricky_formats_rejected(bad):
    assert code_of(bad, ALLOWED + ["2130706433", "127.1"]) == "invalid_target"


def test_non_string_rejected():
    assert code_of(12345) == "invalid_target"
    assert code_of(None) == "invalid_target"


def test_localhost_must_be_in_allowlist():
    assert code_of("localhost", ["127.0.0.1"]) == "target_not_allowed"


def test_error_messages_do_not_echo_input():
    with pytest.raises(TargetValidationError) as info:
        validate_target("http://evil.example/steal", ALLOWED)
    assert "evil" not in info.value.message


def test_lab_env_accepts_private_ip():
    assert config.load_lab_targets("192.168.56.101, 10.0.0.5") == ["192.168.56.101", "10.0.0.5"]


@pytest.mark.parametrize("raw", ["8.8.8.8", "example.com", "192.168.1.1,8.8.8.8", "169.254.1.1", "0.0.0.0"])
def test_lab_env_rejects_unsafe_values(raw):
    with pytest.raises(ConfigError):
        config.load_lab_targets(raw)


def test_lab_env_empty_is_ok():
    assert config.load_lab_targets(None) == []
    assert config.load_lab_targets("") == []
