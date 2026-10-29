"""Strict target validation.

Rules (all must pass):
 1. Format: exactly the word "localhost" OR a dotted-decimal IPv4 address
    (four decimal numbers 0-255, no leading zeros, ASCII digits only).
    This rejects URLs, ports, paths, whitespace, IPv6, decimal/hex/octal
    tricks (2130706433, 0x7f.1, 0177.0.0.1) and look-alike unicode digits.
 2. The address must be private/loopback (never public, link-local,
    multicast, reserved or unspecified).
 3. It must be in the configured allowlist (exact match).

We NEVER do a DNS lookup. "localhost" is mapped to 127.0.0.1 in code, so DNS
tricks and rebinding cannot redirect the scan. The scanner connects to the
validated IP only, and never follows redirects (it does no HTTP at all).
Error messages never echo the submitted text.
"""
import ipaddress
import re
from dataclasses import dataclass

IPV4_PATTERN = re.compile(r"[0-9]{1,3}(?:\.[0-9]{1,3}){3}", re.ASCII)


class ConfigError(Exception):
    """Raised at startup when the server configuration is unsafe."""


class TargetValidationError(Exception):
    def __init__(self, code: str, message: str, status_code: int):
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code


@dataclass(frozen=True)
class ValidatedTarget:
    label: str  # what the user chose, canonical form ("localhost" or an IP)
    ip: str     # the IPv4 address we will actually connect to


def parse_ipv4_literal(text: str) -> ipaddress.IPv4Address | None:
    """Return an IPv4Address only for plain dotted-decimal text, else None."""
    if not isinstance(text, str) or not IPV4_PATTERN.fullmatch(text):
        return None
    octets = text.split(".")
    for octet in octets:
        if len(octet) > 1 and octet.startswith("0"):  # no leading zeros (octal tricks)
            return None
        if int(octet) > 255:
            return None
    try:
        return ipaddress.IPv4Address(text)
    except ValueError:
        return None


def is_safe_lab_address(ip: ipaddress.IPv4Address) -> bool:
    """Private or loopback only; never special-purpose ranges."""
    if ip.is_unspecified or ip.is_link_local or ip.is_multicast or ip.is_reserved:
        return False
    return ip.is_private or ip.is_loopback


def validate_target(raw: object, allowed: list[str]) -> ValidatedTarget:
    if not isinstance(raw, str) or not raw or len(raw) > 64:
        raise TargetValidationError(
            "invalid_target", "Target must be 'localhost' or an IPv4 address like 127.0.0.1.", 422
        )

    text = raw.lower() if raw.lower() == "localhost" else raw

    if text == "localhost":
        label, ip = "localhost", ipaddress.IPv4Address("127.0.0.1")
    else:
        parsed = parse_ipv4_literal(text)
        if parsed is None:
            raise TargetValidationError(
                "invalid_target",
                "Target must be 'localhost' or an IPv4 address like 127.0.0.1 "
                "(no URLs, ports, paths, spaces or alternative number formats).",
                422,
            )
        label, ip = str(parsed), parsed

    if not is_safe_lab_address(ip):
        raise TargetValidationError(
            "target_not_private",
            "Only private lab addresses and localhost can be scanned. Public addresses are rejected.",
            403,
        )

    if label not in {a.lower() for a in allowed}:
        raise TargetValidationError(
            "target_not_allowed", "This target is not in the configured allowlist.", 403
        )

    return ValidatedTarget(label=label, ip=str(ip))
