"""Central settings and safety limits.

Extra lab targets must be added by the owner of the machine through the
NETVULNSCAN_LAB_TARGETS environment variable (comma-separated private IPv4
addresses). They cannot be added through the API.
"""
import os

from .target_validation import ConfigError, parse_ipv4_literal, is_safe_lab_address

DEFAULT_TARGET = "127.0.0.1"
BASE_ALLOWED_TARGETS = ("127.0.0.1", "localhost")
LAB_ENV_VAR = "NETVULNSCAN_LAB_TARGETS"

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995,
    1433, 3306, 3389, 5173, 5432, 5900, 6379, 8000, 8080, 8443, 27017,
]

MIN_PORT = 1
MAX_PORT = 10000
MAX_PORTS_PER_SCAN = 50

# Windows can take about 2 seconds to report a refused local connection,
# so the default timeout is generous.
DEFAULT_TIMEOUT = 3.0
MIN_TIMEOUT = 0.2
MAX_TIMEOUT = 5.0

MAX_WORKERS = 10               # limited concurrency
SCAN_DEADLINE_SECONDS = 60     # whole scan must finish within this
MAX_SCANS_PER_MINUTE = 10
MAX_HISTORY = 50               # scans kept in memory
BANNER_TIMEOUT = 1.0
MAX_BANNER_BYTES = 128
MAX_BANNER_CHARS = 100


def load_lab_targets(raw: str | None) -> list[str]:
    """Parse and strictly validate extra lab targets. Fails closed on bad input."""
    if not raw:
        return []
    targets: list[str] = []
    for item in raw.split(","):
        item = item.strip()
        if not item:
            continue
        ip = parse_ipv4_literal(item)
        if ip is None or not is_safe_lab_address(ip):
            raise ConfigError(
                f"{LAB_ENV_VAR} may only contain private IPv4 addresses such as 192.168.56.101."
            )
        if str(ip) not in targets:
            targets.append(str(ip))
    return targets


def get_allowed_targets() -> list[str]:
    return list(BASE_ALLOWED_TARGETS) + [
        t for t in load_lab_targets(os.environ.get(LAB_ENV_VAR)) if t not in BASE_ALLOWED_TARGETS
    ]
