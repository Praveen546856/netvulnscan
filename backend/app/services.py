"""Standard port -> service-name hints.

IMPORTANT: this is only the name a port is *conventionally* used for
(like IANA/common usage). An open port 80 does not prove a web server runs
there. NetVulnScan never treats this table as positive identification.
"""

COMMON_SERVICES: dict[int, str] = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    135: "MS RPC",
    139: "NetBIOS Session",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    993: "IMAPS",
    995: "POP3S",
    1433: "Microsoft SQL Server",
    3306: "MySQL/MariaDB",
    3389: "RDP",
    5173: "Vite dev server (common)",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8000: "HTTP alternate (common dev port)",
    8080: "HTTP alternate",
    8443: "HTTPS alternate",
    27017: "MongoDB",
}


def service_hint(port: int) -> str | None:
    """Return the conventional service name for a port, or None."""
    return COMMON_SERVICES.get(port)
