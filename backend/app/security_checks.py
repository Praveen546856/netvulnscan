"""Evidence-based findings built ONLY from scan results.

Honesty rules used here:
 * An open port is an "exposure to review", never a confirmed vulnerability.
 * We never say software is outdated: we have no reliable version data.
 * Every finding states its evidence, confidence and limitations.
 * Severity is a simple, documented rating of the *potential* concern:
     High   = protocol known to be insecure by design and reachable
     Medium = sensitive/administrative service reachable that is normally restricted
     Low    = minor exposure or information disclosure
     Info   = informational / scan quality notes
"""
import re

from .schemas import Finding, PortResult

SEVERITY_ORDER = {"High": 0, "Medium": 1, "Low": 2, "Info": 3}

NOT_VERIFIED = "Only the TCP port state was observed; the service behind the port was not verified."

# port -> (title, severity, explanation, remediation)
PORT_RULES: dict[int, tuple[str, str, str, str]] = {
    23: ("Telnet port reachable", "High",
         "Telnet sends everything, including logins, in clear text, so anyone on the network path can read it.",
         "Disable Telnet and use SSH instead. If it must stay, restrict it with a firewall."),
    21: ("FTP port reachable", "Medium",
         "Classic FTP sends credentials and data unencrypted.",
         "Replace with SFTP or FTPS, or restrict access with a firewall."),
    445: ("SMB file-sharing port reachable", "Medium",
          "SMB is a file-sharing/administration service that should normally be limited to trusted hosts.",
          "Block it at the firewall unless needed, keep the OS patched, and disable SMBv1."),
    135: ("Windows RPC port reachable", "Low",
          "MS RPC is used for Windows management and is normally not needed from other hosts.",
          "Restrict it with the host firewall to trusted networks."),
    139: ("NetBIOS session port reachable", "Low",
          "NetBIOS is a legacy Windows networking service.",
          "Disable NetBIOS over TCP/IP if not needed and firewall the port."),
    3389: ("Remote Desktop (RDP) port reachable", "Medium",
           "Remote administration ports are common targets for password guessing.",
           "Restrict RDP to a VPN or trusted IPs, require strong passwords/MFA and Network Level Authentication."),
    5900: ("VNC port reachable", "Medium",
           "VNC provides remote screen control and is often weakly protected.",
           "Restrict to trusted hosts or tunnel it over SSH/VPN, and use strong authentication."),
    22: ("SSH port reachable", "Low",
         "SSH is a remote administration service. It is secure when configured well but should be limited to those who need it.",
         "Use key-based login, disable root/password login where possible, and restrict by firewall."),
    1433: ("SQL Server port reachable", "Medium",
           "Database ports should normally only be reachable from the application that uses them.",
           "Bind the database to localhost or an internal network and firewall the port."),
    3306: ("MySQL/MariaDB port reachable", "Medium",
           "Database ports should normally only be reachable from the application that uses them.",
           "Bind to 127.0.0.1 or an internal network and firewall the port."),
    5432: ("PostgreSQL port reachable", "Medium",
           "Database ports should normally only be reachable from the application that uses them.",
           "Restrict listen_addresses and pg_hba.conf to trusted hosts."),
    6379: ("Redis port reachable", "Medium",
           "Redis is often run without authentication, so network exposure can be risky.",
           "Bind to localhost, enable authentication and firewall the port."),
    27017: ("MongoDB port reachable", "Medium",
            "Database ports should normally only be reachable from the application that uses them.",
            "Bind to localhost or internal network, enable authentication and firewall the port."),
}


def _finding(rule_id, title, severity, port, evidence, explanation, remediation, confidence, limitations):
    return Finding(
        id=rule_id, title=title, severity=severity, port=port, evidence=evidence,
        explanation=explanation, remediation=remediation,
        confidence=confidence, limitations=limitations,
    )


def evaluate(results: list[PortResult], expected_ports: list[int] | None = None) -> list[Finding]:
    findings: list[Finding] = []
    by_port = {r.port: r for r in results}
    open_ports = [r for r in results if r.state == "open"]
    unknown = [r for r in results if r.state == "unknown"]

    # 1. Sensitive / administrative ports that are open.
    for r in open_ports:
        rule = PORT_RULES.get(r.port)
        if rule:
            title, severity, explanation, remediation = rule
            findings.append(_finding(
                f"NVS-PORT-{r.port}", title, severity, r.port,
                f"TCP connection to port {r.port} succeeded.",
                explanation, remediation, "Medium", NOT_VERIFIED,
            ))

    # 2. Unexpected open services (only when the user supplied an expected list).
    if expected_ports is not None:
        for r in open_ports:
            if r.port not in expected_ports:
                findings.append(_finding(
                    f"NVS-UNEXPECTED-{r.port}", "Unexpected open port", "Low", r.port,
                    f"Port {r.port} is open but is not in the expected-ports list.",
                    "Services you did not plan to run increase the attack surface.",
                    "Identify what is listening (for example with netstat on your own machine). "
                    "Stop or firewall it if it is not needed.",
                    "High", "Depends on the accuracy of the expected-ports list you provided.",
                ))

    # 3. Plain HTTP seen without HTTPS among the scanned ports.
    http = by_port.get(80)
    https = by_port.get(443)
    if http and http.state == "open" and https and https.state == "closed":
        findings.append(_finding(
            "NVS-HTTP-NO-HTTPS", "HTTP port open while HTTPS port is closed", "Low", 80,
            "Port 80 accepted a connection and port 443 refused it.",
            "A web service may be offered without encryption.",
            "Serve the site over HTTPS and redirect HTTP to HTTPS.",
            "Low", "HTTPS may run on another port, and port 80 may be a redirect only.",
        ))

    # 4. Banner-based findings (only when banners were collected).
    for r in open_ports:
        if not r.banner:
            continue
        findings.append(_finding(
            f"NVS-BANNER-{r.port}", "Service banner is visible", "Info", r.port,
            f"Service sent: \"{r.banner}\"",
            "Banners can reveal software names or versions to anyone who connects.",
            "If the banner exposes version details, reduce or hide them in the service configuration. "
            "Version strings alone do not prove a vulnerability.",
            "Medium", "A banner can be edited or misleading. No version-to-vulnerability lookup is done.",
        ))
        if re.match(r"SSH-1\.(?!99)", r.banner):
            findings.append(_finding(
                f"NVS-SSH1-{r.port}", "SSH protocol version 1 advertised", "High", r.port,
                f"Banner begins with \"{r.banner[:20]}\".",
                "SSH protocol 1 has known cryptographic weaknesses.",
                "Configure the SSH server to accept only protocol 2.",
                "Medium", "Based only on the banner text the service chose to send.",
            ))

    # 5. Scan quality / informational findings.
    if results and len(unknown) * 2 >= len(results):
        findings.append(_finding(
            "NVS-INCONCLUSIVE", "Many ports gave no clear answer", "Info", None,
            f"{len(unknown)} of {len(results)} ports were 'unknown' (timeout or network error).",
            "Results may be incomplete: a firewall may drop packets, the host may be down, or the timeout is too short.",
            "Check the target is running, then retry with a longer timeout.",
            "High", "Closed and open results in the same scan are still valid.",
        ))
    if results and not open_ports and not unknown:
        findings.append(_finding(
            "NVS-NO-OPEN", "No open ports found among scanned ports", "Info", None,
            f"All {len(results)} scanned ports refused the connection.",
            "Nothing was listening on the ports that were tested.",
            "No action needed for these ports.",
            "Medium", "Only the selected ports were tested; other ports may be open.",
        ))

    findings.sort(key=lambda f: (SEVERITY_ORDER[f.severity], f.port or 0, f.id))
    return findings


def severity_counts(findings: list[Finding]) -> dict[str, int]:
    counts = {"High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for f in findings:
        counts[f.severity] += 1
    return counts
