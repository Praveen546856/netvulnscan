# NetVulnScan Viva Preparation

## 1. Project overview
NetVulnScan checks which TCP ports accept connections on localhost or an allowlisted private lab machine, then creates findings that explain what was observed, how serious it could be, and how to reduce risk. It is a safe learning tool, not an attack tool.

## 2. Architecture
React dashboard (5173) calls a FastAPI backend (8000). The backend validates the target, scans with Python sockets using a small thread pool, builds findings from the results, stores history in memory, and exports JSON/CSV.

## 3. TCP connection and port states
TCP uses a 3-way handshake: SYN, SYN/ACK, ACK. A connect scan asks the OS to complete it.
- **Open**: handshake completed, something is listening.
- **Closed**: the host answered with RST, nothing is listening.
- **Filtered/unknown**: no answer (firewall drop or host down) or a network error. We label it *unknown* because we cannot tell the cause.

## 4. Common ports
21 FTP, 22 SSH, 23 Telnet, 25 SMTP, 53 DNS, 80 HTTP, 110 POP3, 135 RPC, 139 NetBIOS, 143 IMAP, 443 HTTPS, 445 SMB, 3306 MySQL, 3389 RDP, 5432 PostgreSQL, 5900 VNC, 6379 Redis, 27017 MongoDB.

## 5. Network security concepts
Attack surface (every reachable service), least exposure (only open what's needed), firewalls and allowlists, encrypted vs clear-text protocols, defense in depth.

## 6. Vulnerability assessment vs penetration testing
Assessment finds and ranks possible weaknesses without exploiting them. Penetration testing goes further and tries to exploit them, with written authorization, to prove impact. This project is an assessment tool and never exploits anything.

## 7. False positives and false negatives
False positive: a finding that is not a real problem (for example port 80 open but it only redirects to HTTPS). False negative: a real problem the scan missed (a firewall hid a port, or the service started after the scan). We reduce false positives by saying "exposure to review" and showing confidence and limitations.

## 8. Remediation and severity
Remediation is the recommended fix (disable Telnet, firewall the database port, use SSH keys). Severity rates potential impact: High, Medium, Low, Info. Severity is not the same as confirmed risk.

## 9. Twenty technical questions
1. **What is a port scanner?** A tool that tests which ports on a host accept connections.
2. **Is a port scanner a vulnerability scanner?** No. A vulnerability scanner also identifies software and matches known weaknesses.
3. **How does your scan work?** `socket.create_connection` to ip:port with a timeout; success means open.
4. **What does `ConnectionRefusedError` mean?** The host sent RST, so the port is closed.
5. **Why "unknown" for timeouts?** A firewall may drop packets or the host may be down; we can't tell.
6. **Why is an open port not a vulnerability?** It only shows a service listens. Risk depends on the service, its version, configuration and access control.
7. **How do you stop public scanning?** Strict format check, private/loopback check, and an allowlist, all before any network call.
8. **Why no DNS lookups?** DNS can be manipulated (rebinding) to point a name at another IP. Only literal IPs and `localhost` mapped in code are accepted.
9. **What alternative IP tricks do you block?** Decimal (2130706433), hex (0x7f.1), octal (0177.0.0.1), short forms (127.1), unicode digits, IPv6, URLs, ports and spaces.
10. **Why are 127.0.0.1 and localhost both listed?** Both are loopback; `localhost` is mapped to 127.0.0.1 without DNS.
11. **How do you limit load?** At most 10 threads, 50 ports, 5 s timeout, 60 s deadline, one scan at a time, 10 scans per minute.
12. **Why a deadline?** So a scan can never run indefinitely; remaining ports become "unknown".
13. **What is banner grabbing?** Reading the greeting a service sends. Ours is optional, passive, truncated and sanitized.
14. **Why can't you say software is outdated?** We have no reliable version data or vulnerability database.
15. **How are findings built?** Rules over scan results; each has evidence, explanation, remediation, confidence and limitations.
16. **Why is Telnet High?** It sends credentials in clear text.
17. **What is CSV injection and how do you prevent it?** Cells starting with `=`, `+`, `-`, `@` can run as formulas in Excel. Banners come from the target, so we prefix such cells with `'`.
18. **Why Pydantic?** It validates ports, timeouts and unknown fields before our logic runs.
19. **How did you test without internet?** Mocked `socket.create_connection` and one real listener on 127.0.0.1.
20. **What would make it safer to deploy?** Authentication, HTTPS, audit logging, stricter rate limits and a security review. Right now it is local-only.

## 10. Demo script (4 minutes)
1. Show the two terminals and explain ports 8000 and 5173.
2. Open the dashboard; show the allowlist-only target dropdown and the permission checkbox.
3. Run a common-ports scan on localhost. Explain open ports 5173 and 8000.
4. Explain "unknown" vs "closed", and that service names are hints.
5. Open a finding: evidence, remediation, confidence and limitations.
6. Export CSV and JSON.
7. Prove the safety rules in PowerShell:
```powershell
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/api/scan -ContentType "application/json" -Body '{"target":"8.8.8.8"}'
```
It returns 403 and never scans.
8. Run `pytest -v` and show the results.
