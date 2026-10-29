# NetVulnScan: Mini Vulnerability Assessment Tool

An educational web application that runs a basic TCP port check on **localhost and explicitly configured private lab targets** and turns the observations into evidence-based security findings. Built as a cybersecurity internship project.

> **Only scan systems you own or have written permission to test.** The backend blocks public addresses and arbitrary hostnames by design.

## Problem statement
Beginners often confuse "open port" with "vulnerability". Real assessments need safe scoping, careful evidence, honest limitations and clear reporting. This project demonstrates that workflow on a small scale.

## Objectives
- Understand TCP ports, the 3-way handshake and port states
- Build a safe, restricted scanner with strict target validation
- Produce findings with evidence, severity, remediation and confidence
- Practise REST API design, input validation, testing and reporting

## Port scanner vs vulnerability scanner
| | Port scanner (this project's core) | Vulnerability scanner |
|---|---|---|
| Question answered | "Which ports accept connections?" | "Which known weaknesses exist?" |
| Method | Tries TCP connections | Identifies software/versions and compares against vulnerability databases, runs safe checks |
| Output | open / closed / unknown | Findings tied to CVEs, misconfigurations, patches |

NetVulnScan sits in between: it is a port scanner plus a small set of transparent rules about exposure. It does **not** detect CVEs or outdated software.

## Features
- Allowlisted targets (default `127.0.0.1`), no DNS lookups
- TCP connect scan with timeouts, 10 worker threads at most, scan deadline
- Open/closed/unknown states with a reason for each
- Service-name *hints* from port numbers (not positive identification)
- Optional passive banner read (sends nothing, 128 characters max)
- Findings with title, severity, port, evidence, explanation, remediation, confidence, limitations
- Dashboard: summary, charts, open-port table, findings grouped by severity, in-memory history
- JSON and CSV export

## Architecture
```
React + Vite + Recharts (http://localhost:5173) --HTTP/JSON--> FastAPI (http://127.0.0.1:8000)
                                                                 ├─ target_validation.py  (allowlist, strict format)
                                                                 ├─ scanner.py            (socket connect checks)
                                                                 ├─ security_checks.py    (rules -> findings)
                                                                 ├─ store.py              (in-memory history, limits)
                                                                 └─ report.py             (JSON / CSV)
```
No database, no external services, no files written.

## Technologies
Python 3, FastAPI, Uvicorn, Pydantic, Pytest, React, Vite, JavaScript, CSS, Recharts.

## Folder structure
```
netvulnscan/
├── backend/
│   ├── app/ (main, config, scanner, target_validation, security_checks, services, schemas, store, report)
│   ├── tests/ (test_target_validation, test_scanner, test_security_checks, test_api, conftest)
│   ├── pytest.ini, requirements.txt, .gitignore
├── frontend/
│   ├── src/ (App.jsx, api.js, ports.js, main.jsx, index.css, components/)
│   ├── index.html, package.json, vite.config.js, .gitignore
├── docs/screenshots/
├── README.md, VIVA_PREPARATION.md, .gitignore
```

## Installation (Windows 11, PowerShell, VS Code)
```powershell
python --version
node --version
```
**Terminal 1: backend**
```powershell
cd backend
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```
If activation is blocked: `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`.

**Terminal 2: frontend**
```powershell
cd frontend
npm install
```

## Running
Terminal 1:
```powershell
cd backend
.\venv\Scripts\Activate.ps1
uvicorn app.main:app --host 127.0.0.1 --port 8000
```
Terminal 2:
```powershell
cd frontend
npm run dev
```
Open **http://localhost:5173**. Tick the permission box and click **Start scan**. Your own backend (8000) and frontend (5173) will show as open, which is a good first demo. Interactive API docs: http://127.0.0.1:8000/docs

### Adding a private lab target (optional)
Only for a machine you own, for example a VM at `192.168.56.101`. Stop the backend, then:
```powershell
$env:NETVULNSCAN_LAB_TARGETS = "192.168.56.101"
uvicorn app.main:app --host 127.0.0.1 --port 8000
```
Only private IPv4 addresses are accepted; anything else makes the server refuse to start. Targets cannot be added through the API.

## How TCP connection testing works
TCP opens a connection with a 3-way handshake (SYN, SYN/ACK, ACK). The scanner asks the OS for a normal connection:
- Handshake completes → **open**
- Host replies with a reset (RST) → **closed** (Python raises `ConnectionRefusedError`)
- No reply before the timeout, or another network error → **unknown** (a firewall may drop packets, or the host is down)

## API documentation
| Method | Path | Purpose |
|---|---|---|
| GET | `/api/health` | `{"status":"ok"}` |
| GET | `/api/scan/config` | Allowed targets, default ports, limits |
| POST | `/api/scan` | Run a scan (synchronous) |
| GET | `/api/scans` | Scans kept in memory (newest first) |
| GET | `/api/scan/{scan_id}` | One stored scan |
| GET | `/api/scan/{scan_id}/report?format=json\|csv` | Download report |

`POST /api/scan` body (all optional):
```json
{
  "target": "127.0.0.1",
  "ports": [22, 80, 8000],
  "timeout_seconds": 3.0,
  "grab_banner": false,
  "expected_ports": [80]
}
```
Limits: ports 1-10000, at most 50 per scan, timeout 0.2-5 s, one scan at a time, 10 scans per minute. Unknown fields are rejected.

Errors: `403` target not private or not allowlisted, `422` invalid input, `404` unknown scan, `429` busy or rate limited, `500` generic. Error messages never echo the submitted target.

## Sample report format (JSON, abbreviated and illustrative)
```json
{
  "scan_id": "9fd3edb6...",
  "target": "localhost", "target_ip": "127.0.0.1",
  "summary": {"ports_scanned": 25, "open": 3, "closed": 22, "unknown": 0,
              "findings_by_severity": {"High": 0, "Medium": 0, "Low": 1, "Info": 1}},
  "ports": [{"port": 8080, "state": "open", "service_hint": "HTTP alternate",
             "reason": "TCP handshake completed...", "banner": null}],
  "findings": [{"id": "NVS-UNEXPECTED-8080", "title": "Unexpected open port", "severity": "Low",
                "port": 8080, "evidence": "Port 8080 is open but is not in the expected-ports list.",
                "explanation": "...", "remediation": "...", "confidence": "High", "limitations": "..."}],
  "limitations": ["..."]
}
```
The CSV has one row per port and per finding (`record_type` = `port` or `finding`).

## Severity meaning
High: protocol insecure by design and reachable. Medium: sensitive or administrative service reachable. Low: minor exposure or disclosure. Info: notes about the scan. There is no "Critical" because this tool cannot confirm exploitability.

## Testing
```powershell
cd backend
.\venv\Scripts\Activate.ps1
pytest -v
```
Tests mock network connections wherever practical and need no internet. One test opens a real listening socket on `127.0.0.1` to confirm open/closed detection. They cover valid localhost, invalid or tricky targets (URLs, ports, decimal/hex/octal IPs, unicode digits), public-address rejection, allowlist enforcement, invalid ports and timeouts, closed ports, timeouts, API validation, error handling, rate limiting, CORS and reports (including CSV formula-injection protection).

## Security safeguards
- Target format is strict; `localhost` is mapped to 127.0.0.1 in code and **no DNS lookup is ever made**, so DNS tricks and rebinding cannot redirect a scan
- Must be private/loopback **and** in the allowlist; public, link-local, multicast and reserved addresses are always refused
- The scanner connects only to the validated IP, makes no HTTP requests and follows no redirects
- No shell commands, no file access from user input, no exploitation, credential testing, stealth or evasion
- Limited concurrency, port cap, timeout cap, scan deadline, rate limit
- Banner reading is optional and passive (nothing is sent), truncated and sanitized
- CSV cells starting with `= + - @` are neutralized
- Generic error messages, no stack traces; CORS limited to the local frontend; history in memory only

## Limitations
- Basic TCP connect scan only: no UDP, no service fingerprinting, no CVE or version checks
- Open ports are exposures to review, not confirmed vulnerabilities; false negatives are possible (firewalls, rate limits, services that start later)
- Service names are guesses from port numbers
- "Unknown" cannot distinguish a firewall from a down host
- Localhost scans only show what this machine exposes to itself; the host firewall may behave differently for other machines
- Intended for local use. It has no login, so do not expose the API to a network.

## Future improvements
Async scanning, authenticated lab access, more safe service checks, saved reports with consent, comparison between scans, and a Docker lab target for demos.

## Screenshots
Run the app, take your own screenshots (`Win + Shift + S`), save them in `docs/screenshots/`, then add:
```markdown
![Dashboard](docs/screenshots/dashboard.png)
![Findings](docs/screenshots/findings.png)
```

## GitHub
```powershell
git init
git add .
git status
git commit -m "Initial commit: NetVulnScan mini vulnerability assessment tool with FastAPI backend, React dashboard and tests"
git branch -M main
git remote add origin https://github.com/<your-username>/netvulnscan.git
git push -u origin main
```
Suggested description: *"Educational TCP port scanner and security findings dashboard restricted to localhost and private lab targets (FastAPI + React)."* Create the GitHub repo empty (no README), and check `git status` shows no `venv/` or `node_modules/`.

## Troubleshooting
| Problem | Fix |
|---|---|
| Many ports show "unknown" | Raise the timeout (Windows may take about 2 s to refuse a local port) |
| "Cannot reach the local backend" | Start Terminal 1 |
| 403 "not in the configured allowlist" | Only configured lab IPs are allowed (see above) |
| 429 "Another scan is already running" | Wait for the scan to finish |
| Port 8000 or 5173 in use | Close the other program; the frontend must use 5173 |
| `Activate.ps1` blocked | `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` |
