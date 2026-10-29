"""FastAPI app for NetVulnScan.

Safety: targets are validated and allowlisted, ports/timeouts are capped, scans
are rate limited, nothing is written to disk, and errors never expose stack traces.
"""
import logging
import uuid
from datetime import datetime, timezone

from fastapi import FastAPI, Path, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse, Response

from . import config, report, scanner, security_checks
from .schemas import (
    ErrorResponse, ScanRequest, ScanResult, ScanSettings, ScanSummary,
)
from .services import COMMON_SERVICES
from .store import limiter, store
from .target_validation import ConfigError, TargetValidationError, validate_target

logger = logging.getLogger("netvulnscan")

LIMITATIONS = [
    "This is a basic TCP connect scan, not a full vulnerability scanner.",
    "An open port is not a confirmed vulnerability; findings are exposures to review.",
    "Service names come from standard port numbers and are not positive identification.",
    "No software version or CVE lookup is performed, so outdated software is not detected.",
    "Unknown results can mean a firewall, a down host, or a timeout that is too short.",
    "Only the ports you selected were tested. Closed ports on one scan can change later.",
]

# Fail closed at startup if the lab-target setting is unsafe.
try:
    config.get_allowed_targets()
except ConfigError as exc:  # pragma: no cover
    raise SystemExit(str(exc))

app = FastAPI(
    title="NetVulnScan API",
    version="1.0.0",
    description="Educational scanner restricted to localhost and configured private lab targets.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type"],
)


@app.exception_handler(TargetValidationError)
async def target_error_handler(request: Request, exc: TargetValidationError):
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.message, "code": exc.code})


@app.exception_handler(RequestValidationError)
async def validation_handler(request: Request, exc: RequestValidationError):
    # Collect field names and short messages only (never echo submitted values).
    problems = []
    for err in exc.errors()[:5]:
        field = ".".join(str(p) for p in err.get("loc", []) if p != "body")
        problems.append(f"{field or 'request'}: {err.get('msg', 'invalid value')}")
    return JSONResponse(
        status_code=422,
        content={"detail": "Invalid request. " + "; ".join(problems), "code": "invalid_request"},
    )


@app.exception_handler(Exception)
async def unexpected_handler(request: Request, exc: Exception):
    logger.error("Unexpected error: %s", type(exc).__name__)
    return JSONResponse(status_code=500, content={"detail": "Internal server error.", "code": "internal_error"})


@app.get("/api/health")
def health():
    return {"status": "ok"}


@app.get("/api/scan/config")
def scan_config():
    return {
        "default_target": config.DEFAULT_TARGET,
        "allowed_targets": config.get_allowed_targets(),
        "default_ports": config.COMMON_PORTS,
        "service_hints": {str(p): n for p, n in COMMON_SERVICES.items()},
        "limits": {
            "min_port": config.MIN_PORT,
            "max_port": config.MAX_PORT,
            "max_ports_per_scan": config.MAX_PORTS_PER_SCAN,
            "min_timeout_seconds": config.MIN_TIMEOUT,
            "max_timeout_seconds": config.MAX_TIMEOUT,
            "default_timeout_seconds": config.DEFAULT_TIMEOUT,
            "max_concurrent_connections": config.MAX_WORKERS,
            "scan_deadline_seconds": config.SCAN_DEADLINE_SECONDS,
            "max_scans_per_minute": config.MAX_SCANS_PER_MINUTE,
        },
    }


@app.get("/api/scans", response_model=list[ScanResult])
def list_scans():
    return store.list()


@app.post(
    "/api/scan",
    response_model=ScanResult,
    responses={403: {"model": ErrorResponse}, 422: {"model": ErrorResponse}, 429: {"model": ErrorResponse}},
)
def start_scan(payload: ScanRequest):
    # 1. Validate the target BEFORE anything touches the network.
    target = validate_target(payload.target, config.get_allowed_targets())
    ports = payload.ports if payload.ports else list(config.COMMON_PORTS)

    # 2. Request limits.
    reason = limiter.try_start()
    if reason:
        return JSONResponse(status_code=429, content={"detail": reason, "code": "rate_limited"})

    started = datetime.now(timezone.utc)
    try:
        results = scanner.scan_ports(target, ports, payload.timeout_seconds, payload.grab_banner)
    finally:
        limiter.finish()
    finished = datetime.now(timezone.utc)

    findings = security_checks.evaluate(results, payload.expected_ports)
    scan = ScanResult(
        scan_id=uuid.uuid4().hex,
        target=target.label,
        target_ip=target.ip,
        started_at=started.isoformat(),
        finished_at=finished.isoformat(),
        duration_seconds=round((finished - started).total_seconds(), 2),
        settings=ScanSettings(
            ports=ports,
            timeout_seconds=payload.timeout_seconds,
            grab_banner=payload.grab_banner,
            expected_ports=payload.expected_ports,
        ),
        summary=ScanSummary(
            ports_scanned=len(results),
            open=sum(r.state == "open" for r in results),
            closed=sum(r.state == "closed" for r in results),
            unknown=sum(r.state == "unknown" for r in results),
            findings_by_severity=security_checks.severity_counts(findings),
        ),
        ports=results,
        findings=findings,
        limitations=LIMITATIONS,
    )
    store.add(scan)
    return scan


SCAN_ID = Path(..., pattern=r"^[0-9a-f]{32}$")


@app.get("/api/scan/{scan_id}", response_model=ScanResult, responses={404: {"model": ErrorResponse}})
def get_scan(scan_id: str = SCAN_ID):
    scan = store.get(scan_id)
    if scan is None:
        return JSONResponse(status_code=404, content={"detail": "Scan not found.", "code": "not_found"})
    return scan


@app.get("/api/scan/{scan_id}/report", responses={404: {"model": ErrorResponse}})
def get_report(scan_id: str = SCAN_ID, format: str = Query("json", pattern="^(json|csv)$")):
    scan = store.get(scan_id)
    if scan is None:
        return JSONResponse(status_code=404, content={"detail": "Scan not found.", "code": "not_found"})
    filename = f"netvulnscan-{scan_id[:8]}.{format}"
    headers = {"Content-Disposition": f'attachment; filename="{filename}"'}
    if format == "csv":
        return PlainTextResponse(report.build_csv(scan), media_type="text/csv", headers=headers)
    return Response(report.build_json(scan), media_type="application/json", headers=headers)
