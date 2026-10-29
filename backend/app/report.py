"""Build downloadable reports (JSON or CSV) from a stored scan only."""
import csv
import io

from .schemas import ScanResult

CSV_COLUMNS = [
    "record_type", "scan_id", "target", "port", "state", "service_hint",
    "severity", "title", "evidence", "explanation", "remediation",
    "confidence", "limitations",
]


def _safe_cell(value) -> str:
    """Prevent spreadsheet formula injection: banners come from the target."""
    text = "" if value is None else str(value)
    if text and text[0] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + text
    return text


def build_csv(scan: ScanResult) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(CSV_COLUMNS)
    for p in scan.ports:
        writer.writerow([_safe_cell(v) for v in [
            "port", scan.scan_id, scan.target, p.port, p.state, p.service_hint,
            "", "", f"{p.reason} Banner: {p.banner}" if p.banner else p.reason, "", "", "", "",
        ]])
    for f in scan.findings:
        writer.writerow([_safe_cell(v) for v in [
            "finding", scan.scan_id, scan.target, f.port, "", "",
            f.severity, f.title, f.evidence, f.explanation, f.remediation,
            f.confidence, f.limitations,
        ]])
    return buffer.getvalue()


def build_json(scan: ScanResult) -> str:
    return scan.model_dump_json(indent=2)
