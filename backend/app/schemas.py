"""Pydantic models: API request, scan results, findings."""
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from . import config

PortState = Literal["open", "closed", "unknown"]
Severity = Literal["High", "Medium", "Low", "Info"]
Confidence = Literal["High", "Medium", "Low"]


def _validate_port_list(value: list[int] | None) -> list[int] | None:
    if value is None:
        return None
    cleaned: list[int] = []
    for port in value:
        if port < config.MIN_PORT or port > config.MAX_PORT:
            raise ValueError(f"Ports must be between {config.MIN_PORT} and {config.MAX_PORT}.")
        if port not in cleaned:  # remove duplicates, keep order
            cleaned.append(port)
    if len(cleaned) > config.MAX_PORTS_PER_SCAN:
        raise ValueError(f"At most {config.MAX_PORTS_PER_SCAN} ports per scan.")
    return cleaned


class ScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=False)

    target: str = Field(default=config.DEFAULT_TARGET, min_length=1, max_length=64)
    ports: list[int] | None = Field(default=None, max_length=200)
    timeout_seconds: float = Field(
        default=config.DEFAULT_TIMEOUT, ge=config.MIN_TIMEOUT, le=config.MAX_TIMEOUT
    )
    grab_banner: bool = False
    expected_ports: list[int] | None = Field(default=None, max_length=200)

    @field_validator("ports", "expected_ports")
    @classmethod
    def check_ports(cls, value):
        return _validate_port_list(value)


class PortResult(BaseModel):
    port: int
    state: PortState
    service_hint: str | None = None
    reason: str
    banner: str | None = None


class Finding(BaseModel):
    id: str
    title: str
    severity: Severity
    port: int | None = None
    evidence: str
    explanation: str
    remediation: str
    confidence: Confidence
    limitations: str


class ScanSummary(BaseModel):
    ports_scanned: int
    open: int
    closed: int
    unknown: int
    findings_by_severity: dict[str, int]


class ScanSettings(BaseModel):
    ports: list[int]
    timeout_seconds: float
    grab_banner: bool
    expected_ports: list[int] | None = None


class ScanResult(BaseModel):
    scan_id: str
    target: str
    target_ip: str
    started_at: str
    finished_at: str
    duration_seconds: float
    settings: ScanSettings
    summary: ScanSummary
    ports: list[PortResult]
    findings: list[Finding]
    limitations: list[str]


class ErrorResponse(BaseModel):
    detail: str
    code: str | None = None
