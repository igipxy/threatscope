from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field


class ScanRequest(BaseModel):
    target: str = Field(min_length=3, max_length=2048)
    share_with_virustotal: bool = False


class Finding(BaseModel):
    label: str
    severity: Literal["info", "low", "medium", "high"]
    detail: str


class ScanResult(BaseModel):
    id: str
    target: str
    target_type: Literal["url", "domain", "ip"]
    score: int
    verdict: Literal["low_risk", "suspicious", "malicious"]
    provider: str
    analysis_status: Literal["completed"] = "completed"
    cached: bool = False
    scanned_at: datetime
    findings: list[Finding]
