from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field


class ScanRequest(BaseModel):
    target: str = Field(min_length=3, max_length=2048)


class Finding(BaseModel):
    label: str
    severity: Literal["info", "low", "medium", "high"]
    detail: str


class ScanResult(BaseModel):
    id: str
    target: str
    target_type: Literal["url", "domain", "ip"]
    score: int
    verdict: Literal["clean", "suspicious", "malicious"]
    provider: str
    scanned_at: datetime
    findings: list[Finding]
