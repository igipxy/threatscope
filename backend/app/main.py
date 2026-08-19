import hashlib
import ipaddress
import re
from datetime import datetime, timezone
from typing import Literal
from urllib.parse import urlparse

import httpx
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    virustotal_api_key: str = ""
    frontend_origin: str = "http://localhost:5173"
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


settings = Settings()
app = FastAPI(title="ThreatScope API", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[settings.frontend_origin],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


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


def classify_target(value: str) -> tuple[str, str]:
    value = value.strip()
    try:
        ipaddress.ip_address(value)
        return "ip", value
    except ValueError:
        pass

    parsed = urlparse(value if "://" in value else f"https://{value}")
    host = parsed.hostname
    if not host or "." not in host:
        raise HTTPException(status_code=422, detail="Enter a valid URL, domain, or IP address.")
    if "://" in value:
        return "url", value
    return "domain", host


def demo_scan(target: str, target_type: str) -> tuple[int, list[Finding]]:
    findings: list[Finding] = []
    score = 5

    if target_type == "url" and not target.lower().startswith("https://"):
        score += 20
        findings.append(Finding(label="Unencrypted URL", severity="medium", detail="The URL does not use HTTPS."))

    host = urlparse(target if "://" in target else f"https://{target}").hostname or target
    suspicious_words = {"login", "verify", "secure", "account", "wallet", "update"}
    matched = sorted(word for word in suspicious_words if word in host.lower())
    if matched:
        score += min(30, len(matched) * 10)
        findings.append(Finding(label="Suspicious wording", severity="medium", detail=f"Hostname contains: {', '.join(matched)}."))

    if re.search(r"xn--", host, re.IGNORECASE):
        score += 30
        findings.append(Finding(label="Punycode hostname", severity="high", detail="Internationalized hostname requires extra scrutiny."))

    if not findings:
        findings.append(Finding(label="Basic checks passed", severity="info", detail="No obvious risk signals were found by local checks."))

    return min(score, 100), findings


async def virustotal_scan(target: str, target_type: str) -> tuple[int, list[Finding]]:
    endpoint_type = "urls" if target_type == "url" else ("domains" if target_type == "domain" else "ip_addresses")
    identifier = httpx.URL(target).raw_path.decode().strip("/") if target_type == "url" else target
    if target_type == "url":
        import base64
        identifier = base64.urlsafe_b64encode(target.encode()).decode().strip("=")

    async with httpx.AsyncClient(timeout=15) as client:
        response = await client.get(
            f"https://www.virustotal.com/api/v3/{endpoint_type}/{identifier}",
            headers={"x-apikey": settings.virustotal_api_key},
        )
    if response.status_code == 404:
        return demo_scan(target, target_type)
    if response.status_code >= 400:
        raise HTTPException(status_code=502, detail="Threat intelligence provider is unavailable.")

    stats = response.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    malicious = int(stats.get("malicious", 0))
    suspicious = int(stats.get("suspicious", 0))
    total = sum(int(value) for value in stats.values()) or 1
    score = min(100, round(((malicious + suspicious * 0.5) / total) * 100))
    findings = [
        Finding(
            label="Community engine analysis",
            severity="high" if malicious else ("medium" if suspicious else "info"),
            detail=f"{malicious} malicious and {suspicious} suspicious detections across {total} engines.",
        )
    ]
    return score, findings


@app.get("/health")
def health():
    return {"status": "ok", "provider": "virustotal" if settings.virustotal_api_key else "demo"}


@app.post("/api/scans", response_model=ScanResult)
async def create_scan(payload: ScanRequest):
    target_type, normalized = classify_target(payload.target)
    if settings.virustotal_api_key:
        score, findings = await virustotal_scan(normalized, target_type)
        provider = "VirusTotal"
    else:
        score, findings = demo_scan(normalized, target_type)
        provider = "ThreatScope demo analysis"

    verdict = "malicious" if score >= 70 else ("suspicious" if score >= 30 else "clean")
    scanned_at = datetime.now(timezone.utc)
    scan_id = hashlib.sha256(f"{normalized}:{scanned_at.isoformat()}".encode()).hexdigest()[:12]
    return ScanResult(
        id=scan_id,
        target=normalized,
        target_type=target_type,
        score=score,
        verdict=verdict,
        provider=provider,
        scanned_at=scanned_at,
        findings=findings,
    )
