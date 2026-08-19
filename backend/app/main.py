import base64
import hashlib
import ipaddress
import re
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from urllib.parse import urlparse

import httpx
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic_settings import BaseSettings, SettingsConfigDict

from .models import Finding, ScanRequest, ScanResult
from .storage import initialize_database, list_scans, save_scan


class Settings(BaseSettings):
    virustotal_api_key: str = ""
    frontend_origin: str = "http://localhost:5173"
    database_path: str = "threatscope.db"
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


settings = Settings()


@asynccontextmanager
async def lifespan(_: FastAPI):
    initialize_database(settings.database_path)
    yield


app = FastAPI(title="ThreatScope API", version="0.2.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[settings.frontend_origin, "http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


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
    if parsed.scheme not in {"http", "https"}:
        raise HTTPException(status_code=422, detail="Only HTTP and HTTPS URLs can be scanned.")
    return ("url", value) if "://" in value else ("domain", host)


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
    identifier = (
        base64.urlsafe_b64encode(target.encode()).decode().strip("=")
        if target_type == "url"
        else target
    )

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


@app.get("/")
def root():
    return {"name": "ThreatScope API", "docs": "/docs", "health": "/health"}


@app.get("/health")
def health():
    return {"status": "ok", "provider": "virustotal" if settings.virustotal_api_key else "demo"}


@app.get("/api/scans", response_model=list[ScanResult])
def recent_scans(limit: int = Query(default=20, ge=1, le=100)):
    return list_scans(settings.database_path, limit)


@app.post("/api/scans", response_model=ScanResult, status_code=201)
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
    result = ScanResult(
        id=scan_id,
        target=normalized,
        target_type=target_type,
        score=score,
        verdict=verdict,
        provider=provider,
        scanned_at=scanned_at,
        findings=findings,
    )
    save_scan(settings.database_path, result)
    return result
