import asyncio
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
from .url_analysis import analyze_url_structure, check_dns, normalize_url


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

    if "://" in value:
        return "url", normalize_url(value)

    parsed = urlparse(f"https://{value}")
    host = parsed.hostname
    if not host or "." not in host:
        raise HTTPException(status_code=422, detail="Enter a valid URL, domain, or IP address.")
    return "domain", host.lower()


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


async def local_analysis(original: str, target: str, target_type: str) -> tuple[int, list[Finding]]:
    if target_type != "url":
        return demo_scan(target, target_type)

    score, findings = analyze_url_structure(original, target)
    hostname = urlparse(target).hostname or ""
    findings.append(await check_dns(hostname))
    return score, findings


def provider_result(stats: dict) -> tuple[int, list[Finding]]:
    malicious = int(stats.get("malicious", 0))
    suspicious = int(stats.get("suspicious", 0))
    harmless = int(stats.get("harmless", 0))
    undetected = int(stats.get("undetected", 0))
    total = sum(int(value) for value in stats.values()) or 1
    if malicious >= 5:
        score = 90
    elif malicious >= 1:
        score = 60
    elif suspicious >= 3:
        score = 50
    elif suspicious >= 1:
        score = 35
    else:
        score = 0
    severity = "high" if malicious else ("medium" if suspicious else "info")
    return score, [
        Finding(
            label="VirusTotal engine analysis",
            severity=severity,
            detail=f"{malicious} malicious, {suspicious} suspicious, {harmless} harmless, and {undetected} undetected results across {total} engines.",
        )
    ]


async def virustotal_scan(target: str, target_type: str) -> tuple[int, list[Finding]]:
    endpoint_type = "urls" if target_type == "url" else ("domains" if target_type == "domain" else "ip_addresses")
    identifier = (
        base64.urlsafe_b64encode(target.encode()).decode().strip("=")
        if target_type == "url"
        else target
    )
    headers = {"x-apikey": settings.virustotal_api_key}

    async with httpx.AsyncClient(timeout=httpx.Timeout(12.0, connect=5.0)) as client:
        report = await client.get(
            f"https://www.virustotal.com/api/v3/{endpoint_type}/{identifier}",
            headers=headers,
        )
        if report.status_code == 200:
            stats = report.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return provider_result(stats)

        if report.status_code != 404 or target_type != "url":
            if report.status_code == 429:
                raise HTTPException(status_code=429, detail="VirusTotal rate limit reached. Try again later.")
            raise HTTPException(status_code=502, detail="Threat intelligence provider could not return a report.")

        submission = await client.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data={"url": target},
        )
        if submission.status_code == 429:
            raise HTTPException(status_code=429, detail="VirusTotal rate limit reached. Try again later.")
        if submission.status_code >= 400:
            raise HTTPException(status_code=502, detail="VirusTotal could not accept this URL for analysis.")

        analysis_id = submission.json().get("data", {}).get("id")
        if not analysis_id:
            raise HTTPException(status_code=502, detail="VirusTotal returned an invalid analysis response.")

        for _ in range(5):
            await asyncio.sleep(2)
            analysis = await client.get(
                f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                headers=headers,
            )
            if analysis.status_code == 429:
                raise HTTPException(status_code=429, detail="VirusTotal rate limit reached. Try again later.")
            if analysis.status_code >= 400:
                raise HTTPException(status_code=502, detail="VirusTotal analysis could not be retrieved.")
            attributes = analysis.json().get("data", {}).get("attributes", {})
            if attributes.get("status") == "completed":
                return provider_result(attributes.get("stats", {}))

    return 0, [
        Finding(
            label="VirusTotal analysis queued",
            severity="info",
            detail="The URL was submitted successfully, but the live engine analysis is still processing.",
        )
    ]


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
    local_score, findings = await local_analysis(payload.target, normalized, target_type)
    score = local_score
    provider = "ThreatScope structural and DNS analysis"

    if settings.virustotal_api_key:
        provider_score, provider_findings = await virustotal_scan(normalized, target_type)
        score = max(local_score, provider_score)
        findings.extend(provider_findings)
        provider = "ThreatScope + VirusTotal"

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
