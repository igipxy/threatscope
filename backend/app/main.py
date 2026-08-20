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

from .domain_intelligence import domain_intelligence
from .models import Finding, ScanRequest, ScanResult
from .storage import get_cached_scan, initialize_database, list_scans, reserve_provider_request, save_scan
from .url_analysis import analyze_url_structure, check_dns, normalize_url


class Settings(BaseSettings):
    virustotal_api_key: str = ""
    frontend_origin: str = "http://localhost:5173"
    database_path: str = "threatscope.db"
    cache_ttl_seconds: int = 86400
    vt_requests_per_minute: int = 3
    vt_requests_per_day: int = 400
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
    if not parsed.hostname or "." not in parsed.hostname:
        raise HTTPException(status_code=422, detail="Enter a valid URL, domain, or IP address.")
    return "domain", parsed.hostname.lower()


def verdict_for_score(score: int) -> str:
    return "malicious" if score >= 70 else ("suspicious" if score >= 30 else "low_risk")


def local_scan(target: str, target_type: str) -> tuple[int, list[Finding]]:
    findings: list[Finding] = []
    score = 5
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
    if target_type == "url":
        score, findings = analyze_url_structure(original, target)
        hostname = urlparse(target).hostname or ""
        findings.append(await check_dns(hostname))
    elif target_type == "domain":
        score, findings = local_scan(target, target_type)
        hostname = target
    else:
        return local_scan(target, target_type)

    domain_score, domain_findings = await domain_intelligence(hostname)
    return min(100, score + domain_score), [*findings, *domain_findings]

def provider_result(stats: dict) -> tuple[int, list[Finding]]:
    malicious = int(stats.get("malicious", 0))
    suspicious = int(stats.get("suspicious", 0))
    harmless = int(stats.get("harmless", 0))
    undetected = int(stats.get("undetected", 0))
    total = sum(int(value) for value in stats.values()) or 1
    score = 90 if malicious >= 5 else 60 if malicious else 50 if suspicious >= 3 else 35 if suspicious else 0
    severity = "high" if malicious else ("medium" if suspicious else "info")
    return score, [Finding(
        label="VirusTotal engine analysis",
        severity=severity,
        detail=f"{malicious} malicious, {suspicious} suspicious, {harmless} harmless, and {undetected} undetected results across {total} engines.",
    )]


async def virustotal_report(target: str, target_type: str) -> tuple[int, list[Finding]]:
    endpoint_type = "urls" if target_type == "url" else ("domains" if target_type == "domain" else "ip_addresses")
    identifier = base64.urlsafe_b64encode(target.encode()).decode().strip("=") if target_type == "url" else target
    async with httpx.AsyncClient(timeout=httpx.Timeout(12.0, connect=5.0)) as client:
        response = await client.get(
            f"https://www.virustotal.com/api/v3/{endpoint_type}/{identifier}",
            headers={"x-apikey": settings.virustotal_api_key},
        )
    if response.status_code == 200:
        stats = response.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        return provider_result(stats)
    if response.status_code == 404:
        return 0, [Finding(label="VirusTotal report unavailable", severity="info", detail="No existing VirusTotal report was found. ThreatScope did not submit this URL for scanning.")]
    if response.status_code == 429:
        return 0, [Finding(label="VirusTotal quota reached", severity="info", detail="The external provider is currently rate-limited. Local analysis is still complete.")]
    return 0, [Finding(label="VirusTotal unavailable", severity="info", detail="The external provider could not return a report. Local analysis is still complete.")]


@app.get("/")
def root():
    return {"name": "ThreatScope API", "docs": "/docs", "health": "/health"}


@app.get("/health")
def health():
    return {
        "status": "ok",
        "provider": "virustotal" if settings.virustotal_api_key else "local-only",
        "cache_ttl_seconds": settings.cache_ttl_seconds,
    }


@app.get("/api/scans", response_model=list[ScanResult])
def recent_scans(limit: int = Query(default=20, ge=1, le=100)):
    return list_scans(settings.database_path, limit)


@app.post("/api/scans", response_model=ScanResult, status_code=201)
async def create_scan(payload: ScanRequest):
    target_type, normalized = classify_target(payload.target)
    cached = get_cached_scan(settings.database_path, normalized, settings.cache_ttl_seconds)
    if cached:
        cache_finding = Finding(label="Cached result", severity="info", detail="This result was reused from a recent scan to conserve provider quota.")
        return cached.model_copy(update={"cached": True, "findings": [*cached.findings, cache_finding]})

    score, findings = await local_analysis(payload.target, normalized, target_type)
    provider = "ThreatScope local analysis"

    if settings.virustotal_api_key and payload.share_with_virustotal:
        permitted, reason = reserve_provider_request(
            settings.database_path, "virustotal", settings.vt_requests_per_minute, settings.vt_requests_per_day
        )
        if permitted:
            provider_score, provider_findings = await virustotal_report(normalized, target_type)
            score = max(score, provider_score)
            findings.extend(provider_findings)
            provider = "ThreatScope + VirusTotal report"
        else:
            findings.append(Finding(label="VirusTotal budget protected", severity="info", detail=f"Live lookup skipped: {reason}. Local analysis is still complete."))
    elif settings.virustotal_api_key:
        findings.append(Finding(label="VirusTotal lookup disabled", severity="info", detail="Enable the optional lookup only when you need an existing external report."))

    scanned_at = datetime.now(timezone.utc)
    result = ScanResult(
        id=hashlib.sha256(f"{normalized}:{scanned_at.isoformat()}".encode()).hexdigest()[:12],
        target=normalized,
        target_type=target_type,
        score=score,
        verdict=verdict_for_score(score),
        provider=provider,
        scanned_at=scanned_at,
        findings=findings,
    )
    save_scan(settings.database_path, result)
    return result
