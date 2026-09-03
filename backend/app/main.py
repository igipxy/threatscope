import asyncio
import base64
import hashlib
import hmac
import ipaddress
import re
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Literal
from urllib.parse import urlparse, urlunparse

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
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
    threatscope_access_token: str = ""
    scan_requests_per_minute: int = 20
    max_concurrent_scans: int = 4
    max_stored_scans: int = 500
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


settings = Settings()
MAX_PROVIDER_RESPONSE_BYTES = 1_000_000
_scan_slots = asyncio.BoundedSemaphore(max(1, settings.max_concurrent_scans))
_scan_rate_lock = asyncio.Lock()
_scan_requests: dict[str, deque[float]] = defaultdict(deque)


def _loopback_request(request: Request) -> bool:
    if request.headers.get("forwarded") or request.headers.get("x-forwarded-for"):
        return False
    try:
        return bool(request.client and ipaddress.ip_address(request.client.host).is_loopback)
    except ValueError:
        return False


async def require_access(
    request: Request,
    x_threatscope_key: str | None = Header(default=None),
) -> None:
    if settings.threatscope_access_token:
        if x_threatscope_key and hmac.compare_digest(x_threatscope_key, settings.threatscope_access_token):
            return
        raise HTTPException(status_code=401, detail="A valid X-ThreatScope-Key header is required.")
    if _loopback_request(request):
        return
    raise HTTPException(
        status_code=403,
        detail="Remote access is disabled until THREATSCOPE_ACCESS_TOKEN is configured.",
    )


async def enforce_scan_rate(request: Request) -> None:
    client = request.client.host if request.client else "unknown"
    now = time.monotonic()
    cutoff = now - 60
    async with _scan_rate_lock:
        bucket = _scan_requests[client]
        while bucket and bucket[0] <= cutoff:
            bucket.popleft()
        if len(bucket) >= max(1, settings.scan_requests_per_minute):
            raise HTTPException(status_code=429, detail="Scan request limit reached. Try again later.")
        bucket.append(now)


async def reserve_scan_capacity():
    try:
        await asyncio.wait_for(_scan_slots.acquire(), timeout=0.1)
    except TimeoutError as error:
        raise HTTPException(status_code=503, detail="The scanner is at capacity. Try again shortly.") from error
    try:
        yield
    finally:
        _scan_slots.release()


def redact_target(target: str, target_type: str) -> str:
    if target_type != "url":
        return target
    parsed = urlparse(target)
    return urlunparse(parsed._replace(query="", fragment=""))


@asynccontextmanager
async def lifespan(_: FastAPI):
    initialize_database(settings.database_path)
    yield


app = FastAPI(
    title="ThreatScope API",
    version="0.2.0",
    lifespan=lifespan,
    dependencies=[Depends(require_access)],
)
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
        address = ipaddress.ip_address(value)
        if not address.is_global:
            raise HTTPException(
                status_code=422,
                detail="Local, private, and reserved IP addresses cannot be scanned.",
            )
        return "ip", address.compressed
    except ValueError:
        pass
    if "://" in value:
        return "url", normalize_url(value)
    try:
        parsed = urlparse(f"https://{value}")
        hostname = parsed.hostname
    except ValueError as error:
        raise HTTPException(status_code=422, detail="Enter a valid URL, domain, or IP address.") from error
    if not hostname or "." not in hostname:
        raise HTTPException(status_code=422, detail="Enter a valid URL, domain, or IP address.")
    return "domain", hostname.lower()


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


@dataclass(frozen=True)
class ProviderOutcome:
    status: Literal["success", "not_found", "rate_limited", "unavailable"]
    score: int
    findings: list[Finding]


def provider_result(stats: dict) -> ProviderOutcome:
    malicious = int(stats.get("malicious", 0))
    suspicious = int(stats.get("suspicious", 0))
    harmless = int(stats.get("harmless", 0))
    undetected = int(stats.get("undetected", 0))
    total = sum(int(value) for value in stats.values()) or 1
    score = 90 if malicious >= 5 else 60 if malicious else 50 if suspicious >= 3 else 35 if suspicious else 0
    severity = "high" if malicious else ("medium" if suspicious else "info")
    return ProviderOutcome(
        status="success",
        score=score,
        findings=[Finding(
            label="VirusTotal engine analysis",
            severity=severity,
            detail=f"{malicious} malicious, {suspicious} suspicious, {harmless} harmless, and {undetected} undetected results across {total} engines.",
        )],
    )


async def virustotal_report(target: str, target_type: str) -> ProviderOutcome:
    endpoint_type = "urls" if target_type == "url" else ("domains" if target_type == "domain" else "ip_addresses")
    identifier = base64.urlsafe_b64encode(target.encode()).decode().strip("=") if target_type == "url" else target
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(12.0, connect=5.0)) as client:
            response = await client.get(
                f"https://www.virustotal.com/api/v3/{endpoint_type}/{identifier}",
                headers={"x-apikey": settings.virustotal_api_key},
            )
    except httpx.HTTPError:
        return ProviderOutcome(
            status="unavailable",
            score=0,
            findings=[Finding(
                label="VirusTotal unavailable",
                severity="info",
                detail="The external provider could not be reached. Local analysis is still complete.",
            )],
        )
    if response.status_code == 200:
        try:
            if len(response.content) > MAX_PROVIDER_RESPONSE_BYTES:
                raise ValueError("Provider response is too large")
            payload = response.json()
            stats = payload.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            if not isinstance(stats, dict):
                raise ValueError("Invalid provider statistics")
            return provider_result(stats)
        except (AttributeError, TypeError, ValueError):
            return ProviderOutcome(
                status="unavailable",
                score=0,
                findings=[Finding(
                    label="VirusTotal unavailable",
                    severity="info",
                    detail="The external provider returned an invalid response. Local analysis is still complete.",
                )],
            )
    if response.status_code == 404:
        return ProviderOutcome(
            status="not_found",
            score=0,
            findings=[Finding(
                label="VirusTotal report unavailable",
                severity="info",
                detail="No existing VirusTotal report was found. ThreatScope did not submit this URL for scanning.",
            )],
        )
    if response.status_code == 429:
        return ProviderOutcome(
            status="rate_limited",
            score=0,
            findings=[Finding(
                label="VirusTotal quota reached",
                severity="info",
                detail="The external provider is currently rate-limited. Local analysis is still complete.",
            )],
        )
    return ProviderOutcome(
        status="unavailable",
        score=0,
        findings=[Finding(
            label="VirusTotal unavailable",
            severity="info",
            detail="The external provider could not return a report. Local analysis is still complete.",
        )],
    )


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


@app.post(
    "/api/scans",
    response_model=ScanResult,
    status_code=201,
    dependencies=[Depends(enforce_scan_rate), Depends(reserve_scan_capacity)],
)
async def create_scan(payload: ScanRequest):
    target_type, normalized = classify_target(payload.target)
    requested_mode = (
        "virustotal"
        if settings.virustotal_api_key and payload.share_with_virustotal
        else "local"
    )
    cached = get_cached_scan(
        settings.database_path,
        normalized,
        settings.cache_ttl_seconds,
        requested_mode,
    )
    if cached:
        cache_finding = Finding(label="Cached result", severity="info", detail="This result was reused from a recent scan to conserve provider quota.")
        return cached.model_copy(update={"cached": True, "findings": [*cached.findings, cache_finding]})

    score, findings = await local_analysis(payload.target, normalized, target_type)
    provider = "ThreatScope local analysis"
    completed_mode = "local"
    cacheable = True

    if requested_mode == "virustotal":
        completed_mode = "virustotal"
        permitted, reason = reserve_provider_request(
            settings.database_path, "virustotal", settings.vt_requests_per_minute, settings.vt_requests_per_day
        )
        if permitted:
            outcome = await virustotal_report(normalized, target_type)
            score = max(score, outcome.score)
            findings.extend(outcome.findings)
            if outcome.status == "success":
                provider = "ThreatScope + VirusTotal report"
            else:
                cacheable = False
        else:
            cacheable = False
            findings.append(Finding(label="VirusTotal budget protected", severity="info", detail=f"Live lookup skipped: {reason}. Local analysis is still complete."))
    elif settings.virustotal_api_key:
        findings.append(Finding(label="VirusTotal lookup disabled", severity="info", detail="Enable the optional lookup only when you need an existing external report."))

    stored_target = redact_target(normalized, target_type)
    if stored_target != normalized:
        findings.append(Finding(
            label="Sensitive URL data redacted",
            severity="info",
            detail="The URL query string was analyzed but was not retained in scan history.",
        ))

    scanned_at = datetime.now(timezone.utc)
    result = ScanResult(
        id=hashlib.sha256(f"{normalized}:{scanned_at.isoformat()}".encode()).hexdigest()[:12],
        target=stored_target,
        target_type=target_type,
        score=score,
        verdict=verdict_for_score(score),
        provider=provider,
        scanned_at=scanned_at,
        findings=findings,
    )
    save_scan(
        settings.database_path,
        result,
        completed_mode,
        cache_target=normalized,
        cacheable=cacheable,
        max_stored_scans=settings.max_stored_scans,
    )
    return result
