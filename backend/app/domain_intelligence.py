import asyncio
from datetime import datetime, timezone
from typing import Any

import httpx

from .models import Finding


RDAP_BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
_bootstrap: dict[str, str] = {}
_bootstrap_lock = asyncio.Lock()


def parse_rdap_date(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def event_date(payload: dict[str, Any], actions: set[str]) -> datetime | None:
    for event in payload.get("events", []):
        if str(event.get("eventAction", "")).lower() in actions:
            return parse_rdap_date(event.get("eventDate"))
    return None


def registrar_name(payload: dict[str, Any]) -> str | None:
    for entity in payload.get("entities", []):
        if "registrar" not in entity.get("roles", []):
            continue
        vcard = entity.get("vcardArray", [None, []])
        for field in vcard[1] if len(vcard) > 1 else []:
            if field[0] == "fn" and len(field) > 3:
                return str(field[3])
    return None


def interpret_rdap(payload: dict[str, Any], now: datetime | None = None) -> tuple[int, list[Finding]]:
    now = now or datetime.now(timezone.utc)
    findings: list[Finding] = []
    score = 0
    registration = event_date(payload, {"registration", "registered"})
    expiration = event_date(payload, {"expiration", "expiry"})

    if registration:
        age_days = max(0, (now - registration).days)
        if age_days < 30:
            score += 25
            severity = "high"
            detail = f"Domain was registered {age_days} day{'s' if age_days != 1 else ''} ago."
        elif age_days < 180:
            score += 10
            severity = "medium"
            detail = f"Domain was registered {age_days} days ago."
        else:
            severity = "info"
            detail = f"Domain registration age: {age_days} days."
        findings.append(Finding(label="Domain registration age", severity=severity, detail=detail))
    else:
        findings.append(Finding(label="Registration age unavailable", severity="info", detail="The registry did not provide a registration date."))

    if expiration:
        remaining_days = (expiration - now).days
        if 0 <= remaining_days < 30:
            findings.append(Finding(label="Domain expiry approaching", severity="low", detail=f"Domain registration expires in {remaining_days} days."))
        elif remaining_days < 0:
            findings.append(Finding(label="Domain registration expired", severity="medium", detail="Registry data indicates the domain registration has expired."))
        else:
            findings.append(Finding(label="Domain expiry", severity="info", detail=f"Domain registration expires in {remaining_days} days."))

    registrar = registrar_name(payload)
    if registrar:
        findings.append(Finding(label="Registrar", severity="info", detail=registrar))

    nameservers = [item.get("ldhName") for item in payload.get("nameservers", []) if item.get("ldhName")]
    if nameservers:
        visible = ", ".join(nameservers[:3])
        suffix = "…" if len(nameservers) > 3 else ""
        findings.append(Finding(label="Authoritative nameservers", severity="info", detail=f"{visible}{suffix}"))

    return min(score, 100), findings


async def rdap_base_for_tld(client: httpx.AsyncClient, tld: str) -> str | None:
    if tld in _bootstrap:
        return _bootstrap[tld]
    async with _bootstrap_lock:
        if tld in _bootstrap:
            return _bootstrap[tld]
        response = await client.get(RDAP_BOOTSTRAP_URL)
        response.raise_for_status()
        for tlds, urls in response.json().get("services", []):
            if urls:
                for item in tlds:
                    _bootstrap[item.lower()] = urls[0]
    return _bootstrap.get(tld)


async def domain_intelligence(hostname: str) -> tuple[int, list[Finding]]:
    if "." not in hostname:
        return 0, []
    tld = hostname.rsplit(".", 1)[-1].lower()
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(8.0, connect=4.0), follow_redirects=True) as client:
            base_url = await rdap_base_for_tld(client, tld)
            if not base_url:
                return 0, [Finding(label="Registration data unavailable", severity="info", detail="No RDAP registry was found for this top-level domain.")]
            response = await client.get(f"{base_url.rstrip('/')}/domain/{hostname}")
    except httpx.HTTPError:
        return 0, [Finding(label="Registration data unavailable", severity="info", detail="The public RDAP registry could not be reached.")]

    if response.status_code == 404:
        return 0, [Finding(label="Registration data unavailable", severity="info", detail="The RDAP registry has no record for this domain.")]
    if response.status_code == 429:
        return 0, [Finding(label="Registration data rate-limited", severity="info", detail="The public RDAP registry is temporarily rate-limited.")]
    if response.status_code >= 400:
        return 0, [Finding(label="Registration data unavailable", severity="info", detail="The public RDAP registry returned an error.")]

    return interpret_rdap(response.json())
