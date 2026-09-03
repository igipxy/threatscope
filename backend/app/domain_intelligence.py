import asyncio
import ipaddress
import re
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote, urlparse

import httpx
import tldextract

from .models import Finding


RDAP_BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
MAX_RDAP_RESPONSE_BYTES = 1_000_000
_extract_domain = tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=False)
_bootstrap: dict[str, str] = {}
_bootstrap_lock = asyncio.Lock()
_REGISTERED_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def registrable_domain(hostname: str) -> str:
    """Return a normalized registrable domain without making a network request."""
    normalized = hostname.rstrip(".").encode("idna").decode("ascii").lower()
    extracted = _extract_domain(normalized)
    return extracted.top_domain_under_public_suffix or normalized


def validate_rdap_base_url(value: str) -> str:
    """Accept only ordinary public HTTPS RDAP service URLs from the bootstrap."""
    parsed = urlparse(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.port not in {None, 443}
    ):
        raise ValueError("Unsafe RDAP service URL")
    try:
        address = ipaddress.ip_address(parsed.hostname)
    except ValueError:
        pass
    else:
        if not address.is_global:
            raise ValueError("Non-public RDAP service address")
    return value.rstrip("/")


def response_json(response: httpx.Response) -> dict[str, Any]:
    declared_size = response.headers.get("content-length")
    if declared_size and int(declared_size) > MAX_RDAP_RESPONSE_BYTES:
        raise ValueError("RDAP response is too large")
    if len(response.content) > MAX_RDAP_RESPONSE_BYTES:
        raise ValueError("RDAP response is too large")
    payload = response.json()
    if not isinstance(payload, dict):
        raise ValueError("RDAP response must be an object")
    return payload


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
        for tlds, urls in response_json(response).get("services", []):
            if urls:
                for item in tlds:
                    _bootstrap[item.lower()] = validate_rdap_base_url(urls[0])
    return _bootstrap.get(tld)


def is_valid_registered_domain(value: str) -> bool:
    if not value or "." not in value:
        return False
    if not _REGISTERED_DOMAIN_RE.fullmatch(value):
        return False
    return True


async def domain_intelligence(hostname: str) -> tuple[int, list[Finding]]:
    if "." not in hostname:
        return 0, []
    try:
        registered = registrable_domain(hostname)
        if not is_valid_registered_domain(registered):
            raise ValueError("Invalid registrable domain")
        tld = registered.rsplit(".", 1)[-1]
        async with httpx.AsyncClient(timeout=httpx.Timeout(8.0, connect=4.0), follow_redirects=False) as client:
            base_url = await rdap_base_for_tld(client, tld)
            if not base_url:
                return 0, [Finding(label="Registration data unavailable", severity="info", detail="No RDAP registry was found for this top-level domain.")]
            response = await client.get(f"{base_url}/domain/{quote(registered, safe='.-')}")
    except (httpx.HTTPError, UnicodeError, ValueError):
        return 0, [Finding(label="Registration data unavailable", severity="info", detail="The public RDAP registry could not be reached or returned invalid data.")]

    if response.status_code == 404:
        return 0, [Finding(label="Registration data unavailable", severity="info", detail="The RDAP registry has no record for this domain.")]
    if response.status_code == 429:
        return 0, [Finding(label="Registration data rate-limited", severity="info", detail="The public RDAP registry is temporarily rate-limited.")]
    if response.status_code >= 400:
        return 0, [Finding(label="Registration data unavailable", severity="info", detail="The public RDAP registry returned an error.")]

    try:
        return interpret_rdap(response_json(response))
    except (TypeError, ValueError):
        return 0, [Finding(label="Registration data unavailable", severity="info", detail="The public RDAP registry returned invalid data.")]
