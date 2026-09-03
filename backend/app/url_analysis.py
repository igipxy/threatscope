import asyncio
import ipaddress
import re
import socket
from urllib.parse import unquote, urlparse, urlunparse

from fastapi import HTTPException

from .models import Finding


SUSPICIOUS_TERMS = {
    "account",
    "auth",
    "banking",
    "confirm",
    "login",
    "password",
    "recover",
    "secure",
    "signin",
    "update",
    "verify",
    "wallet",
}


def normalize_url(value: str) -> str:
    value = value.strip()
    try:
        parsed = urlparse(value)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError as error:
        raise HTTPException(status_code=422, detail="The URL is malformed.") from error
    if parsed.scheme.lower() not in {"http", "https"}:
        raise HTTPException(status_code=422, detail="Only HTTP and HTTPS URLs can be scanned.")
    if not hostname:
        raise HTTPException(status_code=422, detail="The URL must include a valid hostname.")

    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        try:
            normalized_host = hostname.rstrip(".").encode("idna").decode("ascii").lower()
        except UnicodeError as error:
            raise HTTPException(status_code=422, detail="The URL contains an invalid hostname.") from error
    else:
        normalized_host = address.compressed
        if address.version == 6:
            normalized_host = f"[{normalized_host}]"

    # Always rebuild the authority so credentials are never retained or disclosed.
    netloc = f"{normalized_host}:{port}" if port else normalized_host
    return urlunparse(parsed._replace(scheme=parsed.scheme.lower(), netloc=netloc, fragment=""))


def _is_non_public_ip(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return not address.is_global


async def check_dns(hostname: str) -> Finding:
    if _is_non_public_ip(hostname):
        raise HTTPException(status_code=422, detail="Local, private, and reserved IP addresses cannot be scanned.")

    try:
        records = await asyncio.wait_for(
            asyncio.to_thread(socket.getaddrinfo, hostname, None),
            timeout=3,
        )
    except (TimeoutError, socket.gaierror):
        return Finding(
            label="DNS resolution failed",
            severity="medium",
            detail="The hostname did not resolve within the DNS check window.",
        )

    addresses = {record[4][0] for record in records}
    if any(_is_non_public_ip(address) for address in addresses):
        raise HTTPException(status_code=422, detail="Hostnames resolving to local, private, or reserved networks cannot be scanned.")
    return Finding(
        label="Public DNS resolution",
        severity="info",
        detail=f"The hostname resolves to {len(addresses)} public address{'es' if len(addresses) != 1 else ''}.",
    )


def analyze_url_structure(original: str, normalized: str) -> tuple[int, list[Finding]]:
    parsed = urlparse(normalized)
    original_parsed = urlparse(original.strip())
    host = parsed.hostname or ""
    decoded = unquote(f"{host}{parsed.path}{parsed.query}").lower()
    findings: list[Finding] = []
    score = 0

    if parsed.scheme == "http":
        score += 20
        findings.append(Finding(label="Unencrypted connection", severity="medium", detail="The URL uses HTTP instead of HTTPS."))

    if original_parsed.username or original_parsed.password:
        score += 30
        findings.append(Finding(label="Embedded credentials", severity="high", detail="The original URL contained user information before the hostname."))

    if _is_non_public_ip(host):
        raise HTTPException(status_code=422, detail="Local, private, and reserved IP addresses cannot be scanned.")

    try:
        ipaddress.ip_address(host)
        score += 15
        findings.append(Finding(label="IP-based URL", severity="medium", detail="The URL uses an IP address instead of a domain name."))
    except ValueError:
        pass

    if "xn--" in host.lower():
        score += 30
        findings.append(Finding(label="Punycode hostname", severity="high", detail="The hostname uses internationalized encoding that can imitate familiar names."))

    labels = host.split(".")
    if len(labels) >= 5:
        score += 15
        findings.append(Finding(label="Deep subdomain chain", severity="medium", detail="The hostname contains an unusually deep subdomain structure."))

    matched = sorted(term for term in SUSPICIOUS_TERMS if term in decoded)
    if matched:
        contribution = min(30, len(matched) * 10)
        score += contribution
        findings.append(Finding(label="Sensitive-action wording", severity="medium", detail=f"URL text contains: {', '.join(matched)}."))

    if len(normalized) > 150:
        score += 15
        findings.append(Finding(label="Unusually long URL", severity="medium", detail="Long URLs can be used to hide misleading destinations."))

    if normalized.count("%") >= 4:
        score += 10
        findings.append(Finding(label="Heavy URL encoding", severity="low", detail="The URL contains several encoded characters."))

    if parsed.port and parsed.port not in {80, 443}:
        score += 10
        findings.append(Finding(label="Non-standard port", severity="low", detail=f"The URL uses port {parsed.port}."))

    if not findings:
        findings.append(Finding(label="Structural checks passed", severity="info", detail="No suspicious URL-structure signals were found."))

    return min(score, 100), findings
