# ThreatScope — Development Summary (August 2026)

## Project purpose

ThreatScope is an original, explainable threat-intelligence dashboard for inspecting URLs, domains, and IP addresses. It helps users understand risk signals without opening the target page.

This project is an independent implementation. VirusTotal is optional supporting intelligence, not the product’s sole source of truth.

## What is working

- React + TypeScript + Vite frontend
- FastAPI backend with interactive documentation at `/docs`
- SQLite database for recent scan history and cached results
- URL, domain, and IP validation and normalization
- Local structural checks for:
  - unencrypted HTTP
  - suspicious action words such as `login`, `verify`, and `update`
  - embedded credentials and unusual ports
  - punycode hostnames
  - heavy URL encoding
  - long URLs and deeply nested subdomains
- DNS resolution checks
- Blocking for localhost, private, reserved, and otherwise unsafe network targets
- Domain-registration intelligence through public RDAP registries:
  - domain age
  - expiry information
  - registrar
  - authoritative nameservers
- Explainable 0–100 risk score with low-risk, suspicious, or malicious verdicts
- Optional VirusTotal lookup for an **existing** report only
- Cache-first results (24-hour default)
- Local VirusTotal request budgets (3 per minute, 400 per day by default)
- No automatic VirusTotal URL submissions or polling
- Responsive dashboard and recent-scan list
- Backend tests

## Local setup confirmed on Windows

```bat
cd C:\\Users\\Administrator\\threatscope
git pull
cd backend
venv\\Scripts\\activate
python -m pip install -r requirements.txt
copy .env.example .env
python -m uvicorn app.main:app --reload
```

Run the frontend in another terminal:

```bat
cd C:\\Users\\Administrator\\threatscope\\frontend
npm install
npm run dev
```

Open `http://localhost:5173`.

## Security and privacy decisions

- Keep secrets only in `backend/.env`; never commit that file.
- If a provider key is ever exposed, revoke and replace it immediately.
- The optional VirusTotal control only checks existing public reports. ThreatScope does not submit new URLs or wait for external analysis.
- Do not scan private, confidential, or unauthorized targets.
- ThreatScope does not load or execute the inspected webpage; it analyzes the target string and permitted metadata.

## Safe verification inputs

Use these only in ThreatScope’s input field; do not open them in a browser:

```text
http://secure-login.verify.example.com/account/update
https://xn--pple-43d.example/login
http://127.0.0.1/admin
```

Expected behavior:

- The first input should show unencrypted-connection and sensitive-wording signals.
- The second should exercise punycode and sensitive-wording detection.
- The last should be rejected or treated as a private/local network target.
- DNS or RDAP unavailability for `.example` is expected because it is a reserved test domain.

## Recommended next version

1. Add an analyst-friendly result detail view that groups signals by URL, DNS, and registration intelligence.
2. Add automated frontend tests for the optional lookup control and scan-result rendering.
3. Add a small, versioned set of safe regression fixtures for scoring rules.
4. Add rate-limit and cache status to the UI so users know when an optional provider request was avoided.
5. Consider additional independent sources only after defining their privacy, reliability, and quota impact.

## Current limitation

ThreatScope reports indicators, not certainty. A low score does not prove a target is safe, and a high score should be reviewed in context.
