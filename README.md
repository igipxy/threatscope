# 🛡️ ThreatScope

ThreatScope is an original threat-intelligence dashboard for inspecting URLs, domains, and IP addresses. It turns security signals into a simple risk score, verdict, and explainable findings.

## Current MVP

- URL, domain, and IP input validation
- URL normalization with fragments and embedded credentials removed
- Structural phishing checks for punycode, credential tricks, suspicious wording, encoding, ports, and deep subdomains
- DNS resolution checks and blocking for local, private, and reserved networks
- Risk score from 0–100
- Low-risk, suspicious, or malicious verdicts
- Explainable findings rather than a black-box result
- Local demo analysis when no API key is configured
- Cache-first results with a 24-hour default lifetime
- Optional VirusTotal report lookup, protected by local request budgets
- No automatic VirusTotal URL submissions or polling
- Persistent SQLite scan history
- Responsive React dashboard
- FastAPI backend with interactive API documentation
- Backend API tests

## Tech stack

- Frontend: React, TypeScript, Vite
- Backend: Python, FastAPI
- Database: SQLite
- Intelligence provider: VirusTotal API v3 (optional)

## Run locally

### Backend on Windows

```bat
cd backend
py -m venv venv
venv\Scripts\activate
python -m pip install -r requirements.txt
copy .env.example .env
python -m uvicorn app.main:app --reload
```

The API runs at `http://localhost:8000`. API documentation is available at `http://localhost:8000/docs`.

To enable VirusTotal, put your key in `backend/.env`:

```env
VIRUSTOTAL_API_KEY=your_key_here
```

Never commit the `.env` file.

When a VirusTotal key is enabled, the user must explicitly select the optional lookup. ThreatScope checks only an existing VirusTotal report and never submits a new URL or polls for a new analysis. Results are cached locally for 24 hours by default to conserve quota.

The default local limits are 3 VirusTotal requests per minute and 400 per day. Adjust them in `.env` only if your VirusTotal plan permits it:

```env
VT_REQUESTS_PER_MINUTE=3
VT_REQUESTS_PER_DAY=400
CACHE_TTL_SECONDS=86400
```

Do not submit private or confidential URLs. ThreatScope does not open the target page or execute its content.

### Frontend

In a second terminal:

```bat
cd frontend
npm install
npm run dev
```

Open `http://localhost:5173`.

### Tests

From the `backend` folder with the virtual environment active:

```bat
python -m pytest
```

## Updating an existing local checkout

```bat
cd C:\Users\Administrator\threatscope
git pull
```

Restart the backend after pulling. Vite normally refreshes the frontend automatically.

## Important note

ThreatScope presents security indicators and cannot guarantee that a target is safe. Only scan targets you are authorized to inspect.
