# 🛡️ ThreatScope

ThreatScope is an original threat-intelligence dashboard for inspecting URLs, domains, and IP addresses. It turns security signals into a simple risk score, verdict, and explainable findings.

## Current MVP

- URL, domain, and IP input validation
- Risk score from 0–100
- Clean, suspicious, or malicious verdict
- Explainable findings rather than a black-box result
- Local demo analysis when no API key is configured
- VirusTotal API v3 lookup when a key is configured
- Responsive React dashboard
- FastAPI backend with interactive API documentation

## Tech stack

- Frontend: React, TypeScript, Vite
- Backend: Python, FastAPI
- Intelligence provider: VirusTotal API v3 (optional)
- Planned persistence: SQLite

## Run locally

### Backend

```bash
cd backend
python -m venv venv
# Windows: venv\Scripts\activate
# macOS/Linux: source venv/bin/activate
pip install -r requirements.txt
copy .env.example .env
uvicorn app.main:app --reload
```

The API runs at `http://localhost:8000`. API documentation is available at `http://localhost:8000/docs`.

To enable VirusTotal, put your key in `backend/.env`:

```env
VIRUSTOTAL_API_KEY=your_key_here
```

Never commit the `.env` file.

### Frontend

```bash
cd frontend
npm install
npm run dev
```

Open `http://localhost:5173`.

## Important note

ThreatScope presents security indicators and cannot guarantee that a target is safe. Only scan targets you are authorized to inspect.
