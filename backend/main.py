from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import requests
import os
from dotenv import load_dotenv

load_dotenv()

app = FastAPI(title="ThreatScope API")

# Allow the React frontend to talk to this backend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)

VT_API_KEY = os.getenv("VT_API_KEY")

class ScanRequest(BaseModel):
    url: str

@app.get("/")
def health_check():
    return {"status": "online", "message": "ThreatScope API is running 🛡️"}

@app.post("/scan")
def scan_url(payload: ScanRequest):
    if not VT_API_KEY:
        raise HTTPException(status_code=500, detail="API key not configured")

    headers = {"x-apikey": VT_API_KEY}

    # 1. Submit the URL to VirusTotal
    submit = requests.post(
        "https://www.virustotal.com/api/v3/urls",
        headers=headers,
        data={"url": payload.url},
    )
    if submit.status_code != 200:
        raise HTTPException(status_code=submit.status_code, detail="VirusTotal API error")

    analysis_id = submit.json()["data"]["id"]

    # 2. Fetch the analysis results
    analysis = requests.get(
        f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
        headers=headers,
    ).json()

    stats = analysis["data"]["attributes"]["stats"]

    # 3. Decide the verdict
    verdict = "MALICIOUS" if stats["malicious"] > 0 else "SAFE"

    return {"url": payload.url, "verdict": verdict, "stats": stats}