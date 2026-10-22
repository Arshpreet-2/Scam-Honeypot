"""
Scam Honeypot — backend API (FastAPI).

Exposes the read-only scanner pipeline (triage -> open+capture -> extract ->
score+seal) as a single endpoint the front-end calls.

Run:
    pip install -r requirements.txt
    python -m playwright install chromium
    uvicorn api:app --reload --port 8000
    # real engine:  SCAN_ENGINE=tinyfish  TINYFISH_API_KEY=...  uvicorn api:app --port 8000

Then point the front-end at it: set  API_BASE = "http://localhost:8000"  in the HTML.
POST /scan   {"url": "..."}   ->   verdict + identifiers + sealed evidence (JSON below).
"""
from __future__ import annotations
import os, sys, datetime
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "scanner"))
from triage import triage, OFFICIAL_BRANDS
from scan import scan
from extract import assess, brand_from_page

app = FastAPI(title="Scam Honeypot API", version="1.0")

# Dev CORS: allow the front-end (any origin) to call this. Lock down for prod.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Friendly display names for the brands in triage's OFFICIAL_BRANDS map.
DISPLAY = {
    "parivahan": "e-challan (Parivahan)", "echallan": "e-challan (Parivahan)",
    "incometax": "Income Tax Dept", "sbi": "State Bank of India (SBI)",
    "hdfc": "HDFC Bank", "icici": "ICICI Bank", "indiapost": "India Post",
    "epfo": "EPFO", "uidai": "UIDAI / Aadhaar", "irctc": "IRCTC", "npci": "NPCI",
}


class ScanIn(BaseModel):
    url: str


@app.get("/")
def health():
    return {"ok": True, "service": "scam-honeypot", "engine": os.environ.get("SCAN_ENGINE", "playwright")}


@app.post("/scan")
def do_scan(inp: ScanIn):
    url = inp.url.strip()
    out_dir = os.path.join("evidence", "api_" + datetime.datetime.now().strftime("%Y%m%d_%H%M%S"))

    t = triage(url)
    cap = scan(url, out_dir=out_dir)          # read-only open + capture + SHA-256 seal
    v = assess(t, cap)                        # identifiers + brand check + score

    page_brand = brand_from_page(getattr(cap, "text", "") or "", getattr(cap, "title", "") or "")
    brand_key = page_brand or t.claimed_brand
    official_host = OFFICIAL_BRANDS.get(brand_key, "") if brand_key else ""
    host = cap.final_url or t.url
    is_official = (v.band == "LOW") and not any(v.identifiers.values())

    real = None
    if is_official:
        real = url
    elif official_host:
        real = "https://" + official_host + "/"

    # one-line capture summary for the UI's evidence frame
    cap_line = (cap.text or "").strip().replace("\n", " ")
    cap_line = (cap_line[:160] + "…") if len(cap_line) > 160 else cap_line

    return {
        "url": url,
        "served_from": host,
        "score": v.score,
        "band": v.band,
        "claimed_brand": DISPLAY.get(brand_key, brand_key) if brand_key else None,
        "identifiers": v.identifiers,                 # {upi:[], phone:[], telegram:[], whatsapp:[], crypto:[]}
        "reasons": v.reasons,                         # ["name: reason", ...]
        "evidence": {
            "status": cap.status,
            "captured_at": cap.captured_at,
            "engine": (cap.provenance or {}).get("engine", cap.engine),
            "sha256": cap.screenshot_sha256 or "",
            "vantage": (cap.provenance or {}).get("vantage", ""),
            "streaming_url": cap.streaming_url or "",   # show TinyFish's live browser in the demo
        },
        "real": real,
        "capture_title": cap.title or ("Captured page" if cap.status == "captured" else "Could not capture"),
        "capture_line": cap_line,
    }
