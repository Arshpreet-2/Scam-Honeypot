# 🛡️ Scam Honeypot

**See the scam before it sees you** — open a suspicious link safely, defeat cloaking, and expose the account hidden inside it.

*Submission for Kritical Hacks '26 · AI / ML track · Powered by **TinyFish**.*

---

## The problem

Indian scam pages hide in two ways:

1. **Cloaking** — they show the fake payment screen only to a genuine Indian mobile visitor. Ordinary scanners (Google Safe Browsing, VirusTotal, urlscan) request the page like a bot, get a blank/decoy page, and can't flag it.
2. **A hidden identifier** — the UPI ID / Telegram bot that actually collects the money sits several clicks deep in the funnel; no casual visitor ever sees it.

So dangerous links stay live, and victims pay before anyone can warn them.

## What it does

Paste a suspicious link (or a seized identifier). Scam Honeypot:

1. **Triage** — cheap URL checks (look-alike domain, fake-gov, bad TLD, scam keywords) decide if it's worth a full scan.
2. **Open safely** — a **TinyFish stealth cloud browser** on an **Indian exit** opens it the way a real victim would, defeating the cloaking that blinds normal scanners. Read-only: it observes, it never fills forms or pays.
3. **Extract** — pulls the hidden identifiers from the page: UPI IDs, phone numbers, Telegram/WhatsApp handles, crypto wallets.
4. **Catch the fake** — compares the brand the page *claims* to be against the domain it's *served from*.
5. **Score & seal** — a transparent risk score with reasons, and every artefact hashed (SHA-256) + timestamped as evidence.
6. **Warn & report** — a clear verdict plus a pre-filled `cybercrime.gov.in` "Report Suspect" draft (reviewed by a human before filing).

## How TinyFish is used (core, not an add-on)

TinyFish is the engine. The whole value — reaching the real cloaked funnel — depends on it:

| TinyFish | Role in Scam Honeypot |
|---|---|
| **Browser Infrastructure** (stealth cloud browser) | Opens cloaked pages a normal scraper can't — presenting as a genuine Indian mobile visitor so the scam reveals its real funnel. |
| **Web Agent** | Walks the multi-step funnel to reach the hidden payment step (roadmap for deep investigations). |
| **Search API** | Finds where an extracted identifier appears elsewhere on the web. |
| **Fetch API** | Pulls clean, structured content from each discovered page. |

The scan engine is swappable behind one interface (`scanner/scan.py`):

- `SCAN_ENGINE=tinyfish` + `TINYFISH_API_KEY` → the real stealth, India-exit run (`open_with_tinyfish`).
- `SCAN_ENGINE=playwright` (default) → a local fallback so the demo runs without a key.

> Without TinyFish there is no reliable capture of cloaked pages — and without that, nothing to extract. That is why the integration is meaningful.

## Run it

```bash
pip install -r requirements.txt
python -m playwright install chromium

# Demo (local engine, no key needed) — try the built-in test fixture:
python run_demo.py

# Or a specific URL:
python run_demo.py "https://example.com"

# Dashboard:
streamlit run app.py

# Real run with TinyFish (stealth, India exit):
export TINYFISH_API_KEY=your_key
export SCAN_ENGINE=tinyfish
streamlit run app.py
```

## Project layout

```
scam-honeypot/
├── scanner/
│   ├── triage.py      # URL risk analysis (no browser)
│   ├── scan.py        # open + capture + SHA-256 seal; TinyFish & Playwright engines
│   └── extract.py     # identifier extraction, brand check, risk scoring
├── app.py             # Streamlit dashboard
├── run_demo.py        # end-to-end CLI
├── fixtures/          # neutral, labelled test page (no real branding / payment)
└── evidence/          # per-scan output (screenshot + report.json)
```

## AI / ML

- **Now:** deterministic triage + regex identifier extraction + brand-vs-domain matching + a weighted, explainable risk score.
- **Next (hook `classify_with_llm` in `extract.py`):** an LLM classifies each identifier's *role* (payment vs contact vs warning) and reads the impersonated brand from the screenshot — the fuzzy judgement a human analyst makes.

## What exists, and what we add

URL reputation is a **solved** problem (Safe Browsing, VirusTotal, urlscan, I4C's Report-&-Check-Suspect, and Netcraft for banks). We don't rebuild it — we query it as input. Our contribution is the part they miss: the **India-specific cloaked funnel** and the **hidden payment identifier**, fed toward I4C.

## Ethics & boundaries

- **Read-only**: opens and observes *public* pages. No form submission, no payments, no credential use — so it stays a defensive tool, not an attack tool.
- **Not a guarantee**: strong anti-bot systems can still block a stealth browser; a blocked page is recorded as a signal, not a success.
- **Explainable**: every verdict is a risk score *with reasons*, never a black-box "100% scam".
- **Assisted, not automatic**: reports are prepared for human review before filing; no auto-emailing third parties.

## Backend API + web front-end

`api.py` exposes the scanner as one endpoint the website calls.

```bash
pip install -r requirements.txt
python -m playwright install chromium
uvicorn api:app --reload --port 8000
# real engine:  SCAN_ENGINE=tinyfish TINYFISH_API_KEY=... uvicorn api:app --port 8000
```

`POST /scan  {"url": "..."}` returns:

```json
{
  "url": "...", "served_from": "host", "score": 85, "band": "HIGH",
  "claimed_brand": "e-challan (Parivahan)",
  "identifiers": {"upi": ["..."], "phone": [], "telegram": ["..."], "whatsapp": [], "crypto": ["..."]},
  "reasons": ["name: reason", "..."],
  "evidence": {"status": "captured", "captured_at": "...", "engine": "tinyfish", "sha256": "...", "vantage": "..."},
  "real": "https://echallan.parivahan.gov.in/",
  "capture_title": "...", "capture_line": "..."
}
```

**Front-end** (`frontend.html`): opens in demo mode and calls the API when it's reachable. Point it at the backend one of two ways:

- edit `var API_BASE = "http://localhost:8000"` near the top of the page script, or
- in the browser console: `localStorage.setItem('sh-api','http://localhost:8000')` then reload.

A chip in the header shows **backend: live** vs **backend: demo**. CORS is open in `api.py` for development — restrict it for production.

> Note: hosted as a sandboxed artifact the page cannot reach an external API (the sandbox blocks cross-origin calls), so it stays in demo mode there. Served from your own host, it goes live.

## Status

Working prototype. Market figures cited in the pitch and the exact TinyFish per-session cost are to be confirmed before the finale.
