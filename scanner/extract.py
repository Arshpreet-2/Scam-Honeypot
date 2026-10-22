"""
Scam Honeypot — identifier extraction, brand check & risk scoring.

From the VISIBLE captured content (text + links), pull out the identifiers a
scam uses to collect money or contact victims:
  - UPI VPA (e.g. name@okaxis)
  - Indian phone numbers
  - Telegram / WhatsApp handles & links
  - Crypto wallet addresses (BTC / ETH-style)

Then combine URL triage + brand-vs-page mismatch + what was found into a single
explainable risk verdict.

Pure pattern-matching on already-captured public text. No network calls.

(An LLM step can REPLACE/augment the regexes to classify each identifier's
role — payment vs contact vs warning — and to read brand from a screenshot.
Hook: classify_with_llm() stub below.)
"""
from __future__ import annotations
from dataclasses import dataclass, field, asdict
import re

from triage import TriageResult, OFFICIAL_BRANDS  # same package

# --- Identifier patterns ----------------------------------------------------
UPI_RE      = re.compile(r"\b[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64}\b")
# UPI handles end in a bank/psp suffix; filter emails out with a suffix list.
UPI_SUFFIX  = {"okaxis", "okicici", "oksbi", "okhdfcbank", "ybl", "paytm",
               "apl", "ibl", "axl", "upi", "sbi", "hdfcbank", "icici",
               "axisbank", "kotak", "barodampay", "cnrb", "fbl", "idfcbank"}
PHONE_RE    = re.compile(r"(?:(?:\+91|91|0)?[\-\s]?)?([6-9]\d{9})\b")
TG_RE       = re.compile(r"(?:https?://)?t\.me/[A-Za-z0-9_]{3,}|@[A-Za-z0-9_]{4,}")
WA_RE       = re.compile(r"(?:https?://)?(?:wa\.me|api\.whatsapp\.com/send)\S*")
BTC_RE      = re.compile(r"\b(?:bc1[a-z0-9]{20,}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b")
ETH_RE      = re.compile(r"\b0x[a-fA-F0-9]{40}\b")


@dataclass
class Identifiers:
    upi: list = field(default_factory=list)
    phone: list = field(default_factory=list)
    telegram: list = field(default_factory=list)
    whatsapp: list = field(default_factory=list)
    crypto: list = field(default_factory=list)

    def total(self) -> int:
        return sum(len(v) for v in asdict(self).values())

    def as_dict(self):
        return asdict(self)


def extract_identifiers(text: str, links: list[str] | None = None) -> Identifiers:
    blob = text + "\n" + "\n".join(links or [])
    ids = Identifiers()

    for m in UPI_RE.findall(blob):
        suffix = m.split("@")[-1].lower()
        if suffix in UPI_SUFFIX:                 # real UPI handle, not an email
            ids.upi.append(m)

    ids.phone    = sorted({m for m in PHONE_RE.findall(blob)})
    tg = {m.rstrip("/").lower() for m in TG_RE.findall(blob)}
    # drop bare @handles that are actually UPI suffixes (e.g. @okaxis from name@okaxis)
    tg = {h for h in tg if not (h.startswith("@") and h[1:] in UPI_SUFFIX)}
    ids.telegram = sorted(tg)
    ids.whatsapp = sorted({m.rstrip("/").lower() for m in WA_RE.findall(blob)})
    ids.crypto   = sorted(set(BTC_RE.findall(blob)) | set(ETH_RE.findall(blob)))
    ids.upi      = sorted(set(ids.upi))
    return ids


def brand_from_page(text: str, title: str) -> str | None:
    """Which official brand does the PAGE claim to be (by name in text/title)?"""
    blob = (title + " " + text).lower()
    for brand in OFFICIAL_BRANDS:
        if re.search(rf"\b{brand}\b", blob):
            return brand
    # common display names
    for name, brand in {"state bank": "sbi", "income tax": "incometax",
                        "traffic": "echallan", "e-challan": "echallan",
                        "india post": "indiapost"}.items():
        if name in blob:
            return brand
    return None


@dataclass
class Verdict:
    url: str
    score: int
    band: str
    reasons: list = field(default_factory=list)
    identifiers: dict = field(default_factory=dict)
    claimed_brand: str | None = None
    actual_host: str = ""

    def as_dict(self):
        return asdict(self)


def assess(triage_res: TriageResult, capture) -> Verdict:
    """Combine URL triage + page brand mismatch + identifiers into one verdict."""
    score = triage_res.score
    reasons = [f"{s.name}: {s.reason}" for s in triage_res.signals]

    ids = extract_identifiers(getattr(capture, "text", "") or "",
                              getattr(capture, "links", []) or [])

    # Page-level brand mismatch (stronger than URL-only check)
    page_brand = brand_from_page(getattr(capture, "text", "") or "",
                                 getattr(capture, "title", "") or "")
    host = (getattr(capture, "final_url", "") or triage_res.url)
    claimed = page_brand or triage_res.claimed_brand
    if page_brand:
        official = OFFICIAL_BRANDS.get(page_brand, "")
        if official and official not in host:
            score += 40
            reasons.append(
                f"page_brand_mismatch: page presents itself as '{page_brand}' "
                f"but is served from '{host}', not '{official}'.")

    # A payment identifier present on a suspicious page is a strong signal
    if ids.upi and (triage_res.band != "LOW" or page_brand):
        score += 25
        reasons.append(f"payment_identifier: page exposes UPI id(s) {ids.upi} "
                       f"while impersonating / looking suspicious.")
    if ids.telegram or ids.whatsapp:
        score += 10
        reasons.append("off_platform_contact: pushes victims to Telegram/WhatsApp.")
    if ids.crypto:
        score += 10
        reasons.append(f"crypto_payout: crypto wallet(s) present {ids.crypto}.")

    # capture failures are themselves a (weak) signal
    if getattr(capture, "status", "") in {"blocked", "error"}:
        reasons.append(f"capture_{capture.status}: page did not render normally "
                       f"(can indicate cloaking / anti-bot).")

    score = min(score, 100)
    band = "HIGH" if score >= 55 else "SUSPICIOUS" if score >= 25 else "LOW"
    return Verdict(url=triage_res.url, score=score, band=band, reasons=reasons,
                   identifiers=ids.as_dict(), claimed_brand=claimed, actual_host=host)


def classify_with_llm(text, identifiers):
    """
    PLACEHOLDER for the AI layer: send the page text + candidate identifiers to
    an LLM to (1) classify each identifier's role (payment / contact / warning /
    quoted), and (2) read the impersonated brand from the screenshot.
    Return structured, source-quoted results. Not wired in the demo.
    """
    raise NotImplementedError
