"""
Scam Honeypot — URL triage engine.

Cheap, instant, no-browser checks that decide whether a URL is worth a full
(costly) TinyFish investigation. Every check returns weighted "signals" with a
human-readable reason, so the output is an explainable risk score, never a
black-box verdict.

This module is READ-ONLY analysis of a URL string + public DNS/WHOIS metadata.
It does not open, submit to, or interact with the page.
"""
from __future__ import annotations
from dataclasses import dataclass, field, asdict
from urllib.parse import urlparse
import re
import difflib

# --- Reference data (extend freely) -----------------------------------------

# Brands & govt services commonly impersonated in Indian scams, with their
# REAL domains. A page claiming to be one of these on any other domain is a
# strong red flag.
OFFICIAL_BRANDS = {
    "parivahan": "parivahan.gov.in",
    "echallan": "echallan.parivahan.gov.in",
    "incometax": "incometax.gov.in",
    "sbi": "onlinesbi.sbi",
    "hdfc": "hdfcbank.com",
    "icici": "icicibank.com",
    "indiapost": "indiapost.gov.in",
    "epfo": "epfindia.gov.in",
    "uidai": "uidai.gov.in",
    "irctc": "irctc.co.in",
    "npci": "npci.org.in",
}

# TLDs over-represented in scams / cheap throwaway domains.
SUSPICIOUS_TLDS = {
    "xyz", "top", "online", "site", "icu", "live", "shop", "cfd",
    "click", "link", "rest", "fit", "monster", "buzz", "sbs",
}

# Words that frequently appear in fraud landing pages / URLs.
SCAM_KEYWORDS = {
    "verify", "kyc", "update", "pay", "fine", "challan", "refund",
    "reward", "offer", "winner", "bonus", "unblock", "suspend",
    "confirm", "secure", "login", "otp", "gift", "lottery",
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "cutt.ly", "rb.gy", "shorturl.at", "rebrand.ly",
}


@dataclass
class Signal:
    name: str
    weight: int          # contribution to risk score
    reason: str          # human-readable explanation


@dataclass
class TriageResult:
    url: str
    host: str
    score: int = 0
    band: str = "LOW"
    signals: list = field(default_factory=list)
    claimed_brand: str | None = None

    def as_dict(self):
        d = asdict(self)
        d["signals"] = [asdict(s) for s in self.signals]
        return d


def _registrable(host: str) -> str:
    """Rough registrable domain (last two labels). Good enough for triage."""
    parts = host.split(".")
    if len(parts) >= 3 and parts[-2] in {"co", "gov", "org", "net", "ac", "nic"}:
        return ".".join(parts[-3:])          # e.g. irctc.co.in, parivahan.gov.in
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def triage(url: str) -> TriageResult:
    """Score a URL from its string + structure alone. Higher = more suspicious."""
    if "://" not in url:
        url = "http://" + url
    p = urlparse(url)
    host = (p.hostname or "").lower()
    tld = host.rsplit(".", 1)[-1] if "." in host else ""
    reg = _registrable(host)
    full = url.lower()

    res = TriageResult(url=url, host=host)

    # 1. Brand name present but NOT on the official domain -> impersonation
    for brand, official in OFFICIAL_BRANDS.items():
        if brand in host and not host.endswith(official):
            res.claimed_brand = brand
            res.signals.append(Signal(
                "brand_mismatch", 45,
                f"Mentions '{brand}' but domain is '{host}', not the official '{official}'."))
            break

    # 2. Typo-squatting: registrable domain very close to a real one
    for brand, official in OFFICIAL_BRANDS.items():
        base = official.split(".")[0]
        sim = difflib.SequenceMatcher(None, reg.split(".")[0], base).ratio()
        if base and reg.split(".")[0] != base and sim >= 0.8:
            res.signals.append(Signal(
                "typosquat", 30,
                f"Domain '{reg}' is a near look-alike of '{official}' (similarity {sim:.0%})."))
            break

    # 3. Suspicious / cheap TLD
    if tld in SUSPICIOUS_TLDS:
        res.signals.append(Signal(
            "suspicious_tld", 20, f"Uses a cheap, scam-prone TLD '.{tld}'."))

    # 4. Government service not on a .gov.in / .nic.in domain
    govish = any(k in full for k in ("challan", "parivahan", "incometax", "epfo", "uidai", "aadhaar"))
    if govish and not (host.endswith(".gov.in") or host.endswith(".nic.in")):
        res.signals.append(Signal(
            "fake_gov", 30,
            "Claims a government service but is not on a .gov.in / .nic.in domain."))

    # 5. Scam keywords in host or path
    found = sorted({w for w in SCAM_KEYWORDS if re.search(rf"\b{w}\b", full)})
    if found:
        res.signals.append(Signal(
            "scam_keywords", min(5 * len(found), 20),
            f"Contains scam-associated words: {', '.join(found)}."))

    # 6. URL shortener hides the real destination
    if host in URL_SHORTENERS:
        res.signals.append(Signal(
            "shortener", 15, f"URL shortener '{host}' hides the real destination."))

    # 7. Structural oddities
    if re.search(r"https?://\d{1,3}(\.\d{1,3}){3}", url):
        res.signals.append(Signal("ip_host", 20, "Uses a raw IP address instead of a domain name."))
    if host.count(".") >= 4:
        res.signals.append(Signal("deep_subdomain", 10, "Unusually deep subdomain nesting."))
    if re.search(r"xn--", host):
        res.signals.append(Signal("punycode", 20, "Punycode domain — may hide look-alike characters."))
    if p.scheme == "http":
        res.signals.append(Signal("no_https", 5, "No HTTPS."))

    # --- aggregate ---
    res.score = min(sum(s.weight for s in res.signals), 100)
    res.band = "HIGH" if res.score >= 55 else "SUSPICIOUS" if res.score >= 25 else "LOW"
    return res


if __name__ == "__main__":
    tests = [
        "https://echallan.parivahan.gov.in/",            # legit
        "https://parivahan-echallan-pay.xyz/challan",     # fake gov + bad TLD + keywords
        "http://sbi-kyc-update.online/verify",            # brand mismatch + tld + keywords
        "https://bit.ly/3xk9",                            # shortener
        "https://incometax.gov.in/",                      # legit
        "http://192.168.10.5/pay-fine",                   # raw IP
    ]
    for t in tests:
        r = triage(t)
        print(f"\n[{r.band}]  score={r.score}  {t}")
        for s in r.signals:
            print(f"    +{s.weight:<3} {s.name}: {s.reason}")
