"""
Scam Honeypot — scanner (safe open + capture).

Opens a URL in a cloud/headless browser the way a genuine visitor would,
captures the evidence (screenshot, visible text, links, outbound requests),
and SEALS each artefact with a SHA-256 hash + UTC timestamp.

READ-ONLY by design: it loads and observes the page. It does not fill in
forms, submit anything, or follow a payment flow.

Two engines behind one interface:
  - TinyFishEngine  : the real submission engine (stealth cloud browser + India
                      proxy). Needs TINYFISH_API_KEY. See open_with_tinyfish().
  - PlaywrightEngine: local fallback so the demo runs without a key.

Select with env SCAN_ENGINE=tinyfish|playwright (default: playwright).
"""
from __future__ import annotations
from dataclasses import dataclass, field, asdict
import os, re, time, json, hashlib, datetime, base64


def _utc() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@dataclass
class Capture:
    url: str
    final_url: str = ""
    title: str = ""
    status: str = "captured"          # captured | error | blocked | timeout
    text: str = ""
    links: list = field(default_factory=list)
    requests: list = field(default_factory=list)     # outbound request URLs
    screenshot_path: str = ""
    screenshot_sha256: str = ""
    captured_at: str = ""
    engine: str = ""
    streaming_url: str = ""        # TinyFish live browser view (while the session runs)
    provenance: dict = field(default_factory=dict)

    def as_dict(self):
        return asdict(self)


# --------------------------------------------------------------------------- #
#  Playwright engine (local fallback; runs the demo without a TinyFish key)    #
# --------------------------------------------------------------------------- #
def open_with_playwright(url: str, out_dir: str, timeout_ms: int = 20000,
                         mobile: bool = True) -> Capture:
    from playwright.sync_api import sync_playwright

    cap = Capture(url=url, engine="playwright", captured_at=_utc())
    reqs: list[str] = []
    os.makedirs(out_dir, exist_ok=True)

    with sync_playwright() as p:
        browser = p.chromium.launch(args=["--no-sandbox"])
        # Present as a genuine Indian mobile visitor (what a scam page expects).
        ctx = browser.new_context(
            user_agent=("Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 "
                        "(KHTML, like Gecko) Chrome/120 Mobile Safari/537.36") if mobile else None,
            viewport={"width": 390, "height": 844} if mobile else {"width": 1280, "height": 800},
            locale="en-IN",
            is_mobile=mobile,
        )
        page = ctx.new_page()
        page.on("request", lambda r: reqs.append(r.url))   # listener BEFORE navigation
        try:
            resp = page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
            try:
                page.wait_for_load_state("networkidle", timeout=4000)
            except Exception:
                pass
            cap.final_url = page.url
            cap.title = page.title()
            cap.text = page.inner_text("body")[:20000]
            cap.links = sorted({a for a in page.eval_on_selector_all(
                "a[href]", "els => els.map(e => e.href)") if a})[:200]
            shot = os.path.join(out_dir, "screenshot.png")
            png = page.screenshot(full_page=True)
            with open(shot, "wb") as f:
                f.write(png)
            cap.screenshot_path = shot
            cap.screenshot_sha256 = _sha256(png)
            cap.requests = sorted(set(reqs))[:300]
            cap.status = "captured"
            cap.provenance = {
                "http_status": resp.status if resp else None,
                "engine": "playwright-chromium",
                "vantage": "local (demo) — swap to TinyFish India proxy for real runs",
            }
        except Exception as e:
            cap.status = "error"
            cap.provenance = {"error": str(e)[:300]}
        finally:
            ctx.close()
            browser.close()
    return cap


# --------------------------------------------------------------------------- #
#  TinyFish engine (real submission). Needs TINYFISH_API_KEY.                  #
#  Mandatory integration for Kritical Hacks. Kept behind one function so the   #
#  rest of the pipeline is identical whichever engine runs.                    #
# --------------------------------------------------------------------------- #
def open_with_tinyfish(url: str, out_dir: str, country: str = "IN",
                       timeout_ms: int = 20000) -> Capture:
    """
    Opens the URL in a TinyFish STEALTH cloud browser routed through an Indian
    exit, then drives it with Playwright over the returned CDP URL to capture
    exactly what a real Indian mobile victim would see (defeating cloaking).

    Requires:  pip install tinyfish playwright   +   env TINYFISH_API_KEY
    """
    from tinyfish import TinyFish
    from playwright.sync_api import sync_playwright

    cap = Capture(url=url, engine="tinyfish", captured_at=_utc())
    reqs: list[str] = []
    os.makedirs(out_dir, exist_ok=True)

    client = TinyFish()  # reads TINYFISH_API_KEY from env
    session = client.browser.sessions.create(
        #url="about:blank",
        proxy_config={"type": "tinyfish", "country_code": country},  # India exit
        # browser_profile stealth is applied server-side; confirm field names
        # against the TinyFish SDK version you install.
    )
    # live browser view — show this on screen in the demo to prove TinyFish is driving
    cap.streaming_url = getattr(session, "streaming_url", "") or getattr(session, "live_url", "")
    try:
        with sync_playwright() as p:
            browser = p.chromium.connect_over_cdp(session.cdp_url)
            page = browser.contexts[0].pages[0] if browser.contexts and browser.contexts[0].pages \
                else browser.contexts[0].new_page()
            page.on("request", lambda r: reqs.append(r.url))   # attach BEFORE navigating
            resp = page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
            try:
                page.wait_for_load_state("networkidle", timeout=4000)
            except Exception:
                pass
            cap.final_url = page.url
            cap.title = page.title()
            cap.text = page.inner_text("body")[:20000]
            cap.links = sorted({a for a in page.eval_on_selector_all(
                "a[href]", "els => els.map(e => e.href)") if a})[:200]
            png = page.screenshot(full_page=True)
            shot = os.path.join(out_dir, "screenshot.png")
            with open(shot, "wb") as f:
                f.write(png)
            cap.screenshot_path = shot
            cap.screenshot_sha256 = _sha256(png)
            cap.requests = sorted(set(reqs))[:300]
            cap.status = "captured"
            cap.provenance = {
                "http_status": resp.status if resp else None,
                "engine": "tinyfish-stealth",
                "session_id": getattr(session, "session_id", None),
                "streaming_url": cap.streaming_url,
                "vantage": f"TinyFish proxy exit = {country}",
            }
            browser.close()
    except Exception as e:
        cap.status = "error"
        cap.provenance = {"error": str(e)[:300], "engine": "tinyfish"}
    return cap


def scan(url: str, out_dir: str) -> Capture:
    engine = os.environ.get("SCAN_ENGINE", "playwright").lower()
    if engine == "tinyfish":
        return open_with_tinyfish(url, out_dir)
    return open_with_playwright(url, out_dir)


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "https://example.com"
    cap = scan(target, out_dir="evidence/_cli")
    d = cap.as_dict()
    d.pop("text", None)  # keep CLI output short
    print(json.dumps(d, indent=2)[:1500])
    print("\ntext preview:", cap.text[:300].replace("\n", " "))
