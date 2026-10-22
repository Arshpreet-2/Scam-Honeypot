"""
One-command TinyFish check — run this before the demo.

    pip install -U tinyfish playwright
    python -m playwright install chromium
    export TINYFISH_API_KEY=your_key
    python test_tinyfish.py

It proves four things for the judges / your own confidence:
  1. the API key works,
  2. a STEALTH cloud browser session is created (prints the live streaming URL),
  3. whether an India ("IN") exit is accepted,
  4. what exit country the page actually sees (opens a public IP-echo page).

Nothing here touches a scam site — it opens ipinfo.io to read back the exit IP.
"""
import os, json, sys

def check(country):
    from tinyfish import TinyFish
    from playwright.sync_api import sync_playwright
    client = TinyFish()  # reads TINYFISH_API_KEY
    print(f"\n--- creating TinyFish session (country_code={country}) ---")
    try:
        session = client.browser.sessions.create(
            proxy_config={"type": "tinyfish", "country_code": country},
        )
    except Exception as e:
        print(f"  session.create FAILED for {country}: {e}")
        return False
    print("  session_id :", getattr(session, "session_id", "?"))
    print("  cdp_url    :", getattr(session, "cdp_url", "?"))
    print("  LIVE VIEW  :", getattr(session, "streaming_url", "") or getattr(session, "live_url", "") or "(none exposed)")
    try:
        with sync_playwright() as p:
            browser = p.chromium.connect_over_cdp(session.cdp_url)
            page = (browser.contexts[0].pages[0] if browser.contexts and browser.contexts[0].pages
                    else browser.contexts[0].new_page())
            page.goto("https://ipinfo.io/json", wait_until="domcontentloaded", timeout=25000)
            body = page.inner_text("body")[:600]
            browser.close()
        try:
            info = json.loads(body)
            print(f"  EXIT seen by site: {info.get('country')}  ({info.get('city','?')}, IP {info.get('ip','?')})")
            ok = (country == info.get("country"))
            print("  -> India exit confirmed" if (country == "IN" and ok) else
                  f"  -> exit country is {info.get('country')} (requested {country})")
        except Exception:
            print("  page body:", body[:200])
        return True
    except Exception as e:
        print(f"  connect/open FAILED: {e}")
        return False

if __name__ == "__main__":
    if not os.environ.get("TINYFISH_API_KEY"):
        print("Set TINYFISH_API_KEY first:  export TINYFISH_API_KEY=your_key")
        sys.exit(1)
    print("TinyFish key detected. Testing...")
    in_ok = check("IN")          # try India first
    if not in_ok:
        print("\nIndia exit unavailable — trying US (still proves TinyFish works):")
        check("US")
    print("\nDone. If a session + live view printed, your TinyFish integration is working.")
    print("For the scanner, run:  SCAN_ENGINE=tinyfish TINYFISH_API_KEY=...  uvicorn api:app --port 8000")
