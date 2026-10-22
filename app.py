"""
Scam Honeypot — Streamlit dashboard.

Paste a suspicious link -> triage -> scan (TinyFish stealth / Playwright) ->
extract identifiers -> risk verdict + sealed evidence + JSON download.

Run:  streamlit run app.py
Engine: set env SCAN_ENGINE=tinyfish (+ TINYFISH_API_KEY) for the real run,
        default 'playwright' for local demo.
"""
import os, sys, json, datetime
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "scanner"))
import streamlit as st
from triage import triage
from scan import scan
from extract import assess

st.set_page_config(page_title="Scam Honeypot", page_icon="🛡️", layout="wide")

BANDS = {"HIGH": ("#D1495B", "⛔ HIGH RISK"),
         "SUSPICIOUS": ("#E08A00", "⚠ SUSPICIOUS"),
         "LOW": ("#12B886", "✓ LOW RISK")}

st.markdown("## 🛡️ Scam Honeypot")
st.caption("See the scam before it sees you — open a suspicious link safely, "
           "defeat cloaking, and expose the account hidden inside it.  *Powered by TinyFish.*")

engine = os.environ.get("SCAN_ENGINE", "playwright")
st.sidebar.markdown("### Settings")
st.sidebar.write(f"**Scan engine:** `{engine}`")
st.sidebar.caption("Set `SCAN_ENGINE=tinyfish` + `TINYFISH_API_KEY` for the "
                   "stealth India-exit run. Default `playwright` for local demo.")
st.sidebar.markdown("---")
st.sidebar.caption("Read-only: opens and observes public pages. "
                   "No form-filling, no payments, no credential use.")

url = st.text_input("Suspicious link or page URL",
                    placeholder="https://parivahan-echallan-pay.xyz/challan")
col_a, col_b = st.columns([1, 3])
go = col_a.button("Investigate", type="primary", use_container_width=True)
use_fixture = col_b.checkbox("Use built-in test fixture (no network)", value=False)

if use_fixture and not url:
    url = "file://" + os.path.abspath("fixtures/test_fixture.html")

if go and url:
    with st.spinner("Triaging URL…"):
        t = triage(url)
    with st.spinner(f"Opening the page safely ({engine})…"):
        out_dir = os.path.join("evidence", "ui_" +
                               datetime.datetime.now().strftime("%Y%m%d_%H%M%S"))
        cap = scan(url, out_dir=out_dir)
    v = assess(t, cap)

    color, label = BANDS.get(v.band, ("#888", v.band))
    st.markdown(
        f"<div style='background:{color};color:#fff;padding:14px 18px;border-radius:10px;"
        f"font-size:22px;font-weight:700'>{label} &nbsp; · &nbsp; score {v.score}/100</div>",
        unsafe_allow_html=True)

    left, right = st.columns([1.1, 1])
    with left:
        st.markdown("#### What we found")
        if v.claimed_brand:
            st.write(f"**Claims to be:** {v.claimed_brand}  →  **served from:** `{v.actual_host}`")
        ids = v.identifiers
        any_id = any(ids.values())
        if any_id:
            st.markdown("**Hidden identifiers exposed:**")
            for k, vals in ids.items():
                if vals:
                    st.write(f"- **{k.upper()}**: " + ", ".join(f"`{x}`" for x in vals))
        else:
            st.write("_No payment/contact identifiers found in visible content._")

        st.markdown("#### Why it's flagged")
        for r in v.reasons:
            st.write(f"- {r}")
        if not v.reasons:
            st.write("- No risk signals detected.")

    with right:
        st.markdown("#### Sealed evidence")
        if cap.screenshot_path and os.path.exists(cap.screenshot_path):
            st.image(cap.screenshot_path, caption="Captured page", use_container_width=True)
        st.write(f"**Status:** {cap.status}")
        st.write(f"**Captured:** {cap.captured_at}")
        st.code(f"SHA-256: {cap.screenshot_sha256 or '—'}", language="text")
        st.caption(f"Engine: {cap.engine} · {cap.provenance.get('vantage','')}")

    report = {"verdict": v.as_dict(),
              "evidence": {k: getattr(cap, k) for k in
                           ("final_url", "title", "status", "screenshot_sha256",
                            "captured_at", "engine", "provenance")}}
    st.download_button("⬇ Download evidence (JSON)",
                       data=json.dumps(report, indent=2),
                       file_name="scam_honeypot_report.json",
                       mime="application/json")

    with st.expander("Pre-filled 'Report Suspect' (cybercrime.gov.in) — review before sending"):
        first_upi = (ids.get("upi") or ["<identifier>"])[0]
        st.text_area("Draft", height=160, value=(
            f"Suspected cyber-fraud page.\n"
            f"URL: {cap.final_url or url}\n"
            f"Impersonates: {v.claimed_brand or 'unknown'}\n"
            f"Collecting payments to: {first_upi}\n"
            f"Other identifiers: {json.dumps({k:v2 for k,v2 in ids.items() if v2})}\n"
            f"Evidence hash (SHA-256): {cap.screenshot_sha256}\n"
            f"Captured (UTC): {cap.captured_at}\n"
            f"Risk score: {v.score}/100 ({v.band}).\n"
            f"[Assisted draft — a human reviews before this is filed.]"))
else:
    st.info("Enter a URL and click **Investigate**, or tick the test fixture to try it offline.")
