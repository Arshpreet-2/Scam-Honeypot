"""End-to-end demo: triage a URL -> scan (capture+seal) -> assess -> verdict JSON."""
import sys, os, json
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "scanner"))
from triage import triage
from scan import scan
from extract import assess

def investigate(url: str, out_dir: str):
    t = triage(url)
    cap = scan(url, out_dir=out_dir)
    v = assess(t, cap)
    report = {
        "verdict": v.as_dict(),
        "evidence": {
            "final_url": cap.final_url, "title": cap.title, "status": cap.status,
            "screenshot": cap.screenshot_path, "screenshot_sha256": cap.screenshot_sha256,
            "captured_at": cap.captured_at, "engine": cap.engine,
            "provenance": cap.provenance,
        },
    }
    with open(os.path.join(out_dir, "report.json"), "w") as f:
        json.dump(report, f, indent=2)
    return report

if __name__ == "__main__":
    url = sys.argv[1] if len(sys.argv) > 1 else \
        "file://" + os.path.abspath("fixtures/test_fixture.html")
    rep = investigate(url, out_dir="evidence/demo")
    v = rep["verdict"]
    print(f"\n=== VERDICT: [{v['band']}]  score={v['score']}  ===")
    print(f"URL: {v['url']}")
    print(f"Claimed brand: {v['claimed_brand']}   Served from: {v['actual_host']}")
    print("\nExtracted identifiers:")
    for k, vals in v["identifiers"].items():
        if vals: print(f"   {k}: {vals}")
    print("\nWhy flagged:")
    for r in v["reasons"]:
        print(f"   - {r}")
    print(f"\nEvidence sealed: {rep['evidence']['screenshot_sha256'][:16]}…  "
          f"at {rep['evidence']['captured_at']}")
