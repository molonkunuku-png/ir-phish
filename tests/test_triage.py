import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from phish_triage import report

BASE = Path(__file__).resolve().parents[1] / "samples"

def test_clean_scores_low():
    r = report(BASE / "clean.eml")
    assert r["verdict"] == "CLEAN", r
    assert r["score"] < 40, r

def test_phish_scores_high():
    r = report(BASE / "phish.eml")
    assert r["verdict"] in ("SUSPICIOUS", "MALICIOUS"), r
    assert r["score"] >= 40, r
    assert any("Reply-To" in x or "SPF" in x or "Credential" in x for x in r["reasons"]), r
