import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from phish_triage import report, detection_rules

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

def test_detection_rules_contain_iocs():
    r = report(BASE / "phish.eml")
    rules = detection_rules(r)
    assert "bit.ly" in rules["sigma"] + rules["spl"] + rules["kql"], rules
    assert rules["sender_domain"] not in ("", "unknown"), rules
    assert "condition" in rules["sigma"] and "stats count by" in rules["spl"]
