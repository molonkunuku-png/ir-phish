#!/usr/bin/env python3
"""
phish-triage — lightweight phishing email triage CLI (stdlib only).

Authorized use only: analyze emails you own / are authorized to handle.

Usage:
  python3 phish_triage.py message.eml
  python3 phish_triage.py message.eml --json report.json
  python3 phish_triage.py selftest
"""
import sys
import re
import json
from email import policy
from email.parser import BytesParser
from pathlib import Path

URL_RE = re.compile(r"https?://[^\s<>\"']+")
DOUBLE_EXT_RE = re.compile(r"\.\w+\.(exe|scr|js|vbs|bat|ps1|jar|hta|lnk|cpl|msi)\s*$", re.I)
URGENCY_WORDS = ["urgent", "immediately", "suspended", "verify now", "action required",
                 "limited time", "final notice", "account locked", "confirm now"]
FIN_WORDS = ["wire transfer", "invoice", "payment", "refund", "gift card", "bank",
             "beneficiary", "crypto", "bitcoin"]
CRED_WORDS = ["password", "sign in", "log in", "login", "verify your account",
              "update your account", "click here to verify"]


def parse_eml(path):
    msg = BytesParser(policy=policy.default).parsebytes(Path(path).read_bytes())
    body = ""
    attachments = []
    if msg.is_multipart():
        for part in msg.walk():
            disp = part.get_content_disposition()
            fname = part.get_filename()
            if disp == "attachment" or fname:
                attachments.append(fname or "(unnamed)")
            elif part.get_content_type().startswith("text/"):
                try:
                    body += part.get_content() + "\n"
                except Exception:
                    pass
    else:
        try:
            body = msg.get_content()
        except Exception:
            body = ""
    return {
        "from": str(msg.get("From", "")),
        "reply_to": str(msg.get("Reply-To", "")),
        "return_path": str(msg.get("Return-Path", "")),
        "subject": str(msg.get("Subject", "")),
        "date": str(msg.get("Date", "")),
        "auth_results": str(msg.get("Authentication-Results", "")),
        "received_count": len(msg.get_all("Received", [])),
        "body": body,
        "urls": URL_RE.findall(body + " " + str(msg.get("Subject", ""))),
        "attachments": attachments,
    }


def score(parsed):
    reasons = []
    pts = 0
    low = (parsed["from"] + " " + parsed["reply_to"] + " " + parsed["return_path"]
           + " " + parsed["subject"] + " " + parsed["body"]).lower()

    # 1. Reply-To / Return-Path mismatch (strong)
    if parsed["reply_to"] and parsed["reply_to"] not in parsed["from"]:
        pts += 25
        reasons.append(f"Reply-To mismatch: {parsed['reply_to']!r} vs From {parsed['from']!r}")
    if parsed["return_path"] and parsed["return_path"] not in parsed["from"]:
        pts += 15
        reasons.append(f"Return-Path mismatch: {parsed['return_path']!r}")

    # 2. Auth results
    auth = parsed["auth_results"].lower()
    if auth:
        if "spf=fail" in auth or "dkim=fail" in auth or "dmarc=fail" in auth:
            pts += 30
            reasons.append("SPF/DKIM/DMARC fail in Authentication-Results")
        elif "spf=pass" in auth and "dkim=pass" in auth:
            pts -= 10
            reasons.append("SPF+DKIM pass (reduces score)")

    # 3. Urgency / financial / credential lures
    urg = [w for w in URGENCY_WORDS if w in low]
    if urg:
        pts += min(20, 8 + 4 * len(urg))
        reasons.append(f"Urgency language: {', '.join(urg[:4])}")
    fin = [w for w in FIN_WORDS if w in low]
    if fin:
        pts += min(20, 8 + 4 * len(fin))
        reasons.append(f"Financial lure: {', '.join(fin[:4])}")
    cred = [w for w in CRED_WORDS if w in low]
    if cred:
        pts += min(20, 10 + 4 * len(cred))
        reasons.append(f"Credential-harvest language: {', '.join(cred[:3])}")

    # 4. URLs: shorteners, IP hosts, many links
    for u in parsed["urls"]:
        ul = u.lower()
        if any(s in ul for s in ["bit.ly", "tinyurl", "t.co/", "goo.gl", "is.gd"]):
            pts += 12
            reasons.append(f"URL shortener: {u[:60]}")
            break
    if re.search(r"https?://\d+\.\d+\.\d+\.\d+", low):
        pts += 15
        reasons.append("URL uses raw IP host")
    if len(parsed["urls"]) >= 5:
        pts += 8
        reasons.append(f"Many URLs ({len(parsed['urls'])})")

    # 5. Attachments: double extensions
    for a in parsed["attachments"]:
        if DOUBLE_EXT_RE.search(a or ""):
            pts += 25
            reasons.append(f"Double-extension attachment: {a}")
            break
    if parsed["attachments"]:
        reasons.append(f"Attachments: {', '.join(parsed['attachments'][:4])}")

    pts = max(0, min(100, pts))
    verdict = "MALICIOUS" if pts >= 70 else "SUSPICIOUS" if pts >= 40 else "CLEAN"
    return {"score": pts, "verdict": verdict, "reasons": reasons}


def report(path):
    parsed = parse_eml(path)
    s = score(parsed)
    return {"file": str(path), **{k: v for k, v in parsed.items() if k != "body"},
            "body_chars": len(parsed["body"]), **s}


def detection_rules(r):
    """Build Sigma/SPL/KQL hunts from sender + URLs. Ref: ir-rose SigmaRose pattern."""
    m = re.search(r"@([A-Za-z0-9.-]+\.[A-Za-z]{2,})", r.get("from", ""))
    sender_domain = m.group(1) if m else "unknown"
    urls = r.get("urls", [])[:5]
    level = "high" if r.get("verdict") == "MALICIOUS" else "medium"
    url_list = "\n".join(f"        - '*{u[:80]}*'" for u in urls) or "        - '*phish*'"
    sigma = (
        f"title: Phish triage hunt - {sender_domain}\n"
        f"status: test\n"
        f"description: Generated by phish-triage score {r.get('score')} ({r.get('verdict')})\n"
        f"logsource:\n  category: proxy\n  product: windows\n"
        f"detection:\n  selection_sender:\n    SenderDomain: '{sender_domain}'\n"
        f"  selection_urls:\n    Url:\n{url_list}\n"
        f"  condition: 1 of selection_*\nlevel: {level}\n"
    )
    url_or = " OR ".join(f'url="*{u[:60]}*"' for u in urls) or 'url="*phish*"'
    spl = (
        f"# SPL - phish hunt sender {sender_domain} score {r.get('score')}\n"
        f"index=* earliest=-30d\n| search sender_domain=\"{sender_domain}\" OR {url_or}\n"
        f"| stats count by host, sender_domain, url\n"
    )
    kql = (
        f"// KQL - phish hunt sender {sender_domain} score {r.get('score')}\n"
        f"DeviceNetworkEvents\n| where Timestamp > ago(30d)\n"
        f"| where RemoteUrl has \"{sender_domain}\"\n"
        + "".join(f"| where RemoteUrl has \"{u[:60]}\"\n" for u in urls[:3])
        + "| project Timestamp, DeviceName, RemoteUrl, InitiatingProcessFileName\n"
    )
    return {"sigma": sigma, "spl": spl, "kql": kql, "sender_domain": sender_domain}


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 2
    if argv[1] == "selftest":
        base = Path(__file__).parent / "samples"
        for f in sorted(base.glob("*.eml")):
            r = report(f)
            print(f"{r['verdict']:>10} {r['score']:>3}  {Path(f).name}")
            for reason in r["reasons"]:
                print(f"           - {reason}")
        return 0
    r = report(argv[1])
    print(f"File:    {r['file']}\nFrom:    {r['from']}\nReplyTo: {r['reply_to']}\n"
          f"Subject: {r['subject']}\nScore:   {r['score']}  ->  {r['verdict']}")
    print(f"URLs ({len(r['urls'])}):")
    for u in r["urls"][:10]:
        print(f"  - {u[:100]}")
    print("Reasons:")
    for reason in r["reasons"] or ["(none)"]:
        print(f"  - {reason}")
    if "--json" in argv:
        out = argv[argv.index("--json") + 1]
        Path(out).write_text(json.dumps(r, indent=2))
        print(f"Saved {out}")
    from datetime import datetime as _dt
    def _flag_path(flag, default_ext):
        if flag in argv:
            i = argv.index(flag)
            if i + 1 < len(argv) and not argv[i + 1].startswith("-"):
                return argv[i + 1]
            ts = _dt.now().strftime("%Y%m%d%H%M%S")
            return str(Path("export") / f"phish_{ts}.{default_ext}")
        return None
    rules = None
    for flag, ext, key in [("--sigma", "yml", "sigma"), ("--spl", "spl", "spl"), ("--kql", "kql", "kql")]:
        p = _flag_path(flag, ext)
        if p:
            if rules is None:
                rules = detection_rules(r)
            Path(p).parent.mkdir(parents=True, exist_ok=True)
            Path(p).write_text(rules[key])
            print(f"Saved {p} ({key}, sender {rules['sender_domain']})")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
