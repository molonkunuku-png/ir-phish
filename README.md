# ir-phish

![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Tests](https://github.com/molonkunuku-png/ir-phish/actions/workflows/test.yml/badge.svg)

Lightweight phishing email triage CLI — **stdlib only, no installs**.
Paste in a suspicious email, get a verdict with reasons plus ready-to-hunt
Sigma/SPL/KQL rules. Built as a SOC Tier 1 portfolio project.

## Quick start

```bash
python3 IrPhish.py selftest
python3 IrPhish.py samples/phish.eml
python3 IrPhish.py suspicious.eml --json report.json --sigma hunt.yml --spl hunt.spl --kql hunt.kql
```

Sample output (`samples/phish.eml` → `MALICIOUS 100`):

```
Score:   100  ->  MALICIOUS
Reasons:
  - Reply-To mismatch: 'helpdesk-verify@acme-support-desk.example' vs From 'IT Support <...>'
  - SPF/DKIM/DMARC fail in Authentication-Results
  - Credential-harvest language: password, sign in, login
  - URL shortener: http://bit.ly/3xAcmeVerify
  - URL uses raw IP host
```

## What it checks

1. **Header mismatch** — Reply-To / Return-Path vs From (+25/+15)
2. **Authentication-Results** — SPF/DKIM/DMARC fail (+30), pass reduces score
3. **Lures** — urgency / financial / credential-harvest language
4. **URLs** — shorteners, raw-IP hosts, link count
5. **Attachments** — double extensions (`invoice.pdf.exe`)
6. **BEC** — executive impersonation, From→Reply-To domain pivot, payment-detail-change language

Score 0–100 → `CLEAN` (<40) / `SUSPICIOUS` (40–69) / `MALICIOUS` (≥70),
with reasons listed for every point source.

## Layout

```
ir-phish/
├── IrPhish.py        # the whole tool (parse → score → report → export)
├── samples/          # synthetic .eml fixtures (clean / credential-phish / BEC)
├── tests/            # pytest: scoring separation + rule content
├── docs/             # case write-ups mapped to MITRE T1566.002
└── .github/workflows/test.yml  # CI: pytest + selftest on every push
```

## Tests

```bash
pytest tests/ -v
```

## Case write-ups (MITRE `T1566.002` — Spearphishing Link)

- `docs/CASE-01-credential-phish.md` — urgency + credential harvest, hard auth-fail.
- `docs/CASE-02-bec-wire.md` — CFO impersonation + payment-detail change, no link needed.

## Requirements

- Python 3.8+, nothing else. Test runner: `pip install pytest`.

## License

MIT — see `LICENSE`. Authorized-use only: analyze mail you own or are permitted to handle.
