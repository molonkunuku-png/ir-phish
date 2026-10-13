# phish-triage

Lightweight phishing email triage CLI — stdlib only, no installs.
Built as SOC Tier 1 portfolio project #1.

## Quick start

```bash
python3 phish_triage.py selftest
python3 phish_triage.py samples/clean.eml
python3 phish_triage.py samples/phish.eml
python3 phish_triage.py suspicious.eml --json report.json --sigma hunt.yml --spl hunt.spl --kql hunt.kql
```

## What it checks

1. **Header mismatch** — Reply-To / Return-Path vs From (+25/+15)
2. **Authentication-Results** — SPF/DKIM/DMARC fail (+30), pass reduces score
3. **Lures** — urgency / financial / credential-harvest language
4. **URLs** — shorteners, raw-IP hosts, link count
5. **Attachments** — double extensions (`invoice.pdf.exe`)

Score 0–100 → `CLEAN` (<40) / `SUSPICIOUS` (40–69) / `MALICIOUS` (≥70),
with reasons listed for every point source.

## Tests

```bash
pytest tests/ -v
```

## Next steps

- Add `--sigma/--spl/--kql` export from sender domain + URLs (pattern already proven in ir-rose SigmaRose).
- Add BEC financial-fraud rules (invoice + wire + new beneficiary).
- Write up 2 cases (clean vs phish) mapped to MITRE `T1566.002` (Spearphishing Link).
