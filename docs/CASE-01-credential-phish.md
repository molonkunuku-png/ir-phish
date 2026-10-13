# Case 01 — Credential-harvest phish ("IT Support" account suspension)

- **Sample:** `samples/phish.eml`
- **Tool verdict:** `MALICIOUS 100` (`python3 IrPhish.py samples/phish.eml`)
- **MITRE ATT&CK:** `T1566.002` — Phishing: Spearphishing Link

## Headers (what I looked at first)

| Field | Value | Read |
|---|---|---|
| From | `IT Support <it-support@acme-corp.example>` | claims internal IT |
| Reply-To | `helpdesk-verify@acme-support-desk.example` | **different domain** — credential replies go to attacker |
| Return-Path | `bounce@acme-support-desk.example` | same foreign domain — envelope doesn't match From |
| Authentication-Results | `spf=fail; dkim=fail; dmarc=fail` | sender is not authorized for the claimed domain |

Triage rule from this: Reply-To/Return-Path on a domain that never appears
in From is the single fastest tell, before reading a word of body.

## Body + URLs

- Urgency pretext: "SUSPENDED within 24 hours", "verify now", "action required".
- Credential ask: "sign in to confirm your password".
- Two links: raw-IP host `http://192.0.2.44.verify-login.example/...` and
  shortener `http://bit.ly/3xAcmeVerify` — both hide the real landing page.

## Tool output (reasons)

```
- Reply-To mismatch / Return-Path mismatch
- SPF/DKIM/DMARC fail
- Urgency language: urgent, immediately, suspended, verify now
- Credential-harvest language: password, sign in, login
- URL shortener + raw IP host
```

## Detection rules generated

```bash
python3 IrPhish.py samples/phish.eml \
  --sigma export/case01.yml --spl export/case01.spl --kql export/case01.kql
```

Hunt `acme-support-desk.example`, both URLs, across proxy + mail logs for
30 days. Any other recipient who clicked is a containment target.

## Response (what I'd do as Tier 1)

1. Block sender domain + both URLs at proxy/mail gateway.
2. Search mail logs for all recipients of the same Message-ID/subject.
3. Force password reset for clickers; check for new inbox rules (persistence).
4. Close with MITRE `T1566.002` tag and link this write-up.

## Lesson

Auth-fail + Reply-To pivot + urgency + credential ask = four independent
signals. One can be a misconfiguration; four together is a phish.
