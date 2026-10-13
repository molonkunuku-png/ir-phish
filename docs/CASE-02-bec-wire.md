# Case 02 — BEC wire-fraud ("CFO" confidential vendor payment)

- **Sample:** `samples/bec.eml`
- **Tool verdict:** `MALICIOUS 100` (`python3 phish_triage.py samples/bec.eml`)
- **MITRE ATT&CK:** `T1566.002` — Phishing: Spearphishing Link (pretexting variant;
  no malicious link — the payload is a fraudulent payment instruction)

## Headers (what I looked at first)

| Field | Value | Read |
|---|---|---|
| From | `"Daniel Kofi Mensah", CFO <d.k.mensah@acme-corp.example>` | executive display name |
| Reply-To | `d.k.mensah.finance@acme-finance-desk.example` | **different domain** — replies leave the org |
| Return-Path | `bounce@acme-finance-desk.example` | same foreign domain |
| Authentication-Results | `spf=softfail; dkim=none; dmarc=none` | weak/no authentication — no proof of origin |

No URLs to click and no attachments — BEC doesn't need them. The tell is
entirely in headers + payment language.

## Body (BEC pattern checklist)

- [x] Executive impersonation (CFO display name)
- [x] Payment-detail change ("updated remittance", "new bank details", "new beneficiary")
- [x] Pressure + secrecy ("today", "ASAP", "keep confidential", "do not call")
- [x] Out-of-band reply path (Reply-To on external domain)

Tool output confirms all four: executive impersonation, BEC domain pivot
(`acme-corp.example` → `acme-finance-desk.example`), 6 payment-change
patterns, urgency+payment combo.

## Why this is different from Case 01

| | Case 01 (credential) | Case 02 (BEC) |
|---|---|---|
| Goal | steal password | move money |
| Link needed? | yes | no |
| Auth signal | hard fail | softfail/none (weaker — headers carry it) |
| Best hunt | URL + sender domain | sender domain + subject phrases |

## Response (what I'd do as Tier 1)

1. **Do not reply.** Verify via known phone number / internal channel — never the Reply-To.
2. Block `acme-finance-desk.example`; search mail for the same subject/display-name combo.
3. Alert finance: freeze any payment to the new IBAN; check for prior changed-detail mails (vendor compromise).
4. Tag `T1566.002`, note BEC pretext, link this write-up.

## Lesson

BEC inverts the usual triage: the body looks professional and link-free,
so analysts who only hunt URLs miss it. Headers (domain pivot) +
payment-change language are the detection surface — which is exactly what
the new `bec_check()` rules encode.
