# Phishing triage: `Action required: your account has been limited`

## Summary

Strongest flag: strong. Flagged: 4 strong, 1 medium. Inconclusive: 1. Passed: 5. Indicators: 11.

- From: `"PayPal Security" <security[@]paypa1[.]com>`
- Sender: (none)
- To: `"Jordan Lee" <jordan[.]lee[@]example[.]net>`
- Reply-To: `case-review[@]account-resolution[.]example`
- Return-Path: `bounce[@]paypa1[.]com`
- Date: `Mon, 05 Oct 2026 16:14:18 +0000`
- Message-ID: `<20261005161418[.]4417[@]paypa1[.]com>`
- Origin: `203[.]0[.]113[.]45` (`mail[.]paypa1[.]com`) handed it to `mx[.]example[.]net`; lower hops claim `198[.]51[.]100[.]23` (could be forged)
- Links: 4. Attachments: 1
  - `Account_Statement[.]pdf` (`application/pdf`, 60 bytes), SHA-256 `043ea8960dc71f654cf0ac9ac501c16d09eed7b0e1528532fe25f122f1cc4f35`

## Signals

- **DMARC** (strong): `dmarc=fail for paypa1[.]com (from mx[.]example[.]net, ignored 1 untrusted header(s))`
- **Reply-To** (strong): `Replies go to account-resolution[.]example, not paypa1[.]com`
- **Lookalike domain** (strong): `paypa1[.]com [link, sender] spells 'paypal' with lookalike characters but isn't paypal[.]com`
- **Link text vs destination** (strong): `text shows www[.]paypal[.]com but goes to paypa1[.]com`
- **Display name** (medium): `"PayPal Security" mentions "paypal" but the mail is from paypa1[.]com`

## Inconclusive

- **DKIM** (medium): `dkim=none (from mx[.]example[.]net, ignored 1 untrusted header(s))`

## Passed

SPF; Script, file or app link; Return-Path domain; Free webmail sender; Brand joined to a word

## Indicators

| Type | Indicator, defanged |
|---|---|
| URL | `hxxp://paypa1[.]com/login/verify?case=88213` |
| URL | `hxxps://bit[.]ly/3pPx9Qz` |
| URL | `hxxp://203[.]0[.]113[.]45/t[.]gif?u=jordan[.]lee` |
| Domain | `paypa1[.]com` |
| Domain | `account-resolution[.]example` |
| Domain | `bit[.]ly` |
| IP | `203[.]0[.]113[.]45` |
| Email | `security[@]paypa1[.]com` |
| Email | `case-review[@]account-resolution[.]example` |
| Email | `bounce[@]paypa1[.]com` |
| SHA-256 | `043ea8960dc71f654cf0ac9ac501c16d09eed7b0e1528532fe25f122f1cc4f35` |

## Typical follow-ups if confirmed malicious

Suggestions, not actions taken:

- Find other recipients of the same message (search by its Message-ID or sender)
  - Message-ID: `<20261005161418[.]4417[@]paypa1[.]com>`
  - From: `security[@]paypa1[.]com`
- Check whether anyone clicked a link (proxy or DNS logs for the indicator domains) or replied
- Block the attacker's own sender address and domains, not spoofed or shared ones like a webmail or link-shortening service

## Analyst decision

- Verdict:
- Actions taken:
