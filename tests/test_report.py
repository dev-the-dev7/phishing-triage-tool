"""Tests for triage/report.py: how the evidence is sorted, summed up and written out."""

import json

from triage.models import Address, Attachment, Check, Indicators, LookupStatus, Origin, ParsedEmail, Reputation
from triage.report import build_report, build_text_report, render_json, render_markdown, render_summary, render_text


def report_of(checks=(), found=None, results=None, warnings=(), origin=None, **fields):
    parsed = ParsedEmail(**{"from_addr": Address("", "a@example.org", "example.org"), "subject": "s", **fields})
    return build_report(parsed, origin, list(checks), found or Indicators(), results or {}, list(warnings))


def section(text: str, heading: str) -> list[str]:
    lines = text.splitlines() + [""]
    start = lines.index(heading) + 1
    return lines[start:lines.index("", start)]


def test_flags_go_first_strongest_first_then_inconclusive_then_passes():
    checks = [Check("A", "pass", "strong", ""), Check("B", "flag", "weak", ""),
              Check("C", "inconclusive", "strong", ""), Check("D", "flag", "strong", ""),
              Check("E", "flag", "weak", ""), Check("F", "flag", "medium", "")]
    report = report_of(checks)
    # Checks with the same result and strength keep the order they ran in
    assert [check.name for check in report.findings] == ["D", "F", "B", "E", "C", "A"]
    assert section(render_text(report), "Summary") == [
        "  Strongest flag: strong",
        "  Flagged: 1 strong, 1 medium, 2 weak   Inconclusive: 1   Passed: 1   Indicators: 0",
    ]


def test_nothing_flagged():
    text = render_text(report_of([Check("A", "pass", "strong", "")], warnings=["w"]))
    assert section(text, "Summary") == [
        "  Strongest flag: none",
        "  Flagged: none   Inconclusive: 0   Passed: 1   Indicators: 0   Warnings: 1",
    ]
    assert section(text, "Warnings about the tool's reading") == ["  w"]


def test_email_lines_leave_out_what_isnt_there():
    assert section(render_text(report_of()), "Email") == [
        "  From:        a@example.org",
        "  Origin:      unknown, no Received headers with an IP",
        "  Links: 0   Attachments: 0",
    ]


def test_text_from_the_email_cant_add_lines_or_hide_characters():
    # A newline in an encoded Subject could print a fake PASS line under it. Viewers and
    # JavaScript break lines at a line separator too.
    report = report_of(subject="Invoice\n  PASS         strong  DMARC: ok\N{LINE SEPARATOR}",
                       warnings=["name\N{RIGHT-TO-LEFT OVERRIDE}fdp.exe"])
    text = render_text(report)
    assert text.splitlines()[0] == r"Phishing triage: Invoice\n  PASS         strong  DMARC: ok\u2028"
    assert "name\\u202efdp.exe" in text


def test_long_text_is_cut_in_the_middle():
    text = render_text(report_of(subject="a" + "x" * 998 + "z"))
    assert text.splitlines()[0] == ("Phishing triage: a" + "x" * 149 + " ... (700 characters left out) ... "
                                    + "x" * 149 + "z")


def test_a_padded_name_cant_hide_the_address():
    # Spaces after a display name push the address out of sight in some mail clients, and a
    # quote in it can make another address look like the sender's
    sender = Address('PayPal" <service@paypal.com>' + " " * 400, "attacker@evil.com", "evil.com")
    to = [Address("", f"user{n}@example.net", "example.net") for n in range(7)]
    email = section(render_text(report_of(from_addr=sender, to=to)), "Email")
    assert email[0].startswith(r'  From:        "PayPal\" <service@paypal.com>   ')
    assert email[0].endswith('" <attacker@evil.com>')
    assert email[1] == ("  To:          user0@example.net; user1@example.net; user2@example.net; user3@example.net; "
                        "user4@example.net (and 2 more)")


def test_cutting_a_name_keeps_its_quotes_escaped():
    # The quote lands right after the cut, where the backslash in front of it could be lost
    sender = Address("A" * 200 + '" <service@paypal.com>' + " " * 128, "attacker@evil.com", "evil.com")
    from_line = section(render_text(report_of(from_addr=sender)), "Email")[0]
    assert r'(50 characters left out) ... \" <service@paypal.com>' in from_line


def test_origin_shows_its_network_when_looked_up():
    origin = Origin("8.8.8.8", "dns.google", "mx.example.net")
    found = Indicators(ips=["8.8.8.8"])
    looked_up = {"8.8.8.8": [Reputation("AbuseIPDB", LookupStatus.FOUND, "", {"isp": "Google LLC", "country": "US"})]}
    assert ("  Origin:      8.8.8.8 (dns.google) handed it to mx.example.net, Google LLC in US"
            in render_text(report_of(origin=origin, found=found, results=looked_up)))
    # Without a lookup, or when AbuseIPDB has no answer, just the hop
    no_answer = {"8.8.8.8": [Reputation("AbuseIPDB", LookupStatus.UNAVAILABLE, "unavailable, error 500")]}
    for results in ({}, no_answer):
        assert ("  Origin:      8.8.8.8 (dns.google) handed it to mx.example.net\n"
                in render_text(report_of(origin=origin, found=found, results=results)))


def test_lookups_missed_for_the_whole_run_are_said_once():
    found = Indicators(domains=["a.com", "b.com", "c.com"])
    over = Reputation("VirusTotal", LookupStatus.SKIPPED, "skipped, over the limit of 8 lookups a run",
                      for_the_run=True)
    no_key = Reputation("AbuseIPDB", LookupStatus.UNAVAILABLE, "unavailable, ABUSEIPDB_API_KEY isn't set",
                        for_the_run=True)
    clean = Reputation("VirusTotal", LookupStatus.FOUND, "0 of 90 engines flagged it malicious")
    looked_up = {"a.com": [clean], "b.com": [over], "c.com": [over, no_key]}
    assert section(render_text(build_text_report(found, looked_up)), "Indicators, defanged") == [
        "  Domain   a[.]com",
        "           VirusTotal: 0 of 90 engines flagged it malicious",
        "  Domain   b[.]com",
        "  Domain   c[.]com",
        "  VirusTotal: skipped, over the limit of 8 lookups a run (2 indicators, the ones with no VirusTotal result)",
        "  AbuseIPDB: unavailable, ABUSEIPDB_API_KEY isn't set (1 indicator, the one with no AbuseIPDB result)",
    ]


def test_ips_a_flag_names_are_indicators():
    # Only a flag's, and only once
    checks = [Check("Faked Microsoft hop", "flag", "strong", "", ips=["1.1.1.1", "8.8.8.8"]),
              Check("Other", "pass", "strong", "", ips=["9.9.9.9"])]
    report = report_of(checks, found=Indicators(ips=["8.8.8.8"]))
    assert [(row.value, row.named_by) for row in report.indicators] == [("8.8.8.8", ""),
                                                                       ("1.1.1.1", "Faked Microsoft hop")]


def note_section(note: str, heading: str) -> list[str]:
    # The lines under a Markdown heading, up to the next one, without the blank ones
    lines = note.splitlines()
    start = lines.index(heading) + 1
    end = next((n for n in range(start, len(lines)) if lines[n].startswith("#")), len(lines))
    return [line for line in lines[start:end] if line]


CHECKS = [Check("DMARC", "flag", "strong", "dmarc=fail for paypa1.com", caveats=["c"]),
          Check("DKIM", "inconclusive", "medium", "dkim=none"),
          Check("SPF", "pass", "medium", "spf=pass"), Check("Script, file or app link", "pass", "medium", "ok")]


def test_the_note_follows_the_guide():
    report = report_of(CHECKS, found=Indicators(domains=["paypa1.com"]), message_id="<1@paypa1.com>",
                       from_addr=Address("", "a@paypa1.com", "paypa1.com"), warnings=["w"],
                       attachments=[Attachment("a.pdf", "application/pdf", 5, "f" * 64)])
    note = render_markdown(report)
    assert [line for line in note.splitlines() if line.startswith("#")] == [
        "# Phishing triage: `s`", "## Summary", "## Signals", "## Inconclusive", "## Passed", "## Indicators",
        "## Warnings about the tool's reading", "## Typical follow-ups if confirmed malicious", "## Analyst decision"]
    assert note_section(note, "## Summary") == [
        "Strongest flag: strong. Flagged: 1 strong. Inconclusive: 1. Passed: 2. Indicators: 1. Warnings: 1.",
        "- From: `a[@]paypa1[.]com`",
        "- Message-ID: `<1[@]paypa1[.]com>`",
        "- Origin: unknown, no Received headers with an IP",
        "- Links: 0. Attachments: 1",
        "  - `a[.]pdf` (`application/pdf`, 5 bytes), SHA-256 `" + "f" * 64 + "`",
    ]
    assert note_section(note, "## Signals") == ["- **DMARC** (strong): `dmarc=fail for paypa1[.]com`",
                                                "  - Caveat: `c`"]
    assert note_section(note, "## Inconclusive") == ["- **DKIM** (medium): `dkim=none`"]
    assert note_section(note, "## Passed") == ["SPF; Script, file or app link"]
    assert note_section(note, "## Typical follow-ups if confirmed malicious")[2:4] == [
        "  - Message-ID: `<1[@]paypa1[.]com>`", "  - Sender: `a[@]paypa1[.]com`"]
    assert note_section(note, "## Analyst decision") == ["- Verdict:", "- Actions taken:"]


def test_a_note_with_nothing_flagged_or_no_sender():
    note = render_markdown(report_of([Check("SPF", "pass", "medium", "spf=pass")], from_addr=None))
    assert note_section(note, "## Signals") == ["None."]
    assert note_section(note, "## Inconclusive") == ["None."]
    assert note_section(note, "## Summary")[1] == "- From: (missing)"
    assert [line for line in note_section(note, "## Typical follow-ups if confirmed malicious")
            if line.startswith("  -")] == []


def test_a_missing_subject_or_file_name_isnt_shown_as_the_emails_text():
    report = report_of(subject="", attachments=[Attachment("", "application/pdf", 5, "f" * 64)])
    text, note = render_text(report), render_markdown(report)
    assert text.splitlines()[0] == "Phishing triage: (no subject)"
    assert section(text, "Email")[-1] == "    " + "f" * 64 + "  (no name) (application/pdf, 5 bytes)"
    assert note.splitlines()[0] == "# Phishing triage: (no subject)"
    assert note_section(note, "## Summary")[-1] == ("  - (no name) (`application/pdf`, 5 bytes), SHA-256 `"
                                                    + "f" * 64 + "`")


def test_text_in_the_note_cant_make_links_or_formatting():
    note = render_markdown(report_of(subject="[x](http://evil.com) `y", message_id="`1@evil.com`"))
    assert "http://" not in note and "@evil" not in note
    assert note.splitlines()[0] == "# Phishing triage: ``[x](hxxp://evil[.]com) `y``"
    assert "- Message-ID: `` `1[@]evil[.]com` ``" in note_section(note, "## Summary")


def test_the_indicators_table():
    found = Indicators(urls=["https://evil.com/p|q"], domains=["evil.com", "a.com"])
    vt = Reputation("VirusTotal", LookupStatus.FOUND, "9 of 90 engines flagged it malicious")
    over = Reputation("VirusTotal", LookupStatus.SKIPPED, "skipped, over the limit of 8 lookups a run",
                      for_the_run=True)
    assert note_section(render_markdown(build_text_report(found, {})), "## Indicators") == [
        "| Type | Indicator, defanged |", "|---|---|",
        "| URL | `hxxps://evil[.]com/p\\|q` |", "| Domain | `evil[.]com` |", "| Domain | `a[.]com` |"]
    note = render_markdown(build_text_report(found, {"evil.com": [vt], "a.com": [over]}))
    assert note_section(note, "## Indicators") == [
        "| Type | Indicator, defanged | Reputation |", "|---|---|---|",
        "| URL | `hxxps://evil[.]com/p\\|q` |  |",
        "| Domain | `evil[.]com` | VirusTotal: `9 of 90 engines flagged it malicious` |",
        "| Domain | `a[.]com` |  |",
        "- Not looked up: VirusTotal: skipped, over the limit of 8 lookups a run (1 indicator, the one with no "
        "VirusTotal result)"]


def test_a_note_for_alert_text_has_no_email_sections():
    note = render_markdown(build_text_report(Indicators(domains=["evil.com"]), {}))
    assert [line for line in note.splitlines() if line.startswith("#")] == [
        "# Phishing triage: alert text", "## Indicators", "## Analyst decision"]


def test_the_json_holds_the_same_report():
    looked_up = {"paypa1.com": [Reputation("VirusTotal", LookupStatus.FOUND, "3 of 90", {"malicious": 3})]}
    report = report_of(CHECKS, found=Indicators(domains=["paypa1.com"]), results=looked_up,
                       subject="Hi\x1b\N{RIGHT-TO-LEFT OVERRIDE}", origin=Origin("8.8.8.8", "x", "mx.example.net"))
    text = render_json(report)
    assert text.isascii()
    data = json.loads(text)
    assert data["format"] == 1
    assert data["email"]["subject"] == "Hi\x1b\N{RIGHT-TO-LEFT OVERRIDE}"
    assert data["origin"] == {"ip": "8.8.8.8", "name": "x", "received_by": "mx.example.net", "earliest_claim": None,
                              "network": None}
    assert data["summary"] == {"strongest_flag": "strong", "flagged": {"strong": 1, "medium": 0, "weak": 0},
                               "inconclusive": 1, "passed": 2, "indicators": 1, "warnings": 0}
    assert data["checks"][0] == {"name": "DMARC", "result": "flag", "strength": "strong",
                                 "evidence": "dmarc=fail for paypa1.com", "caveats": ["c"]}
    assert data["indicators"] == [{"type": "Domain", "value": "paypa1.com", "defanged": "paypa1[.]com",
                                   "named_by": None, "lookups": [{"service": "VirusTotal", "status": "found",
                                                                  "text": "3 of 90", "facts": {"malicious": 3}}]}]
    assert data["analyst"] == {"verdict": None, "actions_taken": None}
    assert len(data["follow_ups"]) == 3


def test_json_for_alert_text():
    data = json.loads(render_json(build_text_report(Indicators(domains=["evil.com"]), {})))
    assert (data["email"], data["origin"], data["checks"], data["follow_ups"]) == (None, None, [], [])


def test_the_short_summary():
    over = Reputation("VirusTotal", LookupStatus.SKIPPED, "skipped, over the limit of 8 lookups a run",
                      for_the_run=True)
    report = report_of(CHECKS, found=Indicators(domains=["a.com"]), results={"a.com": [over]})
    assert render_summary(report, ["note.md", "report.json"]).splitlines() == [
        "Phishing triage: s",
        "Strongest flag: strong",
        "Flagged: 1 strong   Inconclusive: 1   Passed: 2   Indicators: 1",
        "VirusTotal: skipped, over the limit of 8 lookups a run (1 indicator, the one with no VirusTotal result)",
        "Wrote note.md and report.json",
    ]
    assert render_summary(build_text_report(Indicators(), {}), ["note.md"]).splitlines() == [
        "Phishing triage: alert text", "Indicators: 0", "Wrote note.md"]
