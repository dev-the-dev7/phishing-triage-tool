"""Tests for the command line (triage/__main__.py), run on the synthetic fixtures and on
emails written to a temporary folder."""

import contextlib
import io
import json
import os
import re
import subprocess
import sys
from datetime import date, timedelta
from pathlib import Path
from unittest.mock import MagicMock

import pytest
import requests

import triage.__main__ as cli
from triage import enrich, impersonation
from triage.__main__ import main
from triage.models import LookupStatus, Reputation

FIXTURES = Path(__file__).parent / "fixtures"
# Ambiguous From, Google redirect, Hidden text, Image only and Text added by CSS are left out,
# since they're only listed when they find something
CHECK_NAMES = ["SPF", "DKIM", "DMARC", "Reply-To", "Return-Path domain", "Display name", "Free webmail sender",
               "Lookalike domain", "Brand joined to a word", "Link text vs destination", "Script, file or app link"]


def run(capsys, *args) -> tuple[int, str, str]:
    code = main([str(arg) for arg in args])
    out, err = capsys.readouterr()
    return code, out, err


def results(out: str) -> dict[str, str]:
    # "  FLAG         very strong Ambiguous From: ..." gives {"Ambiguous From": "FLAG"}
    return dict((name, result) for result, name in
                re.findall(r"^  (FLAG|PASS|INCONCLUSIVE) +(?:very )?\w+ +([^:]+):", out, re.M))


def section(out: str, heading: str) -> list[str]:
    # The lines under a heading, up to the blank line after them
    lines = out.splitlines() + [""]
    start = lines.index(heading) + 1
    return lines[start:lines.index("", start)]


def write_email(tmp_path, text: str) -> Path:
    path = tmp_path / "email.eml"
    path.write_bytes(text.encode())
    return path


def test_clean_email_passes_every_check(capsys):
    code, out, _ = run(capsys, FIXTURES / "clean.eml")
    assert code == 0
    assert "Origin:      192.0.2.10 (mail.example.com) handed it to mx.example.net\n" in out
    assert results(out) == dict.fromkeys(CHECK_NAMES, "PASS")


def test_suspicious_email(capsys):
    code, out, _ = run(capsys, FIXTURES / "suspicious.eml")
    assert code == 0
    assert out.splitlines()[0] == "Phishing triage: Action required: your account has been limited"
    assert section(out, "Summary") == [
        "  Strongest flag: strong",
        "  Flagged: 4 strong, 1 medium   Inconclusive: 1   Passed: 5   Indicators: 11",
    ]
    assert section(out, "Email") == [
        '  From:        "PayPal Security" <security@paypa1.com>',
        '  To:          "Jordan Lee" <jordan.lee@example.net>',
        "  Reply-To:    case-review@account-resolution.example",
        "  Return-Path: bounce@paypa1.com",
        "  Date:        Mon, 05 Oct 2026 16:14:18 +0000",
        "  Message-ID:  <20261005161418.4417@paypa1.com>",
        "  Origin:      203.0.113.45 (mail.paypa1.com) handed it to mx.example.net",
        "               lower hops claim 198.51.100.23 (could be forged)",
        # Two in the HTML, and the same two written out in the plain text part
        "  Links: 4   Attachments: 1",
        "    043ea8960dc71f654cf0ac9ac501c16d09eed7b0e1528532fe25f122f1cc4f35  "
        "Account_Statement.pdf (application/pdf, 60 bytes)",
    ]
    flagged = {name for name, result in results(out).items() if result == "FLAG"}
    assert flagged == {"DMARC", "Reply-To", "Display name", "Lookalike domain", "Link text vs destination"}
    # The tracking image is listed too, and www.paypal.com, which a link only shows, isn't
    assert section(out, "Indicators, defanged") == [
        "  URL      hxxp://paypa1[.]com/login/verify?case=88213",
        "  URL      hxxps://bit[.]ly/3pPx9Qz",
        "  URL      hxxp://203[.]0[.]113[.]45/t[.]gif?u=jordan[.]lee",
        "  Domain   paypa1[.]com",
        "  Domain   account-resolution[.]example",
        "  Domain   bit[.]ly",
        "  IP       203[.]0[.]113[.]45",
        "  Email    security[@]paypa1[.]com",
        "  Email    case-review[@]account-resolution[.]example",
        "  Email    bounce[@]paypa1[.]com",
        "  SHA-256  043ea8960dc71f654cf0ac9ac501c16d09eed7b0e1528532fe25f122f1cc4f35",
    ]


def test_ceo_fraud_needs_executives_filled_in(capsys, monkeypatch):
    # It passes SPF, DKIM and DMARC from a real Gmail account, so only the weak webmail flag
    # shows until the executive's name is listed
    _, out, _ = run(capsys, FIXTURES / "ceo_fraud.eml")
    assert {name for name, result in results(out).items() if result == "FLAG"} == {"Free webmail sender"}
    monkeypatch.setattr(impersonation, "EXECUTIVES", {"Sarah Chen"})
    _, out, _ = run(capsys, FIXTURES / "ceo_fraud.eml")
    assert results(out)["Display name"] == "FLAG"


def test_text_from_the_email_is_printed_escaped(capsys, tmp_path):
    # Terminal control codes could move the cursor and overwrite earlier lines, and a
    # right-to-left override shows invoice<RLO>fdp.exe as invoiceexe.pdf
    path = write_email(tmp_path, (
        "From: a@example.org\r\nTo: someone@example.net\r\n"
        "Subject: =?utf-8?q?Invoice=1B[1A=1B[2K_paid?=\r\n"
        'Content-Type: multipart/mixed; boundary="B"\r\n\r\n'
        "--B\r\nContent-Type: text/plain\r\n\r\nSee attached\r\n"
        "--B\r\nContent-Type: application/octet-stream\r\n"
        "Content-Disposition: attachment; filename*=utf-8''invoice%E2%80%AEfdp.exe\r\n\r\nx\r\n--B--"
    ))
    code, out, _ = run(capsys, path)
    assert code == 0
    assert "\x1b" not in out and "\N{RIGHT-TO-LEFT OVERRIDE}" not in out
    assert r"Phishing triage: Invoice\x1b[1A\x1b[2K paid" in out
    assert "invoice\\u202efdp.exe" in out


def test_caveats_are_printed_under_their_check(capsys, tmp_path):
    path = write_email(tmp_path, (
        "From: a@example.org\r\nTo: someone@example.net\r\nSubject: s\r\nContent-Type: text/html\r\n\r\n"
        '<a href="https://evil.com/">paypal<i> </i>.com</a><a href="https://evil.net/">paypal.com</a>'
    ))
    _, out, _ = run(capsys, path)
    lines = out.splitlines()
    flag = lines.index("  FLAG         strong      Link text vs destination: text shows paypal.com but goes to "
                       "evil.net")
    assert lines[flag + 1] == (" " * 27 + "Caveat: A tag sits in the middle of paypal.com in a link to evil.com, "
                               "where CSS could change what the reader sees. Check what the link looks like in a "
                               "mail client, without clicking it.")
    # The line after is the next check
    assert re.match(r"  (FLAG|INCONCLUSIVE|PASS) ", lines[flag + 2])


def test_a_from_that_reads_two_ways_is_flagged(capsys, tmp_path):
    path = write_email(tmp_path, "From: service@paypal.com\r\nFrom: x@evil.com\r\nSubject: s\r\n\r\nHello")
    _, out, _ = run(capsys, path)
    assert results(out)["Ambiguous From"] == "FLAG"


def test_warnings_are_printed_escaped(capsys, tmp_path):
    # Warnings can repeat text from the email. The Mailsploit attacks hid a null byte in an
    # encoded address, and some clients stopped reading there and showed only service@paypal.com.
    path = write_email(tmp_path, (
        "From: a@example.org\r\nTo: =?utf-8?q?service=40paypal=2Ecom=00?=@evil.com\r\n"
        "Subject: s\r\n\r\nHello"
    ))
    code, out, _ = run(capsys, path)
    assert code == 0
    assert "\x00" not in out
    assert r"Some mail clients decode it and show service@paypal.com\x00@evil.com" in out


@pytest.mark.parametrize("received, origin", [
    ("", "unknown, no Received headers with an IP"),
    # Gmail to Gmail
    ("Received: from mail-sor-f41.google.com (mail-sor-f41.google.com. [209.85.220.41]) "
     "by mx.google.com; Tue, 6 Oct 2026 10:00:00 +0000\r\n",
     "none outside google.com, every hop is inside the provider"),
], ids=["no Received headers", "every hop inside the provider"])
def test_origin_without_an_outside_server(capsys, tmp_path, received, origin):
    path = write_email(tmp_path, received + "From: a@gmail.com\r\nTo: someone@example.net\r\nSubject: s\r\n\r\nHello")
    _, out, _ = run(capsys, path)
    assert f"Origin:      {origin}\n" in out


def test_email_without_a_from_is_still_checked(capsys, tmp_path):
    code, out, _ = run(capsys, write_email(tmp_path, "To: someone@example.net\r\nSubject: s\r\n\r\nHello"))
    assert code == 0
    assert "From:        (missing)\n" in out
    assert sorted(results(out)) == sorted(CHECK_NAMES)


def test_output_that_cant_be_reconfigured():
    # A script calling main() can send its output to a StringIO, which has no encoding to change
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        assert main([str(FIXTURES / "clean.eml")]) == 0
    assert sorted(results(output.getvalue())) == sorted(CHECK_NAMES)


def run_module(*args, **kwargs) -> subprocess.CompletedProcess:
    # python -m triage as its own process, the way it's run from a terminal
    return subprocess.run([sys.executable, "-m", "triage", *(str(arg) for arg in args)],
                          cwd=Path(__file__).parent.parent, capture_output=True, **kwargs)


@pytest.mark.parametrize("name, code", [("clean.eml", 0), ("missing.eml", 1)])
def test_exit_code_from_python_m_triage(name, code):
    # The command the README gives, run for real. Scripts read the exit code to tell
    # finished triage from an error.
    assert run_module(FIXTURES / name).returncode == code


def test_output_in_an_encoding_without_emoji(tmp_path):
    # Windows uses an old encoding when output is redirected to a file. PYTHONIOENCODING sets
    # one on any system, and printing the emoji in it would crash without the switch to UTF-8.
    path = write_email(tmp_path, "From: a@example.org\r\nTo: someone@example.net\r\n"
                                 "Subject: =?utf-8?q?Prize_=F0=9F=8E=81?=\r\n\r\nHello")
    process = run_module(path, env={**os.environ, "PYTHONIOENCODING": "ascii"})
    assert process.returncode == 0
    assert "Phishing triage: Prize \N{WRAPPED PRESENT}" in process.stdout.decode("utf-8")


def test_the_note_and_json_are_written(capsys, tmp_path):
    note, report = tmp_path / "note.md", tmp_path / "report.json"
    note.write_text("an older note")
    code, out, _ = run(capsys, FIXTURES / "suspicious.eml", "--out", note, "--json", report)
    assert code == 0
    assert out.splitlines()[1:] == ["Strongest flag: strong",
                                    "Flagged: 4 strong, 1 medium   Inconclusive: 1   Passed: 5   Indicators: 11",
                                    f"Wrote {note} and {report}"]
    assert note.read_bytes().startswith(b"# Phishing triage: ")
    assert json.loads(report.read_bytes())["format"] == 2
    # \n endings on Windows too, and no .new file left behind
    assert b"\r\n" not in note.read_bytes() + report.read_bytes()
    assert sorted(path.name for path in tmp_path.iterdir()) == ["note.md", "report.json"]


def test_alert_text_can_be_written_to_a_note(capsys, tmp_path, monkeypatch):
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(ALERT.encode())))
    code, _, _ = run(capsys, "--text", "-", "--out", tmp_path / "note.md")
    assert code == 0
    assert "| Domain | `evil[.]com` |" in (tmp_path / "note.md").read_text()


@pytest.mark.parametrize("args, error", [
    (["--out", ""], "error: --out needs a file name\n"),
    (["--out", "."], "error: --out names a folder\n"),
    (["--json", FIXTURES / "clean.eml"], "error: --json names the file being read\n"),
    (["--out", "same.md", "--json", "./same.md"], "error: --out and --json name the same file\n"),
    (["--out", "-", "--json", "-"], "error: only one of --out and --json can be - (standard output)\n"),
], ids=["empty", "folder", "the email", "same file", "both printed"])
def test_file_names_are_checked_before_the_work(capsys, args, error):
    code, out, err = run(capsys, FIXTURES / "clean.eml", *args)
    assert (code, out, err) == (1, "", error)


def test_alert_text_isnt_replaced_by_its_note(capsys, tmp_path):
    alert = write_text(tmp_path, ALERT.encode())
    assert run(capsys, "--text", alert, "--out", alert) == (1, "", "error: --out names the file being read\n")
    assert alert.read_bytes() == ALERT.encode()


@pytest.mark.skipif(os.path.normcase("A") != "a", reason="file names keep their case here")
def test_names_that_differ_in_case_are_the_same_file_on_windows(capsys):
    code, _, err = run(capsys, FIXTURES / "clean.eml", "--out", "Report.md", "--json", "report.md")
    assert (code, err) == (1, "error: --out and --json name the same file\n")


@pytest.mark.parametrize("flag", ["--out", "--json"])
def test_a_dash_prints_the_note_or_json_for_a_pipe(capsys, tmp_path, flag):
    code, out, err = run(capsys, FIXTURES / "suspicious.eml", flag, "-")
    assert code == 0
    assert out.startswith("# Phishing triage: ") if flag == "--out" else json.loads(out)["format"] == 2
    assert err.splitlines()[1] == "Strongest flag: strong"
    assert "Wrote" not in err


def test_a_pipe_closed_early_ends_quietly(tmp_path):
    # Like | head, which stops reading after the first line. The report has to be bigger than
    # the pipe holds, so the tool is still writing when it's closed.
    links = "".join(f'<a href="https://site{n}.example/">x</a>' for n in range(2_000))
    path = write_email(tmp_path, f"From: a@example.org\r\nSubject: s\r\nContent-Type: text/html\r\n\r\n{links}")
    process = subprocess.Popen([sys.executable, "-m", "triage", str(path), "--out", "-"],
                               cwd=Path(__file__).parent.parent, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    process.stdout.readline()
    process.stdout.close()
    assert process.stderr.read() == b""
    assert process.wait() == 1


def test_a_dash_and_a_file(capsys, tmp_path):
    code, out, err = run(capsys, FIXTURES / "suspicious.eml", "--out", "-", "--json", tmp_path / "report.json")
    assert code == 0
    assert out.startswith("# Phishing triage: ")
    assert err.splitlines()[-1] == f"Wrote {tmp_path / 'report.json'}"


def test_a_note_that_cant_be_written_still_shows_the_report(capsys, tmp_path):
    note, report = tmp_path / "note.md", tmp_path / "missing" / "report.json"
    code, out, err = run(capsys, FIXTURES / "clean.eml", "--out", note, "--json", report)
    assert code == 1
    assert err.startswith(f"error: couldn't write {report}: ")
    assert err.endswith(f" ({note} was written)\n")
    assert "\nFindings\n" in out


def test_a_write_that_fails_leaves_nothing_behind(tmp_path):
    # A folder can't be replaced by a file, so this fails after the new file was written
    (tmp_path / "note.md").mkdir()
    with pytest.raises(OSError):
        cli._write(tmp_path / "note.md", "text")
    assert [path.name for path in tmp_path.iterdir()] == ["note.md"]


def test_when_a_pipe_gets_the_note_the_full_report_goes_to_stderr(capsys, tmp_path):
    code, out, err = run(capsys, FIXTURES / "clean.eml", "--out", "-", "--json", tmp_path / "missing" / "report.json")
    assert code == 1
    assert out.startswith("# Phishing triage: ")
    assert "\nFindings\n" in err


def test_the_samples_are_up_to_date(capsys, tmp_path):
    # To make them again: python -m triage tests/fixtures/suspicious.eml --out samples/suspicious.md
    # --json samples/suspicious.json
    samples = Path(__file__).parent.parent / "samples"
    run(capsys, FIXTURES / "suspicious.eml", "--out", tmp_path / "note.md", "--json", tmp_path / "report.json")
    assert (tmp_path / "note.md").read_bytes() == (samples / "suspicious.md").read_bytes().replace(b"\r\n", b"\n")
    assert (tmp_path / "report.json").read_bytes() == (samples / "suspicious.json").read_bytes().replace(b"\r\n", b"\n")


def write_text(tmp_path, data: bytes) -> Path:
    path = tmp_path / "alert.txt"
    path.write_bytes(data)
    return path


ALERT = "Blocked hxxps://evil[.]com/login from 198.51.100.7, sent by x[@]evil[.]com"
ALERT_INDICATORS = ("Phishing triage: alert text\n\n"
                    "Indicators, defanged\n"
                    "  URL      hxxps://evil[.]com/login\n"
                    "  Domain   evil[.]com\n"
                    "  IP       198[.]51[.]100[.]7\n"
                    "  Email    x[@]evil[.]com\n")


# PowerShell 5 and Notepad save text as UTF-16 with a byte order mark
@pytest.mark.parametrize("encoding", ["utf-8", "utf-8-sig", "utf-16"])
def test_alert_text_from_a_file(capsys, tmp_path, encoding):
    code, out, _ = run(capsys, "--text", write_text(tmp_path, ALERT.encode(encoding)))
    assert code == 0
    assert out == ALERT_INDICATORS


def test_alert_text_from_standard_input(capsys, monkeypatch):
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(ALERT.encode())))
    code, out, _ = run(capsys, "--text", "-")
    assert code == 0
    assert out == ALERT_INDICATORS


def test_nothing_is_looked_up_without_enrich(capsys, tmp_path, monkeypatch):
    # Even with both keys set
    monkeypatch.setenv("VT_API_KEY", "vt-key")
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "abuseipdb-key")
    sent = []
    monkeypatch.setattr(requests, "get", lambda *args, **kwargs: sent.append(args))
    assert run(capsys, FIXTURES / "suspicious.eml")[0] == 0
    assert run(capsys, "--text", write_text(tmp_path, ALERT.encode()))[0] == 0
    assert sent == []


def test_enrich_without_keys_still_runs(capsys):
    # Every missed lookup says why, and nothing is sent. The origin IP is reserved for
    # documentation, so it wouldn't be sent anyway.
    code, out, err = run(capsys, FIXTURES / "suspicious.eml", "--enrich")
    assert code == 0
    assert err == "Looking up 8 indicators...\n"
    indicators = section(out, "Indicators, defanged")
    # Said once for the run, not under each indicator
    assert indicators[-1] == ("  VirusTotal: unavailable, VT_API_KEY isn't set (5 indicators, the ones with no "
                              "VirusTotal result)")
    assert indicators[indicators.index("  Domain   bit[.]ly") + 1] == "  IP       203[.]0[.]113[.]45"
    assert indicators[indicators.index("  IP       203[.]0[.]113[.]45") + 1:][:2] == [
        " " * 11 + "AbuseIPDB: skipped, private or reserved address",
        " " * 11 + "VirusTotal: skipped, private or reserved address",
    ]
    # Email addresses aren't looked up, but their domains are
    assert indicators[indicators.index("  Email    security[@]paypa1[.]com") + 1].startswith("  Email ")


def test_enrich_results_go_under_each_indicator(capsys, tmp_path, monkeypatch):
    monkeypatch.setenv("VT_API_KEY", "vt-key")
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "abuseipdb-key")

    def get(url, **kwargs):
        if kwargs["params"]:
            body = {"data": {"abuseConfidenceScore": 100, "totalReports": 40, "numDistinctUsers": 12}}
        elif url.endswith("/domains/evil.com"):
            body = {"data": {"attributes": {"last_analysis_stats": {"malicious": 9, "undetected": 80},
                                            "last_analysis_date": 1791797400}}}
        else:
            body = {"error": {"code": "NotFoundError"}}
        response = MagicMock()
        response.__enter__.return_value = response
        response.status_code = 404 if "error" in body else 200
        response.iter_content.return_value = [json.dumps(body).encode()]
        return response

    monkeypatch.setattr(requests, "get", get)
    alert = "Blocked hxxps://evil[.]com/login from 8.8.8.8, sent by x[@]evil[.]com"
    code, out, _ = run(capsys, "--text", write_text(tmp_path, alert.encode()), "--enrich")
    assert code == 0
    assert out == ("Phishing triage: alert text\n\n"
                   "Indicators, defanged\n"
                   "  URL      hxxps://evil[.]com/login\n"
                   "           VirusTotal: not found (unknown, not clean)\n"
                   "  Domain   evil[.]com\n"
                   "           VirusTotal: 9 of 89 engines flagged it malicious, last checked 2026-10-12\n"
                   "  IP       8[.]8[.]8[.]8\n"
                   "           AbuseIPDB: reported 40 times by 12 users in the last 90 days, abuse confidence 100%\n"
                   "           VirusTotal: not found (unknown, not clean)\n"
                   "  Email    x[@]evil[.]com\n")


def test_enrich_is_given_the_attachments(capsys, tmp_path, monkeypatch):
    # Used to put pictures, like a signature's logo, after the links
    given = []
    monkeypatch.setattr(cli, "look_up", lambda found, attachments=None, flagged=None, origin=None:
                        given.append(attachments) or {})
    path = write_email(tmp_path, (
        "From: a@example.org\r\nTo: someone@example.net\r\nSubject: s\r\n"
        'Content-Type: multipart/related; boundary="B"\r\n\r\n'
        '--B\r\nContent-Type: text/html\r\n\r\n<img src="cid:image001">\r\n'
        '--B\r\nContent-Type: image/png\r\nContent-Disposition: inline; filename="image001.png"\r\n\r\nx\r\n--B--'
    ))
    assert run(capsys, path, "--enrich")[0] == 0
    assert [attachment.filename for attachment in given[0]] == ["image001.png"]


def test_enrich_checks_how_new_the_domains_are(capsys, monkeypatch):
    # The lookalike check's domain is looked up first
    given = []
    monkeypatch.setattr(cli, "look_up", lambda found, attachments=None, flagged=None, origin=None:
                        given.append(flagged) or {})
    _, out, _ = run(capsys, FIXTURES / "suspicious.eml", "--enrich")
    assert given == [["paypa1.com"]]
    assert ("  INCONCLUSIVE medium      Newly registered domain: No registration date for paypa1.com; "
            "bit.ly") in section(out, "Findings")
    assert "Newly registered domain" not in run(capsys, FIXTURES / "suspicious.eml")[1]


def test_enrich_checks_who_owns_hops_named_as_microsofts(capsys, tmp_path, monkeypatch):
    owner = Reputation("AbuseIPDB", LookupStatus.FOUND, "no reports in the last 90 days, DigitalOcean, LLC in US",
                       {"domain": "digitalocean.com"})
    monkeypatch.setattr(cli, "look_up", lambda found, attachments=None, flagged=None, origin=None:
                        {ip: [owner] for _, _, ip in origin.microsoft_hops})
    path = write_email(tmp_path, (
        "Received: from x.prod.outlook.com (203.0.113.9) by SN6PR02.prod.outlook.com;\r\n"
        " Tue, 6 Oct 2026 10:00:00 +0000\r\nFrom: a@example.org\r\nSubject: s\r\n\r\nHello"))
    _, out, _ = run(capsys, path, "--enrich")
    assert section(out, "Findings")[0] == (
        "  FLAG         very strong Faked Microsoft hop: Received header 1 calls itself x.prod.outlook.com, but "
        "AbuseIPDB lists 203.0.113.9 under digitalocean.com: no reports in the last 90 days, DigitalOcean, LLC in US. "
        "The first is the server Microsoft really got the email from, so the Origin line may be wrong")
    # The email didn't list the hop's IP, but it's likely the sender's server, so it's an indicator
    indicators = section(out, "Indicators, defanged")
    row = indicators.index("  IP       203[.]0[.]113[.]9 (from the Faked Microsoft hop check)")
    assert indicators[row + 1] == " " * 11 + "AbuseIPDB: no reports in the last 90 days, DigitalOcean, LLC in US"
    assert "Faked Microsoft hop" not in run(capsys, path)[1]


def test_a_second_ctrl_c_stops_without_a_traceback(capsys, tmp_path, monkeypatch):
    # The first only skips the lookups left
    def ctrl_c(*args):
        raise KeyboardInterrupt

    monkeypatch.setattr(enrich, "_look_up_one", ctrl_c)
    code, _, err = run(capsys, "--text", write_text(tmp_path, ALERT.encode()), "--enrich")
    assert (code, err) == (130, "Looking up 3 indicators...\nStopped\n")


def test_alert_text_without_indicators(capsys, tmp_path):
    _, out, err = run(capsys, "--text", write_text(tmp_path, b"Nothing to see"), "--enrich")
    assert out == "Phishing triage: alert text\n\nIndicators, defanged\n  none found\n"
    # Nothing to wait for, so nothing to say
    assert err == ""


def test_indicators_are_printed_escaped(capsys, tmp_path):
    # A right-to-left override in a URL could make it read differently on screen
    _, out, _ = run(capsys, "--text",
                    write_text(tmp_path, "https://evil.com/\N{RIGHT-TO-LEFT OVERRIDE}fdp.exe".encode()))
    assert "  URL      hxxps://evil[.]com/\\u202efdp[.]exe" in out


def test_alert_text_size_limit(capsys, tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "MAX_TEXT_BYTES", 10)
    assert run(capsys, "--text", write_text(tmp_path, b"x" * 10))[0] == 0
    code, _, err = run(capsys, "--text", write_text(tmp_path, b"x" * 11))
    assert code == 1
    assert err.endswith("too big to be alert text\n")


@pytest.mark.parametrize("name", ["missing.txt", ""])
def test_missing_text_file_gives_a_clean_error(capsys, tmp_path, name):
    code, _, err = run(capsys, "--text", tmp_path / name if name else "")
    assert code == 1
    assert err.startswith("error: ")


@pytest.mark.parametrize("days_old, noted", [(184, True), (183, False), (None, False)],
                         ids=["over 6 months", "6 months", "no date"])
def test_an_old_suffix_list_is_noted(capsys, tmp_path, monkeypatch, days_old, noted):
    # It's about the tool's copy, not the email, so it goes to stderr, after the results
    published = date.today() - timedelta(days=days_old) if days_old is not None else None
    monkeypatch.setattr(cli, "SUFFIX_LIST_DATE", published)
    for args in ([FIXTURES / "clean.eml"], ["--text", write_text(tmp_path, ALERT.encode())]):
        code, _, err = run(capsys, *args)
        assert code == 0
        if noted:
            assert err == (f"Note: the Public Suffix List copy is from {published}, over 6 months old, so endings "
                           "added since aren't known. Update it with: python -m triage.update_suffixes\n")
        else:
            assert err == ""


@pytest.mark.parametrize("args", [[], [FIXTURES / "clean.eml", "--text", "alert.txt"]], ids=["neither", "both"])
def test_needs_an_email_or_text_but_not_both(capsys, args):
    with pytest.raises(SystemExit) as exit_info:
        run(capsys, *args)
    assert exit_info.value.code == 2


def test_help_describes_what_works(capsys):
    with pytest.raises(SystemExit) as exit_info:
        run(capsys, "--help")
    assert exit_info.value.code == 0
    out = " ".join(capsys.readouterr().out.split())
    # Named triage, not __main__.py, which python -m would show
    assert out.startswith("usage: triage ")
    assert "The verdict is left to the analyst." in out
    assert "write the Markdown triage note to FILE, for a ticket" in out
    assert "write the report as JSON to FILE, for other tools" in out


@pytest.mark.parametrize("text, message", [
    ("just some text\r\nwith no headers", "error: no email headers found"),
    ("From: a@example.org\r\nContent-Type: text/plain; name=" + "a" * 10_000 + "\r\n\r\nx",
     "error: the Content-Type header is 10,"),
    ("From: a@example.org\r\nContent-Type: text/html; " + "(a" * 1_000 + "\r\n\r\nx",
     "error: the email has parts or header comments nested too deeply to read"),
], ids=["no headers", "header too long", "nested too deeply"])
def test_emails_that_cant_be_read_give_a_clean_error(capsys, tmp_path, text, message):
    code, out, err = run(capsys, write_email(tmp_path, text))
    assert code == 1
    assert err.startswith(message)
    assert "Traceback" not in err


def test_missing_file_gives_a_clean_error(capsys, tmp_path):
    code, _, err = run(capsys, tmp_path / "missing.eml")
    assert code == 1
    assert err.startswith("error: ")
