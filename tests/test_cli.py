"""Tests for the command line (triage/__main__.py), run on the synthetic fixtures and on
emails written to a temporary folder."""

import contextlib
import io
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

from triage import impersonation
from triage.__main__ import main

FIXTURES = Path(__file__).parent / "fixtures"
CHECK_NAMES = ["SPF", "DKIM", "DMARC", "Reply-To", "Return-Path domain", "Display name", "Free webmail sender",
               "Lookalike domain", "Brand joined to a word", "Link text vs destination"]


def run(capsys, *args) -> tuple[int, str, str]:
    code = main([str(arg) for arg in args])
    out, err = capsys.readouterr()
    return code, out, err


def results(out: str) -> dict[str, str]:
    # "  FLAG         strong  DMARC: ..." gives {"DMARC": "FLAG"}
    return dict((name, result) for result, name in
                re.findall(r"^  (FLAG|PASS|INCONCLUSIVE) +\w+ +([^:]+):", out, re.M))


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
    summary, checks = out.split("\n\n")
    assert summary.splitlines() == [
        "From:        security@paypa1.com",
        "Subject:     Action required: your account has been limited",
        "Links:       2",
        "Attachments: 1",
        "  043ea8960dc71f654cf0ac9ac501c16d09eed7b0e1528532fe25f122f1cc4f35  "
        "Account_Statement.pdf (application/pdf, 60 bytes)",
        "Origin:      203.0.113.45 (mail.paypa1.com) handed it to mx.example.net, "
        "lower hops claim 198.51.100.23 (could be forged)",
    ]
    flagged = {name for name, result in results(checks).items() if result == "FLAG"}
    assert flagged == {"DMARC", "Reply-To", "Display name", "Lookalike domain", "Link text vs destination"}


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
    assert r"Subject:     Invoice\x1b[1A\x1b[2K paid" in out
    assert "invoice\\u202efdp.exe" in out


def test_warnings_are_printed_escaped(capsys, tmp_path):
    # Warnings can repeat text from the email. The Mailsploit attacks hid a null byte in an
    # encoded address, and some clients stopped reading there and showed only service@paypal.com.
    path = write_email(tmp_path, (
        "From: =?utf-8?q?service=40paypal=2Ecom=00?=@evil.com\r\nTo: someone@example.net\r\n"
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
    assert list(results(out)) == CHECK_NAMES


def test_output_that_cant_be_reconfigured():
    # A script calling main() can send its output to a StringIO, which has no encoding to change
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        assert main([str(FIXTURES / "clean.eml")]) == 0
    assert list(results(output.getvalue())) == CHECK_NAMES


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
    assert "Subject:     Prize \N{WRAPPED PRESENT}" in process.stdout.decode("utf-8")


@pytest.mark.parametrize("args, flags", [
    (["--out", "note.md"], "--out"),
    (["--json", "report.json"], "--json"),
    (["--enrich"], "--enrich"),
    (["--out", "note.md", "--enrich"], "--out, --enrich"),
])
def test_options_not_built_yet_stop(capsys, args, flags):
    # Stops instead of quietly skipping what was asked for
    code, out, err = run(capsys, FIXTURES / "clean.eml", *args)
    assert code == 1
    assert err == f"error: not built yet: {flags}\n"
    assert out == ""


def test_empty_text_option_still_counts_as_asked_for(capsys):
    code, _, err = run(capsys, "--text", "")
    assert code == 1
    assert err == "error: not built yet: --text\n"


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
    assert out.count("Not built yet") == 4


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
