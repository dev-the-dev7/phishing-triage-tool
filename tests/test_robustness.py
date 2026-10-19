"""Broken and damaged emails. Spam is often malformed, and the tool should still give a
report that nothing in the email can rewrite, or a clean error. The command line only catches
ValueError (and OSError for the file), so anything else would end triage with a traceback."""

import random
import unicodedata
from pathlib import Path

import pytest

from triage.checks import run_checks
from triage.iocs import from_email, from_text
from triage.models import MAX_FROMS
from triage.parser import parse_bytes
from triage.received import find_origin, received_warnings
from triage.report import build_report, build_text_report, render_json, render_markdown, render_summary, render_text

FIXTURES = Path(__file__).parent / "fixtures"
HEADERS = b"From: a@example.org\r\nTo: b@example.net\r\nSubject: s\r\n"


def triage(raw: bytes) -> None:
    # Up to the report in every format, which is where text from the email ends up. The bytes are
    # read as alert text too, since alerts quote the email they came from.
    reports = [build_text_report(from_text(raw.decode("utf-8-sig", errors="replace")), {})]
    try:
        parsed = parse_bytes(raw)
    except ValueError:
        pass  # shown as a clean error
    else:
        origin = find_origin(parsed)
        reports.append(build_report(parsed, origin, run_checks(parsed), from_email(parsed, origin), {},
                                    parsed.parse_warnings + received_warnings(parsed)))
    for report in reports:
        # Anything outside ASCII, control characters included, is written as an escape code
        assert render_json(report).isascii()
        for text in (render_text(report), render_markdown(report), render_summary(report, ["note.md"])):
            # Shown as codes, so nothing from the email can move the cursor, reorder the text,
            # start a line of its own or stop the note being written
            unescaped = [c for c in text if c != "\n" and unicodedata.category(c) in ("Cc", "Cf", "Cs", "Zl", "Zp")]
            assert not unescaped, f"shown as they are: {unescaped}"


BROKEN_EMAILS = {
    "attachment with bad base64": HEADERS + (
        b"Content-Type: multipart/mixed; boundary=X\r\n\r\n--X\r\nContent-Type: application/pdf\r\n"
        b"Content-Transfer-Encoding: base64\r\nContent-Disposition: attachment; filename=a.pdf\r\n\r\n!!!@@@\r\n--X--"),
    "HTML in an unknown charset": HEADERS + b"Content-Type: text/html; charset=x-nope\r\n\r\n<a href='http://\xff\xfe.com'>p</a>",
    "20,000 unclosed links": HEADERS + b"Content-Type: text/html\r\n\r\n" + b"<a href='http://x.com'>" * 20_000,
    "broken hrefs": HEADERS + b"Content-Type: text/html\r\n\r\n" + b"".join(
        b"<a href='%s'>paypal.com</a>" % href for href in (
            b"http://[::1", b"http://[zz]/", b"http://a:99999/", b"http://%41/", b"http://\xc3\xa9.com",
            b"http:////x", b"\x00", b"http://a..b/", b"http://-/")),
    "broken addresses": (b'From: "" <@>\r\nReply-To: <>, undisclosed, @x, "a"@, <a@[1.2.3.4]>\r\n'
                         b"Return-Path: <@@>\r\nSubject: s\r\n\r\nx"),
    "broken Received headers": HEADERS + b"".join(b"Received: from %s by %s\r\n" % pair for pair in (
        (b"(", b"x"), (b"[", b"y"), (b"([1.2.3.4]", b";"), (b"a (b [::ffff:1.2.3.4])", b"z"),
        (b"x (1.2.3.4.5)", b"q"), (b"x ([999.1.1.1])", b"q"), (b"([fe80::1%eth0])", b"q"))) + b"\r\nx",
    "broken Authentication-Results": HEADERS + (
        b"Authentication-Results: ;;;=;(;)=pass;dmarc=\r\nAuthentication-Results: (((\r\n\r\nx"),
    "null bytes and stray 8-bit": b"From: a\x00@exa\xffmple.org\r\nSubject: \x00\xff\r\n\r\n\x00",
    # Terminal codes, a right-to-left override and line and paragraph separators, in the display
    # name, file name and declared type, which the parser keeps as they are
    "characters that would change the report": (
        b"From: =?utf-8?q?Pay=1B[2KPal=E2=80=A8PASS?= <a@example.org>\r\nSubject: s\r\n"
        b'Content-Type: multipart/mixed; boundary="B"\r\n\r\n--B\r\nContent-Type: application/x\x1b[2Kpdf\r\n'
        b'Content-Disposition: attachment; filename="invoice\xe2\x80\xaefdp.exe\xe2\x80\xa8x\xe2\x80\xa9y"\r\n\r\n'
        b"x\r\n--B--"),
}


@pytest.mark.parametrize("raw", BROKEN_EMAILS.values(), ids=BROKEN_EMAILS.keys())
def test_broken_email_gives_a_result_or_a_clean_error(raw):
    triage(raw)


# Damaged copies of the fixtures: bytes inserted, deleted, changed, or copied elsewhere.
# The seed is fixed, so every run tries the same emails and a failure can be repeated.

TOKENS = [b"\r\n", b"\r\n\r\n", b"=?utf-8?b?", b"=?utf-8?q?", b"?=", b"<", b">", b"@", b'"', b"(", b")",
          b"[", b"]", b"--", b"boundary=", b'Content-Type: multipart/mixed; boundary="b"',
          b"Content-Transfer-Encoding: base64", b'charset="x-unknown"', b'<a href="', b'">', b"</a>",
          b"<![", b"\x00", b"\xff", b"%", b"xn--", b"\x1b", b"Received: from ", b" by ",
          b"Authentication-Results: ", b";", b"=", b":", b"::ffff:", b"[IPv6:",
          # A right-to-left override, a zero-width space and a line separator, in UTF-8
          b"\xe2\x80\xae", b"\xe2\x80\x8b", b"\xe2\x80\xa8"]


def damaged(data: bytes, rng: random.Random) -> bytes:
    damaged = bytearray(data)
    for _ in range(rng.randint(1, 12)):
        action = rng.random()
        position = rng.randrange(len(damaged) + 1)
        if action < 0.35:
            damaged[position:position] = rng.choice(TOKENS)
        elif action < 0.6 and damaged:
            del damaged[position:position + rng.randint(1, 40)]
        elif action < 0.8 and damaged:
            damaged[min(position, len(damaged) - 1)] = rng.randrange(256)
        else:
            start = rng.randrange(len(damaged) or 1)
            damaged[position:position] = damaged[start:start + rng.randint(1, 200)]
    return bytes(damaged)


def run_damaged(count: int, seed: int) -> None:
    rng = random.Random(seed)
    originals = [path.read_bytes() for path in sorted(FIXTURES.glob("*.eml"))]
    for _ in range(count):
        raw = damaged(rng.choice(originals), rng)
        try:
            triage(raw)
        except Exception as e:
            raise AssertionError(f"{type(e).__name__} on this email: {raw!r}") from e


def repeated(n: int) -> bytes:
    # Every item a sender can repeat, n times over, numbered to the same width so the first five
    # are as long at any size. Authentication-Results is left out, since your provider writes it.
    date = "Tue, 06 Oct 2026 10:00:00 +0000"
    headers = [f"{name}: =?utf-8?q?x{i:03}?=@{domain}{i:03}.com" for i in range(n)
               for name, domain in (("From", "paypa"), ("Sender", "evil"), ("Reply-To", "reply"))]
    headers += [f"Return-Path: <=?utf-8?q?b{i:03}?=@bounce{i:03}.com>" for i in range(n)]
    headers += ["To: " + ", ".join(f"=?utf-8?q?t{i:03}?=@example.net" for i in range(n))]
    headers += [f"Received: from 203.0.113.{i} by mta.example.org with HTTP; {date}" for i in range(n)]
    html = "\n".join(
        f'<a href="https://evil{i:03}.com/">paypal.com</a> <a href="javascript:x{i:03}()">Open</a> '
        f'<a href="https://www.google.com/url?q=https://g{i:03}.com/">Go</a> <a href="https://nam12.safelinks.'
        f'protection.outlook.com/?url=https://a{i:03}.com/&amp;url=https://b{i:03}.com/">Click</a> '
        f'<a href="https://x{i:03}.com/">pay<b>pal{i:03}</b>.com</a> Mic<span style="font-size:0">x{i:03}</span>rosoft '
        f'<base href="https://base{i:03}.com/"><style>.c{i:03}::after {{content: "pay{i:03}pal.com"}}</style>'
        for i in range(n))
    parts = [f"Content-Type: text/html\r\n\r\n{html}"] + ["Content-Type: text/plain; charset=x-unknown\r\n\r\nhi"] * n
    parts += [f'Content-Type: message/rfc822\r\nContent-Disposition: attachment; filename="{i:03}.eml"\r\n\r\nhi'
              for i in range(n)]
    body = "".join(f"--B\r\n{part}\r\n" for part in parts) + "--B--"
    return ("\r\n".join(headers) + '\r\nContent-Type: multipart/mixed; boundary="B"\r\n\r\n' + body).encode()


def sizes(raw: bytes) -> tuple[int, dict]:
    parsed = parse_bytes(raw)
    checks = run_checks(parsed)
    return (len(parsed.parse_warnings + received_warnings(parsed)),
            {check.name: (check.result, len(check.caveats), len(check.evidence)) for check in checks})


def test_repeating_every_item_doesnt_grow_the_warnings_caveats_or_evidence():
    # Indicators and attachments are listed in full, since each is acted on. The two lookup
    # checks are left out, since a run's lookups are limited. Both sizes have more From
    # addresses than a check reads, which on its own makes a pass inconclusive.
    (few_warnings, few), (many_warnings, many) = sizes(repeated(MAX_FROMS + 1)), sizes(repeated(60))
    assert many_warnings == few_warnings
    assert many.keys() == few.keys()
    for name, (result, caveats, evidence) in few.items():
        assert many[name][:2] == (result, caveats), name
        # Counts like "(and 1 more)" are a digit longer
        assert many[name][2] - evidence <= 6, name


def test_damaged_emails():
    run_damaged(500, seed=1)


@pytest.mark.slow
def test_many_damaged_emails():
    run_damaged(10_000, seed=2)
