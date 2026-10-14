"""Broken and damaged emails. Spam is often malformed, and the tool should still give a
result or a clean error. The command line only catches ValueError (and OSError for the
file), so anything else would end triage with a traceback."""

import random
from pathlib import Path

import pytest

from triage.checks import run_checks
from triage.iocs import from_email
from triage.parser import parse_bytes
from triage.received import find_origin, received_warnings

FIXTURES = Path(__file__).parent / "fixtures"
HEADERS = b"From: a@example.org\r\nTo: b@example.net\r\nSubject: s\r\n"


def triage(raw: bytes) -> None:
    try:
        parsed = parse_bytes(raw)
    except ValueError:
        return  # shown as a clean error
    run_checks(parsed)
    from_email(parsed, find_origin(parsed))
    received_warnings(parsed)


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
          b"Authentication-Results: ", b";", b"=", b":", b"::ffff:", b"[IPv6:"]


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


def test_damaged_emails():
    run_damaged(500, seed=1)


@pytest.mark.slow
def test_many_damaged_emails():
    run_damaged(10_000, seed=2)
