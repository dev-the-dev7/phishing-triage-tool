"""Timing tests. The sender controls most of an email, and a crafted one can make slow code
run for minutes, which stalls triage. Run the full sweep with: pytest -m slow"""

import os
import time

import pytest

from triage.checks import run_checks
from triage.headers import check_dkim, check_dmarc, check_spf
from triage.impersonation import check_brand_joined, check_lookalike
from triage.iocs import from_email, from_text
from triage.link_wrappers import destinations, unwrap
from triage.models import Link, ParsedEmail
from triage.parser import parse_bytes
from triage.received import find_origin, received_warnings


def seconds(task) -> float:
    start = time.perf_counter()
    task()
    return time.perf_counter() - start


# A slower or busier machine, like a shared one running CI, slows a regression as much as the
# code, so it can give every limit here more room: TIMING_SCALE=3 triples them
SCALE = float(os.environ.get("TIMING_SCALE", "1"))
LIMIT = 1 * SCALE

# Input that made the tool take minutes while it was being built, or that could. The slowest
# takes about half a second now, so a machine twice as slow would reach the one-second limit.

def test_long_run_of_spaces_in_received():
    # \s+ next to .*? in the from ... by pattern tried every split of the spaces
    parsed = ParsedEmail(received=["from " + " " * 200_000 + "x"])
    assert seconds(lambda: (find_origin(parsed), received_warnings(parsed))) < LIMIT


def test_many_dashes_in_a_link_host():
    # Every run of neighboring pieces is a word to compare, so runs longer than any brand
    # name are skipped
    parsed = ParsedEmail(links=[Link("https://" + "a-" * 5_000 + "a.com/", "")])
    assert seconds(lambda: (check_lookalike(parsed), check_brand_joined(parsed))) < LIMIT


@pytest.mark.parametrize("unit", ["(", "(a", '"', '"\\', '\\"', '"('])
def test_unclosed_comments_and_quotes_in_authentication_results(unit):
    parsed = ParsedEmail(auth_results=["mx.example.org; dkim=pass " + unit * 20_000])
    assert seconds(lambda: (check_spf(parsed), check_dkim(parsed), check_dmarc(parsed))) < LIMIT


def test_many_bases_and_links():
    # Every link is read against each <base>, so only the first MAX_BASES of them are used
    html = "".join(f'<base href="https://b{i}.example/">' for i in range(500)) + '<a href="/x">x</a>' * 500
    raw = ("From: a@example.org\r\nContent-Type: text/html\r\n\r\n" + html).encode()
    assert seconds(lambda: run_checks(parse_bytes(raw))) < LIMIT


def test_many_from_and_reply_to_addresses():
    # The Reply-To check compares each From with every Reply-To
    addresses = ", ".join(f"a{i}@e{i}.example" for i in range(1_000))
    parsed = parse_bytes(f"From: {addresses}\r\nReply-To: {addresses}\r\n\r\nx".encode())
    assert seconds(lambda: run_checks(parsed)) < LIMIT


def test_thousands_of_open_elements():
    # Finding the element an end tag closes, or one a new tag ends, would search every open
    # element each time
    html = "<span>" * 10_000 + "<p>x<li>" * 10_000 + "</b>" * 10_000
    raw = ("From: a@example.org\r\nContent-Type: text/html\r\n\r\n" + html).encode()
    assert seconds(lambda: run_checks(parse_bytes(raw))) < LIMIT


def test_unclosed_outlook_parts():
    # Python reads an unclosed comment as running to the end, so an early version that read
    # each Outlook part again on its own read the rest of the email once per part
    raw = ("From: a@example.org\r\nContent-Type: text/html\r\n\r\n" + "<!--[if mso]>" * 150_000).encode()
    assert seconds(lambda: parse_bytes(raw)) < LIMIT


def test_long_style_block_and_link_text():
    # Every content: in the CSS is read, and every tag in a link's text marks a place to look
    css = "<style>" + r".x::before{content:'\2e'}" * 10_000 + "content:" * 10_000 + "</style>"
    link = '<a href="https://evil.com/">' + "pay<b>pal</b>.com " * 10_000 + "</a>"
    raw = ("From: a@example.org\r\nContent-Type: text/html\r\n\r\n" + css + link).encode()
    assert seconds(lambda: parse_bytes(raw)) < LIMIT


def test_long_run_of_spaces_in_alert_text():
    # Defanged brackets can have spaces in front (evil [.] com), and trying every space in the
    # run as the start was quadratic
    assert seconds(lambda: from_text("a" + " " * 200_000 + "b")) < LIMIT


@pytest.mark.parametrize("link", [
    # A regex matching lazily from each /v3/__ to the end would be quadratic
    "https://urldefense.com/v3/__" + "/v3/__" * 200_000,
    # Kysr is base64 for +++, one character for each mark
    "https://urldefense.com/v3/__https://evil.com/" + "a*" * 100_000 + "__;" + "Kysr" * 33_334 + "!!x$",
], ids=["no end", "many marks"])
def test_long_proofpoint_link(link):
    assert seconds(lambda: unwrap(link)) < LIMIT


def test_two_link_wrappers_nested_hundreds_deep():
    # Encoding only % and & at each level keeps the link short enough to nest this deep.
    # Reading every level took seconds, and twice as deep ran out of stack.
    url = "https://evil.com/"
    for _ in range(600):
        url = "https://www.google.com/url?url=https://a.com/&q=" + url.replace("%", "%25").replace("&", "%26")
    assert seconds(lambda: destinations(url)) < LIMIT


# The full sweep puts each pattern in every field the sender controls, at two sizes. Code
# that keeps up with the input takes about twice as long for twice the input. Four times
# means it's quadratic, and that becomes minutes on a larger email.

UNITS = [
    "( ", "(a", "x(", "( [", "(a [", "[1", "[1.1", "a.", "a-", "-.", "1.", ". ", "a ", "\t",
    "from by ", "by ", "=", ";", ";l=", "header.d=", "=?utf-8?q?a?=", "\\", '"', '"\\', "/\\",
    "a\\@", "%7", "&#9;", "rn", "c1", "a,", "<a", "@", ":", "<p>", "<li>", "<td>", "</b>", "<i hidden>", "a.<br>",
    '<i style="font-size:0">x', "/*", "<!--[if mso]><a>", "<![endif]-->",
    "\N{FULLWIDTH LATIN SMALL LETTER P}", "\N{IDEOGRAPHIC FULL STOP}",
]


def crafted_email(unit: str, length: int) -> bytes:
    blob = (unit * (length // len(unit) + 1))[:length]
    return (
        f"Received: from {blob} by mx.example.org; Tue, 6 Oct 2026\r\n"
        f"Received: from x ({blob} [203.0.113.5]) by {blob}; Tue, 6 Oct 2026\r\n"
        f"Authentication-Results: mx.example.org; spf=pass {blob}; dkim=pass header.d={blob}\r\n"
        f"DKIM-Signature: v=1; d=example.org; {blob}\r\n"
        f'From: "{blob}" <a@{blob}.com>\r\n'
        f"Reply-To: {blob}\r\nReturn-Path: {blob}\r\nTo: {blob}\r\nSubject: {blob}\r\n"
        "Content-Type: text/html; charset=utf-8\r\n\r\n"
        f'<base href="{blob}"><a href="http:{blob}">{blob}</a><a href="https://{blob}/">x</a>\r\n'
    ).encode()


def triage(raw: bytes) -> None:
    parsed = parse_bytes(raw)
    run_checks(parsed)
    from_email(parsed, find_origin(parsed))
    received_warnings(parsed)


@pytest.mark.slow
@pytest.mark.parametrize("unit", UNITS)
def test_time_grows_with_the_input(unit):
    small = seconds(lambda: triage(crafted_email(unit, 20_000)))
    large = seconds(lambda: triage(crafted_email(unit, 40_000)))
    # The added 0.1 seconds covers timer noise on the quick ones
    assert large < 3 * small + 0.1 * SCALE


# Alert text goes through other patterns: defanged brackets, addresses, IPs and hashes
TEXT_UNITS = UNITS + [" ", "[", "[ ", " [.", "(dot", "hxx", "h**ps", "a@", "a@b", "@a.", "1.1.", "1:",
                      "::", "a:", "0a", "www.", "https://", "\\."]


@pytest.mark.slow
@pytest.mark.parametrize("unit", TEXT_UNITS)
def test_alert_text_time_grows_with_the_input(unit):
    small = seconds(lambda: from_text((unit * 100_000)[:100_000]))
    large = seconds(lambda: from_text((unit * 200_000)[:200_000]))
    assert large < 3 * small + 0.1 * SCALE
