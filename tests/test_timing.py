"""Timing tests. The sender controls most of an email, and a crafted one can make slow code
run for minutes, which stalls triage. Run the full sweep with: pytest -m slow"""

import time

import pytest

from triage.checks import run_checks
from triage.headers import check_authentication
from triage.impersonation import check_brand_joined, check_lookalike
from triage.models import Link, ParsedEmail
from triage.parser import parse_bytes
from triage.received import find_origin, received_warnings


def seconds(task) -> float:
    start = time.perf_counter()
    task()
    return time.perf_counter() - start


# Four slowdowns found while building the checks. Each took minutes on input like this, and
# takes milliseconds now, so a one-second limit leaves plenty of room on a slow machine.

def test_long_run_of_spaces_in_received():
    # \s+ next to .*? in the from ... by pattern tried every split of the spaces
    parsed = ParsedEmail(received=["from " + " " * 200_000 + "x"])
    assert seconds(lambda: (find_origin(parsed), received_warnings(parsed))) < 1


def test_many_dashes_in_a_link_host():
    # Every run of neighboring pieces is a word to compare, so runs longer than any brand
    # name are skipped
    parsed = ParsedEmail(links=[Link("https://" + "a-" * 5_000 + "a.com/", "")])
    assert seconds(lambda: (check_lookalike(parsed), check_brand_joined(parsed))) < 1


@pytest.mark.parametrize("unit", ["(", "(a", '"', '"\\', '\\"', '"('])
def test_unclosed_comments_and_quotes_in_authentication_results(unit):
    parsed = ParsedEmail(auth_results=["mx.example.org; dkim=pass " + unit * 20_000])
    assert seconds(lambda: check_authentication(parsed)) < 1


def test_many_bases_and_links():
    # Every link is read against each <base>, so only the first MAX_BASES of them are used
    html = "".join(f'<base href="https://b{i}.example/">' for i in range(500)) + '<a href="/x">x</a>' * 500
    raw = ("From: a@example.org\r\nContent-Type: text/html\r\n\r\n" + html).encode()
    assert seconds(lambda: run_checks(parse_bytes(raw))) < 1


# The full sweep puts each pattern in every field the sender controls, at two sizes. Code
# that keeps up with the input takes about twice as long for twice the input. Four times
# means it's quadratic, and that becomes minutes on a larger email.

UNITS = [
    "( ", "(a", "x(", "( [", "(a [", "[1", "[1.1", "a.", "a-", "-.", "1.", ". ", "a ", "\t",
    "from by ", "by ", "=", ";", ";l=", "header.d=", "=?utf-8?q?a?=", "\\", '"', '"\\', "/\\",
    "a\\@", "%7", "&#9;", "rn", "c1", "a,", "<a", "@", ":",
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
    find_origin(parsed)
    received_warnings(parsed)


@pytest.mark.slow
@pytest.mark.parametrize("unit", UNITS)
def test_time_grows_with_the_input(unit):
    small = seconds(lambda: triage(crafted_email(unit, 20_000)))
    large = seconds(lambda: triage(crafted_email(unit, 40_000)))
    # The added 0.1 seconds covers timer noise on the quick ones
    assert large < 3 * small + 0.1
