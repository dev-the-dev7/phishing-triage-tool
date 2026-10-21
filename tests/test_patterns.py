"""Tests for triage/report/patterns.py: findings that mean more together than apart."""

from triage.checks import run_checks
from triage.checks.impersonation import check_lookalike
from triage.models import Address, Check, Link, ParsedEmail
from triage.reading.parser import parse_bytes
from triage.report.patterns import find_patterns

ORG = [Address("", "a@example.org", "example.org")]
LOOKALIKE_FROM = [Address("", "a@paypa1.com", "paypa1.com")]
DMARC_PASS = Check("DMARC", "pass", "strong", "")
LOOKALIKE = Check("Lookalike domain", "flag", "strong", "", domains=["paypa1.com"])
LOOKALIKE_LINK = [Link("https://paypa1.com/", "")]
WEBMAIL = Check("Free webmail sender", "flag", "weak", "")


def patterns_found(checks, **fields) -> list[tuple[str, list[str]]]:
    parsed = ParsedEmail(**{"from_addrs": ORG, **fields})
    return [(pattern.name, pattern.found) for pattern in find_patterns(parsed, checks)]


def test_a_lookalike_that_passes_authentication():
    dkim = Check("DKIM", "pass", "medium", "")
    assert patterns_found([DMARC_PASS, dkim, LOOKALIKE], from_addrs=LOOKALIKE_FROM) == [
        ("Lookalike that passes authentication", ["DMARC", "DKIM", "Lookalike domain"])]
    assert patterns_found([Check("DMARC", "flag", "strong", ""), LOOKALIKE], from_addrs=LOOKALIKE_FROM) == []


def test_a_dkim_pass_doesnt_count_once_dmarc_fails():
    # An envelope address with an unquoted ; can add a DKIM pass to your provider's header
    dkim = Check("DKIM", "pass", "medium", "")
    dmarc_fail = Check("DMARC", "flag", "strong", "")
    assert patterns_found([dmarc_fail, dkim, LOOKALIKE], links=LOOKALIKE_LINK) == []
    assert patterns_found([dmarc_fail, dkim, LOOKALIKE], from_addrs=LOOKALIKE_FROM) == []
    # A domain with no DMARC record has only DKIM to go by
    assert patterns_found([Check("DMARC", "inconclusive", "strong", ""), dkim, LOOKALIKE], links=LOOKALIKE_LINK) == [
        ("Authenticated sender with a lookalike link", ["DKIM", "Lookalike domain"])]


def test_a_unicode_lookalike_is_matched_as_the_reader_sees_it():
    # The lookalike check names the domain as it displays, and the From and links have its xn-- form
    parsed = ParsedEmail(from_addrs=[Address("", "a@xn--pypal-4ve.com", "xn--pypal-4ve.com")])
    patterns = find_patterns(parsed, [DMARC_PASS, check_lookalike(parsed)])
    assert [pattern.name for pattern in patterns] == ["Lookalike that passes authentication"]
    parsed = ParsedEmail(from_addrs=ORG, links=[Link("https://xn--pypal-4ve.com/", "")])
    patterns = find_patterns(parsed, [DMARC_PASS, check_lookalike(parsed)])
    assert [pattern.name for pattern in patterns] == ["Authenticated sender with a lookalike link"]


def test_an_authenticated_sender_with_a_lookalike_link():
    assert patterns_found([DMARC_PASS, LOOKALIKE], links=LOOKALIKE_LINK) == [
        ("Authenticated sender with a lookalike link", ["DMARC", "Lookalike domain"])]
    assert patterns_found([LOOKALIKE], links=LOOKALIKE_LINK) == []
    # The lookalike is only in the Reply-To
    assert patterns_found([DMARC_PASS, LOOKALIKE], reply_to=LOOKALIKE_FROM) == []
    # Anyone can make a webmail account to send from
    assert patterns_found([DMARC_PASS, LOOKALIKE, WEBMAIL], links=LOOKALIKE_LINK) == []
    # Ordinary mail trips these, with click tracking and a template's javascript:void(0)
    assert patterns_found([DMARC_PASS, Check("Link text vs destination", "flag", "strong", ""),
                           Check("Script, file or app link", "flag", "medium", "")]) == []


def patterns_in(from_domain: str, html: str) -> list[str]:
    raw = (f"Authentication-Results: mx.example.net; dkim=pass header.d={from_domain}; dmarc=pass "
           f"header.from={from_domain}\r\nFrom: a@{from_domain}\r\nContent-Type: text/html\r\n\r\n{html}")
    parsed = parse_bytes(raw.encode())
    return [pattern.name for pattern in find_patterns(parsed, run_checks(parsed))]


def test_patterns_from_the_real_checks():
    # They find checks by name, so a renamed check would quietly stop one
    assert patterns_in("paypa1.com", "<p>Hi</p>") == ["Lookalike that passes authentication"]
    assert patterns_in("vendor.example", '<a href="https://micros0ft-login.example/">View</a>') == [
        "Authenticated sender with a lookalike link"]
