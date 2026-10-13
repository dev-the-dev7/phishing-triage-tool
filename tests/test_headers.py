"""Tests for triage/headers.py: SPF, DKIM, DMARC, Reply-To, Return-Path, and free webmail."""

import pytest

from triage import headers
from triage.headers import check_authentication, check_free_email, check_reply_to, check_return_path
from triage.impersonation import check_lookalike
from triage.models import Check, ParsedEmail, Result
from triage.parser import parse_bytes

PASS, FLAG, INCONCLUSIVE = Result.PASS, Result.FLAG, Result.INCONCLUSIVE


def parse(*header_lines: str) -> ParsedEmail:
    # Goes through the parser, since some of these attacks depend on how a header is read
    raw = "\r\n".join([*header_lines, "To: someone@example.net", "Subject: Test", "", "Hello"])
    return parse_bytes(raw.encode())


def authenticate(*auth_results: str, from_addr="service@paypal.com", signatures=(), extra=()) -> dict[str, Check]:
    # auth_results topmost first, the way providers stack them
    parsed = parse(*(f"Authentication-Results: {r}" for r in auth_results),
                   *(f"DKIM-Signature: {s}" for s in signatures),
                   f"From: {from_addr}", *extra)
    return {check.name: check for check in check_authentication(parsed)}


ALL_PASS = ("mx.google.com; dkim=pass header.i=@paypal.com header.s=s1 header.b=AbCd; "
            "spf=pass smtp.mailfrom=paypal.com; dmarc=pass header.from=paypal.com")
ALL_FAIL = ("mx.google.com; dkim=fail header.i=@paypal.com; spf=fail smtp.mailfrom=paypal.com; "
            "dmarc=fail header.from=paypal.com")


def test_all_pass():
    checks = authenticate(ALL_PASS)
    assert [c.result for c in checks.values()] == [PASS, PASS, PASS]


def test_no_header_is_inconclusive():
    checks = check_authentication(parse("From: service@paypal.com"))
    assert [c.result for c in checks] == [INCONCLUSIVE] * 3
    assert [c.evidence for c in checks] == ["Not reported (the email has no Authentication-Results header)"] * 3


def test_a_forged_pass_below_the_provider_header_is_ignored():
    # The sender wrote the lower header, so its passes don't count
    checks = authenticate(ALL_FAIL, ALL_PASS)
    assert [c.result for c in checks.values()] == [FLAG, FLAG, FLAG]
    assert all("ignored 1 untrusted header(s)" in c.evidence for c in checks.values())


def test_trusted_authserv_ids_pick_the_provider_header(monkeypatch):
    # Compared without case. The trusted server's header counts even with a forged one above
    # it, which the default (trust the topmost) would have used.
    monkeypatch.setattr(headers, "TRUSTED_AUTHSERV_IDS", {"MX.Google.com"})
    checks = authenticate(ALL_PASS.replace("mx.google.com", "mx.evil.com"), ALL_FAIL.replace("mx.google.com", "MX.GOOGLE.COM"))
    assert [c.result for c in checks.values()] == [FLAG, FLAG, FLAG]


def test_trusted_authserv_ids_with_only_a_forged_header(monkeypatch):
    monkeypatch.setattr(headers, "TRUSTED_AUTHSERV_IDS", {"mx.google.com"})
    checks = authenticate(ALL_PASS.replace("mx.google.com", "mx.evil.com"))
    assert [c.result for c in checks.values()] == [INCONCLUSIVE] * 3
    assert "no Authentication-Results header from a server in TRUSTED_AUTHSERV_IDS" in checks["SPF"].evidence


def test_forged_header_with_the_trusted_name_is_ignored(monkeypatch):
    # The sender can write any server name, including your provider's. Your provider's own
    # header goes on top, so the topmost one with a trusted name counts.
    monkeypatch.setattr(headers, "TRUSTED_AUTHSERV_IDS", {"mx.google.com"})
    checks = authenticate(ALL_FAIL, ALL_PASS)
    assert [c.result for c in checks.values()] == [FLAG, FLAG, FLAG]
    assert all("ignored 1 untrusted header(s)" in c.evidence for c in checks.values())


@pytest.mark.parametrize("value, expected", [
    ("pass", PASS),
    ("fail", FLAG), ("softfail", FLAG), ("permerror", FLAG),
    # Not a failure, but not verified either
    ("neutral", INCONCLUSIVE), ("none", INCONCLUSIVE), ("temperror", INCONCLUSIVE),
])
def test_spf_results(value, expected):
    assert authenticate(f"mx.google.com; spf={value} smtp.mailfrom=paypal.com")["SPF"].result == expected


@pytest.mark.parametrize("method", ["spf", "dmarc"])
@pytest.mark.parametrize("other, expected", [("fail", FLAG), ("neutral", INCONCLUSIVE)])
def test_an_added_pass_doesnt_hide_a_worse_result(method, other, expected):
    # One result per message, so a second one was added, and the worst one counts
    for results in (f"{method}={other}; {method}=pass", f"{method}=pass; {method}={other}"):
        check = authenticate(f"mx.google.com; {results}")[method.upper()]
        assert check.result == expected
        assert "More than one result reported" in check.evidence


def test_method_and_result_names_ignore_case():
    # Read without case, so a server that writes them in capitals isn't misread
    checks = authenticate("mx.google.com; SPF=Fail smtp.mailfrom=paypal.com; DKIM=Pass Header.I=@PayPal.com; "
                          "DMARC=PASS Header.From=PAYPAL.COM")
    assert [c.result for c in checks.values()] == [FLAG, PASS, PASS]
    assert checks["DKIM"].evidence == "dkim=pass for paypal.com (from mx.google.com)"


@pytest.mark.parametrize("mailfrom", [
    '"x;dkim=pass"@evil.com',
    # Encoded words are valid in an address, and decoding them gives x;dkim=pass@evil.com
    "=?utf-8?q?x=3Bdkim=3Dpass?=@evil.com",
    "=?utf-8?b?eDtka2ltPXBhc3M=?=@evil.com",
    "=?utf-8?q?x=3Bdkim=3Dpass=20header=2Ei=3D=40paypal=2Ecom?=@evil.com",
])
def test_the_envelope_address_cant_add_a_dkim_pass(mailfrom):
    # The provider copies the sender's envelope address into its header, in a comment and
    # in smtp.mailfrom, the way Gmail does
    checks = authenticate(f"mx.google.com; dkim=fail header.i=@paypal.com header.s=s1 header.b=AbCd; "
                          f"spf=pass (google.com: domain of {mailfrom} designates 203.0.113.5 as permitted "
                          f"sender) smtp.mailfrom={mailfrom}; dmarc=fail header.from=paypal.com")
    assert checks["DKIM"].result == FLAG
    assert checks["DKIM"].evidence == "dkim=fail for paypal.com (from mx.google.com)"


def test_text_in_a_comment_cant_add_a_dkim_pass():
    # Comments can hold text the sender chose, like the envelope address Gmail copies into one
    check = authenticate("mx.google.com; dkim=fail header.i=@paypal.com; "
                         "spf=pass (google.com: domain of x; dkim=pass header.i=@paypal.com) smtp.mailfrom=evil.com")["DKIM"]
    assert check.result == FLAG
    assert check.evidence == "dkim=fail for paypal.com (from mx.google.com)"


def test_methods_named_like_dkim_arent_read_as_dkim():
    check = authenticate("mx.google.com; dkim=fail; dkim-atps=pass; x-dkim=pass")["DKIM"]
    assert check.result == FLAG
    assert check.evidence == "dkim=fail (from mx.google.com)"


@pytest.mark.parametrize("auth_results, from_addr, expected", [
    # Anyone can sign with their own domain, in Gmail's or Microsoft's format
    ("mx.google.com; dkim=pass header.i=@evil.com", "service@paypal.com", INCONCLUSIVE),
    ("spf=pass smtp.mailfrom=evil.com; dkim=pass (signature was verified) header.d=evil.com;"
     "dmarc=fail header.from=paypal.com", "service@paypal.com", INCONCLUSIVE),
    ("mx.google.com; dkim=pass header.i=@sendgrid.net", "service@paypal.com", INCONCLUSIVE),
    ("mx.example.net; dkim=pass", "service@paypal.com", INCONCLUSIVE),
    ("mx.google.com; dkim=pass header.i=@paypal.com", "undisclosed-recipients:;", INCONCLUSIVE),
    # A failed From-domain signature isn't saved by a valid one from another domain
    ("mx.google.com; dkim=fail header.i=@paypal.com; dkim=pass header.i=@evil.com", "service@paypal.com", FLAG),
    # Aligned means the same organization, so subdomains count on either side
    ("mx.google.com; dkim=pass header.i=@paypal.com", "service@mail.paypal.com", PASS),
    ("mx.google.com; dkim=pass header.i=@mail.paypal.com", "service@paypal.com", PASS),
    ("spf=pass smtp.mailfrom=paypal.com; dkim=pass (signature was verified) header.d=paypal.com;dmarc=pass",
     "service@paypal.com", PASS),
    # A mailing service signing too is normal
    ("mx.google.com; dkim=pass header.i=@paypal.com; dkim=pass header.i=@sendgrid.net", "service@paypal.com", PASS),
])
def test_dkim_alignment(auth_results, from_addr, expected):
    assert authenticate(auth_results, from_addr=from_addr)["DKIM"].result == expected


def test_dkim_pass_from_another_domain_says_why_it_doesnt_count():
    check = authenticate("mx.google.com; dkim=pass header.i=@evil.com")["DKIM"]
    assert check.evidence == ("dkim=pass for evil.com (from mx.google.com). "
                              "No valid signature is from the From domain (paypal.com)")


GMAIL_DKIM_PASS = "mx.google.com; dkim=pass header.i=@paypal.com header.s=s1 header.b=AbCd"


@pytest.mark.parametrize("signature", [
    "v=1; a=rsa-sha256; d=paypal.com; s=s1; l=50; h=from:subject; bh=x; b=AbCd",
    # Folded onto two lines, and signed by a subdomain
    "v=1; a=rsa-sha256;\r\n d=mail.paypal.com; s=s1; l=50; b=abc==",
    # Spaces are allowed around = (RFC 6376)
    "v=1; d = paypal.com; s=s1; l = 50; b=x",
])
def test_dkim_signature_covering_part_of_the_body_is_inconclusive(signature):
    check = authenticate(GMAIL_DKIM_PASS, signatures=[signature])["DKIM"]
    assert check.result == INCONCLUSIVE
    assert "covers only the first 50 bytes of the body" in check.evidence


@pytest.mark.parametrize("signature", [
    # Tag names are case-sensitive (RFC 6376), so verifiers ignore L= and D=
    "v=1; d=paypal.com; s=s1; L=50; b=x",
    "v=1; D=paypal.com; s=s1; l=50; b=x",
    # Another domain's signature doesn't affect the From domain's
    "v=1; d=sendgrid.net; s=s1; l=10; b=x",
])
def test_dkim_body_length_only_counts_on_the_from_domain_signature(signature):
    assert authenticate(GMAIL_DKIM_PASS, signatures=[signature])["DKIM"].result == PASS


@pytest.mark.parametrize("auth_results, from_addr, expected", [
    # The provider checked a different From than the one shown
    ("mx.google.com; dmarc=pass header.from=evil.com", "service@paypal.com", INCONCLUSIVE),
    ("mx.google.com; dmarc=fail header.from=evil.com", "service@paypal.com", FLAG),
    ("mx.google.com; dmarc=pass header.from=mail.paypal.com", "service@mail.paypal.com", PASS),
    # Nothing to compare when the provider doesn't name the domain
    ("mx.google.com; dmarc=pass", "service@paypal.com", PASS),
])
def test_dmarc_checked_domain(auth_results, from_addr, expected):
    assert authenticate(auth_results, from_addr=from_addr)["DMARC"].result == expected


def test_dmarc_pass_for_the_other_of_two_from_headers():
    # The provider checked the second From, and the tool shows the first, like many mail clients
    check = authenticate("mx.google.com; dmarc=pass header.from=evil.com", extra=["From: x@evil.com"])["DMARC"]
    assert check.result == INCONCLUSIVE
    assert "The provider checked a different From than the one shown (paypal.com)" in check.evidence


@pytest.mark.parametrize("auth_results, source", [
    ("mx.google.com; spf=pass", "(from mx.google.com)"),
    # A version number after the server name is dropped
    ("mx.microsoft.com 1; spf=pass", "(from mx.microsoft.com)"),
    # Microsoft leaves out the server name
    ("spf=pass smtp.mailfrom=paypal.com", "(from unnamed server)"),
    # An empty name, once the comment before it is removed
    ("(mx.example.org) ; spf=pass", "(from unnamed server)"),
])
def test_server_named_in_the_evidence(auth_results, source):
    assert authenticate(auth_results)["SPF"].evidence == f"spf=pass {source}"


def reply_to_check(*reply_tos: str, from_addr="Alice <alice@example.org>") -> Check:
    return check_reply_to(parse(f"From: {from_addr}", *(f"Reply-To: {r}" for r in reply_tos)))


@pytest.mark.parametrize("reply_tos, expected", [
    ((), PASS),
    (("alice@example.org",), PASS),
    (("help@support.example.org",), PASS),
    (("x@evil.net",), FLAG),
    (("a@example.org, x@evil.net",), FLAG),
    # Every Reply-To header is checked, since it isn't defined which one a mail client uses
    (("alice@example.org", "x@evil.net"), FLAG),
    (("alice@example.org", "Alice <alice@example.org>"), PASS),
    # An empty Reply-To has no address to send replies to, and doesn't hide the ones after it
    (("<>",), PASS),
    (("undisclosed-recipients:;",), PASS),
    (("<>, x@evil.net",), FLAG),
])
def test_reply_to(reply_tos, expected):
    assert reply_to_check(*reply_tos).result == expected


def test_reply_to_evidence():
    check = reply_to_check("alice@example.org", "x@evil.net", "y@evil.net", "undisclosed")
    assert check.evidence == "Replies go to evil.net, undisclosed, not example.org"


@pytest.mark.parametrize("from_addr, reply_to, expected", [
    # Everyone on free webmail shares the domain, so the whole address is compared
    ("alice@gmail.com", "bob@gmail.com", FLAG),
    ("alice@gmail.com", "Alice@Gmail.com", PASS),
    ("Alice@Gmail.com", "alice@gmail.com", PASS),
    # The same goes for each customer's subdomain on a hosting service
    ("alice@alice.appspot.com", "x@evil.appspot.com", FLAG),
])
def test_reply_to_on_shared_domains(from_addr, reply_to, expected):
    assert reply_to_check(reply_to, from_addr=from_addr).result == expected


def test_reply_to_from_a_subdomain_sender():
    # Compared by organization, so the subdomain can be on either side
    assert reply_to_check("help@example.org", from_addr="alice@mail.example.org").result == PASS


def test_reply_to_without_a_from_domain_is_inconclusive():
    assert reply_to_check("x@evil.net", from_addr="alice").result == INCONCLUSIVE


def test_no_reply_to_passes_without_a_from_domain():
    # Replies go to the sender, whatever its address is
    assert reply_to_check(from_addr="alice").result == PASS


def test_lookalike_in_a_second_reply_to_is_checked():
    parsed = parse("From: alice@example.org", "Reply-To: alice@example.org", "Reply-To: x@paypa1.com")
    assert "paypa1.com [sender]" in check_lookalike(parsed).evidence


@pytest.mark.parametrize("return_path, expected", [
    ("<bounce@paypal.com>", PASS),
    ("<bounce@mail.paypal.com>", PASS),
    ("<bounce@evil.com>", FLAG),
    # Read as written: decoded, this would show x@paypal.com
    ("<=?utf-8?q?x=40paypal=2Ecom=3E?=@evil.com>", FLAG),
    # A null Return-Path, used on bounces
    ("<>", INCONCLUSIVE),
])
def test_return_path(return_path, expected):
    check = check_return_path(parse(f"Return-Path: {return_path}", "From: service@paypal.com"))
    assert check.result == expected
    if expected == FLAG:
        assert check.evidence == "Bounces go to evil.com, From is paypal.com"


def test_return_path_with_a_from_subdomain_passes():
    check = check_return_path(parse("Return-Path: <bounce@paypal.com>", "From: service@mail.paypal.com"))
    assert check.result == PASS


def test_return_path_missing_is_inconclusive():
    assert check_return_path(parse("From: service@paypal.com")).result == INCONCLUSIVE


def test_return_path_with_a_from_without_a_domain_is_inconclusive():
    check = check_return_path(parse("Return-Path: <bounce@evil.com>", 'From: "PayPal" <service>'))
    assert check.result == INCONCLUSIVE


@pytest.mark.parametrize("from_addr, expected", [
    ("alice@gmail.com", FLAG),
    ("alice@mail.yahoo.co.uk", FLAG),
    ("alice@example.org", PASS),
    ("alice", INCONCLUSIVE),
])
def test_free_email(from_addr, expected):
    assert check_free_email(parse(f"From: {from_addr}")).result == expected
