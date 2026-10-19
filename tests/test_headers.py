"""Tests for triage/headers.py: SPF, DKIM, DMARC, an ambiguous From, Reply-To, Return-Path, and free
webmail."""

import pytest

from triage import headers
from triage.headers import (check_ambiguous_from, check_dkim, check_dmarc, check_free_email, check_reply_to,
                            check_return_path, check_spf)
from triage.impersonation import check_lookalike
from triage.models import Check, ParsedEmail, Result
from triage.parser import parse_bytes

PASS, FLAG, INCONCLUSIVE = Result.PASS, Result.FLAG, Result.INCONCLUSIVE


def parse(*header_lines: str) -> ParsedEmail:
    # Goes through the parser, since some of these attacks depend on how a header is read
    raw = "\r\n".join([*header_lines, "To: someone@example.net", "Subject: Test", "", "Hello"])
    return parse_bytes(raw.encode())


def authentication(parsed: ParsedEmail) -> list[Check]:
    return [check_spf(parsed), check_dkim(parsed), check_dmarc(parsed)]


def authenticate(*auth_results: str, from_addr="service@paypal.com", signatures=(), extra=()) -> dict[str, Check]:
    # auth_results topmost first, the way providers stack them
    parsed = parse(*(f"Authentication-Results: {r}" for r in auth_results),
                   *(f"DKIM-Signature: {s}" for s in signatures),
                   f"From: {from_addr}", *extra)
    return {check.name: check for check in authentication(parsed)}


ALL_PASS = ("mx.google.com; dkim=pass header.i=@paypal.com header.s=s1 header.b=AbCd; "
            "spf=pass smtp.mailfrom=paypal.com; dmarc=pass header.from=paypal.com")
ALL_FAIL = ("mx.google.com; dkim=fail header.i=@paypal.com; spf=fail smtp.mailfrom=paypal.com; "
            "dmarc=fail header.from=paypal.com")


def test_all_pass():
    checks = authenticate(ALL_PASS)
    assert [c.result for c in checks.values()] == [PASS, PASS, PASS]


def test_no_header_is_inconclusive():
    checks = authentication(parse("From: service@paypal.com"))
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


def gmail_header(mailfrom: str) -> str:
    # The provider copies the sender's envelope address into its header, in a comment and
    # in smtp.mailfrom, the way Gmail does
    return (f"mx.google.com; dkim=fail header.i=@paypal.com header.s=s1 header.b=AbCd; "
            f"spf=pass (google.com: domain of {mailfrom} designates 203.0.113.5 as permitted "
            f"sender) smtp.mailfrom={mailfrom}; dmarc=fail header.from=paypal.com")


@pytest.mark.parametrize("mailfrom", [
    '"x;dkim=pass"@evil.com',
    # An escaped quote doesn't end the quoted part, or an escaped bracket the comment
    '"x\\";dkim=pass header.i=@paypal.com"@evil.com',
    '"x\\);dkim=pass header.i=@paypal.com"@evil.com',
    # Encoded words are valid in an address, and decoding them gives x;dkim=pass@evil.com
    "=?utf-8?q?x=3Bdkim=3Dpass?=@evil.com",
    "=?utf-8?b?eDtka2ltPXBhc3M=?=@evil.com",
    "=?utf-8?q?x=3Bdkim=3Dpass=20header=2Ei=3D=40paypal=2Ecom?=@evil.com",
])
def test_the_envelope_address_cant_add_a_dkim_pass(mailfrom):
    checks = authenticate(gmail_header(mailfrom))
    assert checks["DKIM"].result == FLAG
    assert checks["DKIM"].evidence == "dkim=fail for paypal.com (from mx.google.com)"


@pytest.mark.parametrize("mailfrom", [
    # One quote, whose copy in the comment mustn't pair with the copy after it
    '"x;dkim=pass header.i=@paypal.com',
    # Outside quotes and comments a backslash is just a character, so the quote after it counts
    'x\\";dkim=pass header.i=@paypal.com',
    # A bracket, which opens a comment inside Gmail's and leaves it open
    'x(;dkim=pass header.i=@paypal.com',
])
def test_a_quote_or_comment_left_open_hides_the_rest_and_says_so(mailfrom):
    # The rest could be the sender's text, so it isn't read, and the report says why dmarc=fail is missing
    checks = authenticate(gmail_header(mailfrom))
    assert checks["DKIM"].evidence == ("dkim=fail for paypal.com (from mx.google.com, read up to a quote or "
                                       "comment left open)")
    assert checks["DMARC"].evidence == "Not reported (from mx.google.com, read up to a quote or comment left open)"


def test_a_header_cut_short_cant_pass():
    # Unquoted, the address can add a pass and then hide the real result, and which passes are
    # real can't be told
    checks = authenticate('mx.google.com; dkim=pass header.i=@paypal.com; spf=pass '
                          'smtp.mailfrom=x;dmarc=pass;"@evil.com; dmarc=fail header.from=paypal.com')
    assert [checks[name].result for name in ("SPF", "DKIM", "DMARC")] == [INCONCLUSIVE] * 3
    assert checks["DMARC"].evidence == ("dmarc=pass (from mx.google.com, read up to a quote or comment left open). "
                                        "The pass could be text the sender added, with the real result hidden after it")


@pytest.mark.parametrize("comment", [
    "(google.com: domain of x; dkim=pass header.i=@paypal.com)",
    # A comment inside it, which doesn't end it
    "(domain of x (y) ; dkim=pass header.i=@paypal.com )",
])
def test_text_in_a_comment_cant_add_a_dkim_pass(comment):
    # Comments can hold text the sender chose, like the envelope address Gmail copies into one
    check = authenticate(f"mx.google.com; dkim=fail header.i=@paypal.com; spf=pass {comment} "
                         "smtp.mailfrom=evil.com")["DKIM"]
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
    # A Reply-To the tool can't read doesn't hide the one before it
    (("x@evil.net", "y@evil.net (Support"), FLAG),
])
def test_reply_to(reply_tos, expected):
    assert reply_to_check(*reply_tos).result == expected


def test_reply_to_evidence():
    check = reply_to_check("alice@example.org", "x@evil.net", "y@evil.net", "undisclosed")
    assert check.evidence == "Replies go to evil.net, undisclosed, not example.org"
    check = reply_to_check(", ".join(f"x@d{n}.com" for n in range(6)))
    assert check.evidence == "Replies go to d0.com, d1.com, d2.com, d3.com, d4.com (and 1 more), not example.org"


def test_several_encoded_reply_to_addresses_are_one_caveat():
    check = reply_to_check("=?utf-8?q?a?=@evil.net, =?utf-8?q?b?=@evil.net")
    assert check.result == FLAG
    assert check.caveats == [
        "2 addresses have encoded text in them, which isn't allowed in an address. Some mail clients decode them "
        "and show a@evil.net for =?utf-8?q?a?=@evil.net; b@evil.net for =?utf-8?q?b?=@evil.net."]


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


ENCODED = "=?utf-8?q?x=40evil=2Enet?=@example.org"
SHOWN = (f"{ENCODED} has encoded text in it, which isn't allowed in an address. Some mail clients decode it "
         "and show x@evil.net@example.org")


@pytest.mark.parametrize("reply_tos, result", [
    (("alice@example.org", "alice@example.org"), PASS),
    (("alice@example.org", "x@evil.net"), FLAG),
])
def test_several_reply_to_headers_are_a_caveat_on_any_result(reply_tos, result):
    check = reply_to_check(*reply_tos)
    assert (check.result, check.caveats) == (result, [
        "The email has 2 Reply-To headers, where one is allowed. Which one a mail client uses isn't defined, "
        "so the addresses in all of them were checked."])


def test_encoded_reply_to_that_matches_as_written_is_inconclusive():
    check = reply_to_check(ENCODED)
    assert check.result == INCONCLUSIVE
    assert check.evidence == f"Reply-To matches the sender (example.org) as written. {SHOWN}"


@pytest.mark.parametrize("from_addr, result", [
    # The address as written already goes elsewhere
    ("Alice <alice@paypal.com>", FLAG),
    # No From domain to compare against
    ("undisclosed", INCONCLUSIVE),
])
def test_encoded_reply_to_is_a_caveat_when_it_already_has_a_result(from_addr, result):
    check = reply_to_check(ENCODED, from_addr=from_addr)
    assert (check.result, check.caveats) == (result, [f"{SHOWN}."])


@pytest.mark.parametrize("from_lines, evidence", [
    (("From: service@paypal.com", "From: x@evil.com"),
     "2 From headers (service@paypal.com; x@evil.com). Mail clients and DMARC checks don't always use the "
     "same one"),
    (("From: service@paypal.com, x@evil.com",),
     "From has 2 addresses (service@paypal.com; x@evil.com), and no Sender header names who sent it. Mail "
     "clients and DMARC checks don't always use the same one"),
    # Several authors the way the standard allows, which mail clients can still show either way
    (("From: service@paypal.com, x@evil.com", "Sender: x@evil.com"),
     "From has 2 addresses (service@paypal.com; x@evil.com). Mail clients and DMARC checks don't always use "
     "the same one"),
    # Both findings are given, not just the first
    ((f"From: alice@example.org, {ENCODED}",),
     f"From has 2 addresses (alice@example.org; {ENCODED}), and no Sender header names who sent it. Mail "
     f"clients and DMARC checks don't always use the same one. {SHOWN}"),
    ((f"From: {ENCODED}",), SHOWN),
    # Neither From has an address to list
    (("From: <>", "From: <>"), "2 From headers. Mail clients and DMARC checks don't always use the same one"),
])
def test_ambiguous_from(from_lines, evidence):
    assert check_ambiguous_from(parse(*from_lines)) == [
        Check("Ambiguous From", FLAG, "very strong", evidence)]


def test_one_plain_from_isnt_listed():
    assert check_ambiguous_from(parse("From: PayPal <service@paypal.com>")) == []


def test_reply_to_without_a_from_domain_is_inconclusive():
    assert reply_to_check("x@evil.net", from_addr="alice").result == INCONCLUSIVE


def test_no_reply_to_passes_without_a_from_domain():
    # Replies go to the sender, whatever its address is
    assert reply_to_check(from_addr="alice").result == PASS


def test_lookalike_in_a_second_reply_to_is_checked():
    parsed = parse("From: alice@example.org", "Reply-To: alice@example.org", "Reply-To: x@paypa1.com")
    assert "paypa1.com [sender]" in check_lookalike(parsed).evidence


def test_lookalike_in_a_second_sender_header_is_checked():
    # Outlook shows the Sender next to the From
    parsed = parse("From: alice@example.org", "Sender: alice@example.org", "Sender: x@paypa1.com")
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


@pytest.mark.parametrize("return_paths, found", [
    # A planted one matching the From, above the provider's own as Microsoft 365 orders them,
    # would otherwise pass
    (("<bounce@paypal.com>", "<x@evil.com>"), "2 Return-Path headers, with bounce@paypal.com; x@evil.com"),
    # An empty first one would otherwise read as no Return-Path at all
    (("<>", "<bounce@paypal.com>"), "2 Return-Path headers, with bounce@paypal.com"),
    (("<>", "<>"), "2 Return-Path headers"),
])
def test_more_than_one_return_path_is_inconclusive(return_paths, found):
    check = check_return_path(parse(*(f"Return-Path: {rp}" for rp in return_paths), "From: service@paypal.com"))
    assert check.result == INCONCLUSIVE
    assert check.evidence == (f"The email has {found}. Your provider adds one, but not always first, so which is "
                              "its own can't be told")


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
