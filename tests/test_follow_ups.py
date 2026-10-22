"""Tests for triage/report/follow_ups.py: the follow-ups picked from what was found."""

from pathlib import Path

from triage.checks import run_checks
from triage.checks.lookups import check_domain_age
from triage.models import Address, Attachment, Check, Indicators, Link, LookupStatus, ParsedEmail, Reputation
from triage.reading.parser import parse_bytes, parse_file
from triage.report.follow_ups import suggest_follow_ups
from triage.report.patterns import find_patterns

FIXTURES = Path(__file__).parent / "fixtures"
FROM = [Address("", "a@evil.com", "evil.com")]
FIND = "Find other recipients of the same message (search by its Message-ID or sender)"
REPLIES = "Check whether anyone replied (search sent mail for the address replies go to)"
REPLIES_BY_HAND = "Check whether anyone replied. The tool couldn't read the Reply-To, so find where replies go by hand"
CLICKS = ("Check whether anyone clicked a link (proxy or DNS logs for the indicator domains). If anyone entered a "
          "password, reset it and end their sessions")
EDR = "Search EDR for the attachments' SHA-256, to find computers that saved or opened them"
BLOCK = "Block the lookalike or newly registered domains"
BLOCK_WEBMAIL = "Block the sender's webmail address, not the whole webmail domain"
BLOCK_ANY = ("Block the attacker's own sender address and domains, not spoofed or shared ones like a webmail or "
             "link-shortening service")
TELL_IMPERSONATED = "Tell whoever the display name pretends to be, like an executive or a brand's phishing team"
TELL_SENDER = ("Tell the sender's organization its account or service may be misused, instead of blocking its "
               "domain")


def suggested(checks=(), found=None, **fields) -> list[tuple[str, dict]]:
    parsed = ParsedEmail(**{"from_addrs": FROM, **fields})
    patterns = find_patterns(parsed, list(checks))
    return [(f.text, f.values) for f in suggest_follow_ups(parsed, list(checks), patterns, found or Indicators())]


def test_what_every_email_gets():
    assert suggested(message_id="<1@evil.com>", sender=[Address("", "s@evil.net", "evil.net")]) == [
        (FIND, {"Message-ID": ["<1@evil.com>"], "From": ["a@evil.com"], "Sender": ["s@evil.net"]}),
        (REPLIES, {"From": ["a@evil.com"]}),
        (BLOCK_ANY, {})]
    # Nothing to search with is left out, not shown empty
    assert suggested(from_addrs=[])[:2] == [(FIND, {}), (REPLIES, {})]


def test_replies_are_searched_for_where_they_go():
    reply_to = [Address("", "r@evil.net", "evil.net"), Address("", "q@evil.org", "evil.org")]
    assert suggested(reply_to=reply_to)[1] == (REPLIES, {"Reply-To": ["r@evil.net", "q@evil.org"]})
    # Replies don't go to the From, so it isn't offered in place of a Reply-To the tool couldn't read
    assert suggested(unread_address_headers=["Reply-To"])[1] == (REPLIES_BY_HAND, {})
    # As the parser names the header
    parsed = parse_bytes(b'From: a@evil.com\nReply-To: "x" <a@b@evil.net>\n\nHi\n')
    assert suggest_follow_ups(parsed, [], [], Indicators())[1].text == REPLIES_BY_HAND
    # Like the summary, the ones read are shown
    assert suggested(reply_to=reply_to[:1], unread_address_headers=["Reply-To"])[1] == (
        REPLIES, {"Reply-To": ["r@evil.net"]})
    assert suggested(unread_address_headers=["Sender"])[1] == (REPLIES, {"From": ["a@evil.com"]})


def test_clicks_and_files_are_searched_for_only_when_there_are_some():
    attachment = Attachment("a.pdf", "application/pdf", 5, "f" * 64)
    assert [text for text, _ in suggested(found=Indicators(urls=["https://evil.com/"]), attachments=[attachment])] == [
        FIND, REPLIES, CLICKS, EDR, BLOCK_ANY]
    # A domain with no link, like the From's, isn't something anyone could click
    assert [text for text, _ in suggested(found=Indicators(domains=["evil.com"]))] == [FIND, REPLIES, BLOCK_ANY]


def test_only_lookalike_and_new_domains_are_blocked():
    checks = [Check("Lookalike domain", "flag", "strong", "", domains=["p\u0430ypal.com", "paypa1.com."]),
              Check("Newly registered domain", "flag", "medium", "", domains=["paypa1.com", "new.com"]),
              # Brands own domains like these too
              Check("Brand joined to a word", "flag", "weak", "", domains=["paypalsecure.com"])]
    # As the indicators write them, in the xn-- form and without the dot at the end, and once each
    assert suggested(checks)[-1] == (BLOCK, {"Domains": ["xn--pypal-4ve.com", "paypa1.com", "new.com"]})
    assert suggested(checks[1:2])[-1] == (BLOCK, {"Domains": ["paypa1.com", "new.com"]})
    assert suggested(checks[2:])[-1] == (BLOCK_ANY, {})


def test_a_webmail_sender_is_blocked_by_its_address():
    webmail = Check("Free webmail sender", "flag", "weak", "")
    froms = [Address("", "ceo@example.org", "example.org"), Address("", "x@gmail.com", "gmail.com")]
    # Another From can be someone's real address the attacker put there
    assert suggested([webmail], from_addrs=froms)[-1] == (BLOCK_WEBMAIL, {"From": ["x@gmail.com"]})
    # With a lookalike too, both are named, so the general line isn't needed
    lookalike = Check("Lookalike domain", "flag", "strong", "", domains=["paypa1.com"])
    assert suggested([lookalike, webmail], from_addrs=froms)[-2:] == [
        (BLOCK, {"Domains": ["paypa1.com"]}), (BLOCK_WEBMAIL, {"From": ["x@gmail.com"]})]


def test_whoever_the_display_name_pretends_to_be_is_told():
    assert suggested([Check("Display name mismatch", "flag", "medium", "")])[-1] == (TELL_IMPERSONATED, {})
    assert suggested([Check("Display name mismatch", "pass", "medium", "")])[-1] == (BLOCK_ANY, {})


def test_a_sender_that_may_be_hacked_is_told_instead_of_blocked():
    checks = [Check("DMARC", "pass", "strong", ""),
              Check("Lookalike domain", "flag", "strong", "", domains=["paypa1.com"])]
    org = [Address("", "a@example.org", "example.org")]
    assert suggested(checks, from_addrs=org, links=[Link("https://paypa1.com/", "")])[-2:] == [
        (BLOCK, {"Domains": ["paypa1.com"]}), (TELL_SENDER, {})]
    # The lookalike is the sender's own domain, so there's no one to tell
    assert suggested(checks, from_addrs=[Address("", "a@paypa1.com", "paypa1.com")])[-1] == (
        BLOCK, {"Domains": ["paypa1.com"]})


def test_the_checks_are_matched_by_their_real_names():
    # A renamed check would quietly drop its follow-up
    parsed = parse_file(FIXTURES / "suspicious.eml")
    today = [Reputation("VirusTotal", LookupStatus.FOUND, "", {"registered": "2027-01-15"})]
    checks = run_checks(parsed) + [check_domain_age(Indicators(domains=["new.com"]), {"new.com": today})]
    follow_ups = suggest_follow_ups(parsed, checks, find_patterns(parsed, checks), Indicators())
    assert [(f.text, f.values) for f in follow_ups][-2:] == [
        (BLOCK, {"Domains": ["paypa1.com", "new.com"]}), (TELL_IMPERSONATED, {})]
    parsed = parse_file(FIXTURES / "ceo_fraud.eml")
    checks = run_checks(parsed)
    follow_ups = suggest_follow_ups(parsed, checks, find_patterns(parsed, checks), Indicators())
    assert (follow_ups[-1].text, follow_ups[-1].values) == (BLOCK_WEBMAIL, {"From": ["ceo.fraud.example@gmail.com"]})
