"""Tests for triage/impersonation.py: lookalike domains, brands joined to words, and display names."""

import pytest

from triage import impersonation
from triage.impersonation import (LONG_NAME_LENGTH, MIN_NAME_LENGTH, _english_words, _one_typo_apart,
                                  check_brand_joined, check_display_name, check_lookalike)
from triage.lists import BRANDS
from triage.models import Address, Link, ParsedEmail, Result


def link_to(domain: str) -> ParsedEmail:
    return ParsedEmail(links=[Link(href=f"https://{domain}/", text="")])


def sent_as(display_name: str, domain: str = "evil.com") -> ParsedEmail:
    return ParsedEmail(from_addrs=[Address(display_name, f"someone@{domain}", domain)])


def known_limitation(*values, reason: str):
    # Written as what should happen, so it fails today. See Limitations in the README.
    # Only a failed assert counts, so a test that crashes isn't hidden as a known limitation.
    return pytest.param(*values, marks=pytest.mark.xfail(reason=reason, raises=AssertionError))


@pytest.mark.parametrize("a, b, expected", [
    ("paypal", "paypai", True),    # one letter wrong
    ("paypal", "papyal", True),    # two neighbors swapped
    ("paypal", "paypall", True),   # one added
    ("paypal", "paypa", True),     # one missing
    ("paypal", "paypal", False),
    ("paypal", "pyapla", False),   # two swaps
    ("paypal", "paypaii", False),  # wrong and added
    ("paypal", "payp", False),
])
def test_one_typo_apart(a, b, expected):
    assert _one_typo_apart(a, b) == expected
    assert _one_typo_apart(b, a) == expected


LOOKALIKE_DOMAINS = [
    # Digits for letters, also on another TLD or with the name in a subdomain
    ("paypa1.com", "paypal.com"),
    ("paypa1.xyz", "paypal.com"),
    ("paypa1.com.evil.net", "paypal.com"),
    ("g00gle.com", "google.com"),
    ("m1crosoft.com", "microsoft.com"),
    ("pay-pal.com", "paypal.com"),
    # Letter pairs: rn and nn for m, vv for w, cl for d
    ("rnicrosoft.com", "microsoft.com"),
    ("arnazon.com", "amazon.com"),
    ("annazon.com", "amazon.com"),
    ("nnicrosoft.com", "microsoft.com"),
    ("bankofannerica.com", "bankofamerica.com"),
    ("vvellsfargo.com", "wellsfargo.com"),
    ("clocusign.com", "docusign.com"),
    ("c1ocusign.com", "docusign.com"),
    # Read without the pairs too: nn makes linnedin limedin, which hides the typo
    ("linnedin.com", "linkedin.com"),
    # A typo on top of a digit or a letter pair still flags
    ("mlcrosoft.com", "microsoft.com"),
    ("rn1crosoft.com", "microsoft.com"),
    # Cyrillic and Greek letters, written as they are or as punycode
    ("p\N{CYRILLIC SMALL LETTER A}ypal.com", "paypal.com"),
    ("xn--pypal-4ve.com", "paypal.com"),
    ("g\N{GREEK SMALL LETTER OMICRON}\N{GREEK SMALL LETTER OMICRON}gle.com", "google.com"),
    ("\N{CYRILLIC SMALL LETTER KOMI DE}ocu\N{CYRILLIC SMALL LETTER DZE}ign.com", "docusign.com"),
    # Invisible characters in the host
    ("paypa\N{ZERO WIDTH SPACE}1.com", "paypal.com"),
    ("paypa\N{ZERO WIDTH NON-JOINER}1.com", "paypal.com"),
    # Multi-word names split by dashes or a dot, spelled right or with a typo
    ("wells-fargo-login.com", "wellsfargo.com"),
    ("wells-farqo-login.com", "wellsfargo.com"),
    ("wellsfarqo.com", "wellsfargo.com"),
    ("wells.fargo-alerts.com", "wellsfargo.com"),
    # Social brands share Meta's domain list, and each is named by its own domain. So is
    # Office 365 in Microsoft's.
    ("lnstagram.com", "instagram.com"),
    ("whatsap.com", "whatsapp.com"),
    ("linkedln.com", "linkedin.com"),
    ("0ffice365.com", "office365.com"),
    # A short name matches spelled right, with digits, or with a typo that isn't a word
    ("meta-business-support.com", "meta.com"),
    ("m3ta.com", "meta.com"),
    ("metta.com", "meta.com"),
    ("metq.com", "meta.com"),
    # Names of six letters or more are typo-checked in subdomains too
    ("login.amazom.evil.net", "amazon.com"),
    # Short names are typo-checked in the registered name
    ("appie.com", "apple.com"),
    ("clase.com", "chase.com"),
    # A long name's typo counts even when it's a word
    ("goggle.com", "google.com"),
    known_limitation("g\N{ARMENIAN SMALL LETTER OH}\N{ARMENIAN SMALL LETTER OH}gle.com", "google.com",
                     reason="Armenian letters aren't swapped"),
    # Two of each, since a single one is already caught as a typo
    known_limitation("\N{LATIN SMALL LETTER SCRIPT G}oo\N{LATIN SMALL LETTER SCRIPT G}le.com",
                     "google.com", reason="Latin variants aren't swapped"),
    known_limitation("l\N{LATIN SMALL LETTER DOTLESS I}nked\N{LATIN SMALL LETTER DOTLESS I}n.com",
                     "linkedin.com", reason="Latin variants aren't swapped"),
    known_limitation("wells.farqo-alerts.com", "wellsfargo.com",
                     reason="a multi-word name split by a dot isn't typo-checked"),
]


@pytest.mark.parametrize("domain, real_domain", LOOKALIKE_DOMAINS)
def test_lookalike_domain_flags(domain, real_domain):
    check = check_lookalike(link_to(domain))
    assert check.result == Result.FLAG
    assert f"isn't {real_domain}" in check.evidence


def _one_letter_typos(name: str) -> set[str]:
    typos = set()
    for i in range(len(name)):
        typos.add(name[:i] + name[i + 1:])
        typos.add(name[:i] + name[i] + name[i:])
        typos.add(name[:i] + name[i + 1:i + 2] + name[i] + name[i + 2:])
    typos.discard(name)
    return typos


# A set, since two brands could share a typo and pytest refuses a repeated test case. An English
# word near a short name is left to the analyst instead.
@pytest.mark.parametrize("domain", sorted({
    f"{typo}.com"
    for brand in BRANDS if len(brand.replace(" ", "")) >= MIN_NAME_LENGTH
    for typo in _one_letter_typos(brand.replace(" ", ""))
    if len(brand.replace(" ", "")) >= LONG_NAME_LENGTH or typo not in _english_words()
}))
def test_every_dropped_doubled_or_swapped_letter_flags(domain):
    assert check_lookalike(link_to(domain)).result == Result.FLAG


@pytest.mark.parametrize("domain, evidence", [
    ("paypal-secure.com", "paypal-secure.com [link] contains 'paypal' but isn't paypal.com"),
    ("wellsfargo-login.com", "wellsfargo-login.com [link] contains 'wells fargo' but isn't wellsfargo.com"),
    ("rnicrosoft.com", "rnicrosoft.com [link] spells 'microsoft' with lookalike characters but isn't microsoft.com"),
    ("paypai.com", "paypai.com [link] has a typo of 'paypal' but isn't paypal.com"),
    # A punycode domain is shown the way the reader sees it
    ("xn--pypal-4ve.com", "xn--pypal-4ve.com (displays as p\N{CYRILLIC SMALL LETTER A}ypal.com) [link] "
                          "spells 'paypal' with lookalike characters but isn't paypal.com"),
])
def test_evidence_says_how_the_domain_looks_alike(domain, evidence):
    assert check_lookalike(link_to(domain)).evidence == evidence


def test_flags_name_their_domains():
    # So --enrich looks them up first
    parsed = ParsedEmail(links=[Link("https://paypa1.com/", ""), Link("https://paypalsecure.com/", ""),
                                Link("https://example.com/", "")])
    assert check_lookalike(parsed).domains == ["paypa1.com"]
    assert check_brand_joined(parsed).domains == ["paypalsecure.com"]
    assert check_lookalike(link_to("example.com")).domains == []


@pytest.mark.parametrize("domain, real_domain", [
    ("login.microsoftonline.com.evil.net", "microsoftonline.com"),
    ("facebookmail.com.evil.net", "facebookmail.com"),
    ("microsoft.com-review.example.org", "microsoft.com"),
])
def test_real_domain_in_front_flags(domain, real_domain):
    check = check_lookalike(link_to(domain))
    assert check.result == Result.FLAG
    assert f"puts the real domain {real_domain} in front of" in check.evidence


@pytest.mark.parametrize("domain", [
    # The brands' own domains, with subdomains and the other domains their mail uses
    "paypal.com", "mail.paypal.com", "amazon.co.uk", "facebookmail.com", "mail.instagram.com", "lnkd.in",
    # The TLD isn't compared, so a brand's own TLD doesn't match its name
    "applecard.apple",
    # Free webmail is a real provider, with its own check
    "gmail.com",
    # Ordinary words with letter pairs in them
    "cloudflare.com", "connect.example.com", "clinic-news.com", "cleveland.com", "classroom.org",
    "channel4.com", "cornell.edu", "learnmore.io", "annual-report.com", "tennis.org", "inn.com",
    "cnn.com", "pinnacle.com", "cinnamon.com", "hannah-design.com",
    # An allowed name one letter from a short name, and a word two letters from a long one
    "mega.nz", "linked.com",
    # Short names aren't typo-checked in subdomains, where a phisher would write the real name
    "appel.example.com", "chose.example.com",
    # A real domain inside a longer word, like a CDN host for purchase.com
    "www.purchase.com.edgekey.net",
])
def test_ordinary_domain_passes(domain):
    assert check_lookalike(link_to(domain)).result == Result.PASS


@pytest.mark.parametrize("domain, word", [
    ("appel.com", "appel"), ("apply-now.com", "apply"), ("chaser-games.com", "chaser"), ("beta.com", "beta"),
])
def test_an_english_word_one_letter_from_a_short_name_is_inconclusive(domain, word):
    # It can be a typosquat (appel.com) or just the word (apply.com), and the spelling can't tell
    check = check_lookalike(link_to(domain))
    assert check.result == Result.INCONCLUSIVE
    assert check.evidence.startswith(f"{domain} [link] is one letter from ")
    assert f", but '{word}' is also an English word. " in check.evidence


def test_next_to_a_flag_an_english_word_is_a_caveat():
    check = check_lookalike(ParsedEmail(links=[Link("https://paypa1.com/", ""), Link("https://appel.com/", "")]))
    assert check.result == Result.FLAG
    assert check.caveats == ["appel.com [link] is one letter from 'apple', but 'appel' is also an English word. A "
                             "name that short is one letter from many words, so check it by hand."]


def test_allowed_names_pass(monkeypatch):
    # Real names that aren't English words, like Chicago's Metra
    assert check_lookalike(link_to("metra.com")).result == Result.FLAG
    monkeypatch.setattr(impersonation, "ALLOWED_NAMES", {"metra"})
    assert check_lookalike(link_to("metra.com")).result == Result.PASS
    assert check_brand_joined(link_to("applebees.com")).result == Result.INCONCLUSIVE


def test_names_under_four_letters_arent_typo_checked(monkeypatch):
    # Nearly every short label is one letter from them
    monkeypatch.setattr(impersonation, "OWN_NAMES", {"ibm"})
    monkeypatch.setattr(impersonation, "OWN_DOMAINS", ["ibm.com"])
    assert check_lookalike(link_to("ibn.com")).result == Result.PASS
    assert check_lookalike(link_to("ibm-login.com")).result == Result.FLAG
    assert check_brand_joined(link_to("ibmlogin.com")).result == Result.PASS


@pytest.mark.parametrize("domain", [
    "paypalsecure.com", "mypaypal.com",
    # nn would make these amazomow and limedinnews, which no longer contain the brand
    "amazonnow.com", "linkedinnews.com",
    "docusignnow.com",
    # A name of several words is joined without its spaces
    "mywellsfargo.com",
    # Short names joined to a word phishers use
    "appleid.com", "applesupport.com", "mymeta.com", "metaverify.com", "fedexdelivery.com", "chaseonline.com",
])
def test_brand_joined_to_a_word_flags(domain):
    check = check_brand_joined(link_to(domain))
    assert check.result == Result.FLAG


@pytest.mark.parametrize("domain", [
    # The name on its own is the lookalike check's job
    "paypal-secure.com",
    # A short name inside an English word or an allowed name
    "pineapple.com", "purchase.com", "metal.com", "metadata.com",
    "paypal.com",
])
def test_brand_joined_passes(domain):
    assert check_brand_joined(link_to(domain)).result == Result.PASS


def test_a_short_name_joined_to_another_word_is_inconclusive():
    # Like Appleby Farms, a real name holding a short brand name
    check = check_brand_joined(link_to("applebyfarms.com"))
    assert (check.result, check.evidence) == (
        Result.INCONCLUSIVE, "applebyfarms.com [link] has 'apple' inside a word that isn't in the word list. A name "
        "that short is often part of a real name, so check it by hand.")
    links = [Link("https://appleid.com/", ""), Link("https://applebyfarms.com/", "")]
    check = check_brand_joined(ParsedEmail(links=links))
    assert check.result == Result.FLAG
    assert check.caveats[0].startswith("applebyfarms.com [link] has 'apple' inside a word")


@pytest.mark.parametrize("display_name", [
    "PayPal", "PAYPAL", "Wells-Fargo", "WellsFargo", "Microsoft Office 365",
    # Checked after microsoft, which shares its domains
    "Office 365 Support",
    # Capitals that look like lowercase letters: I for l, Cyrillic I and Greek Iota for l,
    # Cyrillic soft sign for b
    "PayPaI", "PAYPAI", "GoogIe Security", "WeIls Fargo",
    "PayPa\N{CYRILLIC CAPITAL LETTER BYELORUSSIAN-UKRAINIAN I}",
    "PayPa\N{GREEK CAPITAL LETTER IOTA}",
    "PayPa\N{FULLWIDTH LATIN CAPITAL LETTER I}",
    "Face\N{CYRILLIC CAPITAL LETTER SOFT SIGN}ook",
    "FACE\N{CYRILLIC CAPITAL LETTER SOFT SIGN}OOK",
    # Digits, letter pairs, Cyrillic and Greek letters
    "PayPa1", "Arnazon",
    "P\N{CYRILLIC SMALL LETTER A}yPal",
    "PayPa\N{CYRILLIC SMALL LETTER PALOCHKA}",
    "Micro\N{CYRILLIC SMALL LETTER DZE}oft",
    "G\N{GREEK SMALL LETTER OMICRON}\N{GREEK SMALL LETTER OMICRON}gle",
    # Invisible characters and fullwidth letters
    "Pay\N{ZERO WIDTH SPACE}Pal", "Pay\N{SOFT HYPHEN}Pal",
    "\N{FULLWIDTH LATIN CAPITAL LETTER P}\N{FULLWIDTH LATIN SMALL LETTER A}yPal",
    # An address that hides the real sender in many mail clients
    "security@paypal.com", "security\N{FULLWIDTH COMMERCIAL AT}paypal.com",
    known_limitation("Pay Pal", reason="a brand split into two words isn't matched in a display name"),
    known_limitation("Linkedln", reason="brand names are lowercase, so a lowercase l for a capital I isn't swapped"),
    known_limitation("\N{CYRILLIC CAPITAL LETTER EM}icrosoft", reason="capitals that only look Latin in uppercase"),
])
def test_display_name_claiming_a_brand_flags(display_name):
    assert check_display_name(sent_as(display_name)).result == Result.FLAG


@pytest.mark.parametrize("display_name", [
    # Capital I as written: these don't become lan, lT or lnfo
    "Ian Wright", "IT Support", "Info Desk", "Ivan Ivanov",
    # Letter pairs and words near brand names
    "Arnold Clark", "Corner Bakery", "Hannah Glenn", "Team 365", "MetaMask",
    # Cyrillic soft sign reads as b only where it matches a brand
    "\N{CYRILLIC CAPITAL LETTER DE}\N{CYRILLIC CAPITAL LETTER O}\N{CYRILLIC CAPITAL LETTER EL}"
    "\N{CYRILLIC CAPITAL LETTER SOFT SIGN}",
    # Emoji sequences are joined by invisible characters
    "Dev \N{MAN}\N{ZERO WIDTH JOINER}\N{PERSONAL COMPUTER}",
    # An address at the sender's own organization, and a handle, which isn't an address
    "support@evil.com", "support@mail.evil.com", "Jane Doe @jdoe",
    # Brand names inside other words
    "Pineapple Express", "Applebee's Grill",
    known_limitation("Apple Valley Dental", reason="brand names are matched as whole words"),
])
def test_ordinary_display_name_passes(display_name):
    assert check_display_name(sent_as(display_name)).result == Result.PASS


@pytest.mark.parametrize("display_name, domain", [
    ("PayPal", "paypal.com"),
    ("PayPal Service", "mail.paypal.com"),
    # Meta's brands share one domain list
    ("Instagram", "facebookmail.com"),
])
def test_display_name_from_the_brand_passes(display_name, domain):
    assert check_display_name(sent_as(display_name, domain)).result == Result.PASS


def test_display_name_from_another_brand_flags():
    # Only the brand the sender's domain belongs to is skipped
    assert check_display_name(sent_as("DocuSign", "microsoft.com")).result == Result.FLAG


def test_no_display_name_passes():
    assert check_display_name(sent_as("")).evidence == "No display name"


def test_organization_is_named_once():
    # "microsoft" and "office 365" share Microsoft's domains, so each check reports them once,
    # and still checks the brands listed after them (docusign)
    assert check_display_name(sent_as("Microsoft Office 365 DocuSign")).evidence.count("mentions") == 2
    assert check_lookalike(link_to("microsoft-office365-docusign.com")).evidence.count("[link]") == 2
    assert check_brand_joined(link_to("mymicrosoftoffice365.com")).evidence.count("[link]") == 1


def test_link_to_the_real_brand_doesnt_end_the_check():
    # Phishing often links to the real site too, for a logo or privacy page
    parsed = ParsedEmail(links=[Link("https://help.paypal.com/privacy", ""), Link("https://paypa1.com/login", "")])
    assert check_lookalike(parsed).result == Result.FLAG


def test_display_name_from_an_address_without_a_domain():
    # The evidence names the whole address when there's no domain to show
    check = check_display_name(ParsedEmail(from_addrs=[Address("PayPal", "service", "")]))
    assert check.evidence == '"PayPal" mentions "paypal" but the mail is from service'


def test_display_name_shows_the_address_it_hides():
    check = check_display_name(sent_as("security@pay\N{ZERO WIDTH SPACE}pal.com"))
    assert "shows an address at paypal.com but the mail is from evil.com" in check.evidence


# impersonation.py imports the lists by name, so they're replaced there, not in lists.py

@pytest.mark.parametrize("display_name", [
    "Ian Wright", "IAN WRIGHT", "Wright, Ian", "Ian Wright (CEO)",
    # A lowercase l for the capital I
    "lan Wright",
])
def test_executive_name_from_outside_flags(monkeypatch, display_name):
    monkeypatch.setattr(impersonation, "EXECUTIVES", {"Ian Wright"})
    check = check_display_name(sent_as(display_name, "gmail.com"))
    assert check.result == Result.FLAG
    assert "uses executive Ian Wright's name" in check.evidence


@pytest.mark.parametrize("display_name", [
    "Ivan Wrighton",
    # Every part of the name, each as a whole word
    "Brian Wright", "Ian Wrighton", "Ian Smith",
])
def test_executive_name_needs_whole_words(monkeypatch, display_name):
    monkeypatch.setattr(impersonation, "EXECUTIVES", {"Ian Wright"})
    assert check_display_name(sent_as(display_name, "gmail.com")).result == Result.PASS


def test_executive_name_from_own_domain_passes(monkeypatch):
    monkeypatch.setattr(impersonation, "EXECUTIVES", {"Ian Wright"})
    monkeypatch.setattr(impersonation, "OWN_DOMAINS", ["contoso.com"])
    assert check_display_name(sent_as("Ian Wright", "mail.contoso.com")).result == Result.PASS


@pytest.fixture
def own_organization(monkeypatch):
    monkeypatch.setattr(impersonation, "OWN_NAMES", {"ken nelson"})
    monkeypatch.setattr(impersonation, "OWN_DOMAINS", ["kennelson.com"])


@pytest.mark.parametrize("domain, expected", [
    ("kennelsen-login.com", Result.FLAG),
    # Spaces are removed before pairs, so nn across the two words counts
    ("kemelson.com", Result.FLAG),
    ("kennelson.net", Result.FLAG),
    ("mail.kennelson.com", Result.PASS),
])
def test_own_domain_lookalikes(own_organization, domain, expected):
    assert check_lookalike(link_to(domain)).result == expected


def test_own_name_from_outside_flags(own_organization):
    assert check_display_name(sent_as("Ken Nelson IT Support", "gmail.com")).result == Result.FLAG


def test_own_domain_listed_as_a_subdomain(monkeypatch):
    # Listing mail.contoso.com covers the whole organization, contoso.com
    monkeypatch.setattr(impersonation, "OWN_DOMAINS", ["mail.contoso.com"])
    monkeypatch.setattr(impersonation, "EXECUTIVES", {"Ian Wright"})
    assert check_lookalike(link_to("contoso.com")).result == Result.PASS
    assert check_lookalike(link_to("contoso-login.com")).result == Result.FLAG
    assert check_display_name(sent_as("Ian Wright", "contoso.com")).result == Result.PASS


def test_own_name_evidence_names_your_main_domain(monkeypatch):
    # Names are compared without case, and the first domain in OWN_DOMAINS is the main one
    monkeypatch.setattr(impersonation, "OWN_NAMES", {"Northwind"})
    monkeypatch.setattr(impersonation, "OWN_DOMAINS", ["nwtraders.com", "nwtraders.net"])
    evidence = check_lookalike(link_to("northwind-login.com")).evidence
    assert evidence == "northwind-login.com [link] contains 'northwind' but isn't nwtraders.com"


def test_own_names_wait_for_own_domains(monkeypatch):
    # With no domains to compare against, a name isn't checked yet (see lists.py)
    monkeypatch.setattr(impersonation, "OWN_NAMES", {"contoso"})
    assert check_display_name(sent_as("Contoso IT Support", "gmail.com")).result == Result.PASS
    assert check_lookalike(link_to("contoso-login.com")).result == Result.PASS
