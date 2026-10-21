"""Tests for triage/settings.py: entries are written the way the checks compare them, so an
edit for your own organization doesn't quietly stop matching."""

import re

import pytest

from triage import settings
from triage.domains import base_domain, lookalike_forms
from triage.settings import ALLOWED_NAMES, BRANDS, EXECUTIVES, FREE_EMAIL_DOMAINS, JOIN_WORDS, OWN_DOMAINS, OWN_NAMES


def entries(setting) -> list[str]:
    # A setting written the wrong way fails its own test below, not every test that reads it
    return [e for e in setting if isinstance(e, str)] if isinstance(setting, (set, list, tuple)) else []


BRAND_DOMAINS = {d for domains in BRANDS.values() for d in entries(domains)}


# The checks compare a sender's or link's base domain with these as written, so an entry
# like mail.paypal.com or Gmail.com would never match. One set, because pytest refuses a
# domain listed twice before the webmail test below can say why it's in both lists.
@pytest.mark.parametrize("domain", sorted(BRAND_DOMAINS | set(entries(FREE_EMAIL_DOMAINS))))
def test_listed_domain_is_its_own_base_domain(domain):
    assert base_domain(domain) == domain


@pytest.mark.parametrize("name", sorted(BRANDS))
def test_brand_name_is_lowercase_with_a_domain(name):
    # Some comparisons use the name as written, so a capital letter gives the wrong evidence
    assert name == name.lower()
    # A list, since the first domain is named in the evidence, and a lone string would be
    # read one letter at a time
    domains = BRANDS[name]
    assert isinstance(domains, list) and domains and entries(domains) == domains, (
        f'write the domains for "{name}" as a list, like ["paypal.com"]')


@pytest.mark.parametrize("word", sorted(set(entries(JOIN_WORDS)) | set(entries(ALLOWED_NAMES))))
def test_join_word_or_allowed_name_is_written_like_a_domain_word(word):
    # Compared with the pieces of a domain between dots and dashes, lowercased and with
    # lookalike digits swapped (3 to e), so Metra, metra.com or 3m would never match
    assert re.fullmatch(r"[a-z0-9]+", word)
    assert word in lookalike_forms(word)


def test_free_webmail_isnt_a_brand_or_own_domain():
    # Anyone can sign up at a free provider. Listing outlook.com under Microsoft would let any
    # outlook.com account use Microsoft's name, and listing gmail.com in OWN_DOMAINS would
    # let any Gmail account use your executives' names.
    owned = BRAND_DOMAINS | {base_domain(d) for d in entries(OWN_DOMAINS)}
    assert not owned & set(entries(FREE_EMAIL_DOMAINS))


@pytest.mark.parametrize("name", ["OWN_NAMES", "OWN_DOMAINS", "TRUSTED_AUTHSERV_IDS", "EXECUTIVES", "JOIN_WORDS",
                                  "ALLOWED_NAMES", "FREE_EMAIL_DOMAINS"])
def test_each_setting_is_a_set_or_list_of_text(name):
    # A lone string, even in brackets with no comma, is read one letter at a time
    setting = getattr(settings, name)
    assert isinstance(setting, (set, list, tuple)) and entries(setting) == list(setting), (
        f"write {name} as a set or list, like the others in settings.py")


def test_your_domains_are_written_as_domain_names():
    # Compared with the hosts in the email, so https://, an @ or a / would never match
    wrong = [d for d in entries(OWN_DOMAINS) if not re.fullmatch(r"[^\s/@:]+\.[^\s/@:]+", d)]
    assert not wrong, f"write these in OWN_DOMAINS like contoso.com: {wrong}"


def test_your_names_and_executives_come_with_your_domains():
    # Without OWN_DOMAINS your names aren't checked, and your executives' own mail is flagged
    assert OWN_DOMAINS or not (OWN_NAMES or EXECUTIVES), "fill in OWN_DOMAINS in settings.py"
