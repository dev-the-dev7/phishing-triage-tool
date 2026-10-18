"""Tests for triage/lists.py: entries are written the way the checks compare them, so an
edit for your own organization doesn't quietly stop matching."""

import re

import pytest

from triage.domains import base_domain, lookalike_forms
from triage.lists import ALLOWED_NAMES, BRANDS, FREE_EMAIL_DOMAINS, JOIN_WORDS, OWN_DOMAINS, SHARED_HOSTING

BRAND_DOMAINS = {d for domains in BRANDS.values() for d in domains}


# The checks compare a sender's or link's base domain with these as written, so an entry
# like mail.paypal.com or Gmail.com would never match. One set, because pytest refuses a
# domain listed twice before the last test here can say why it's in both lists.
@pytest.mark.parametrize("domain", sorted(BRAND_DOMAINS | FREE_EMAIL_DOMAINS))
def test_listed_domain_is_its_own_base_domain(domain):
    assert base_domain(domain) == domain


@pytest.mark.parametrize("name", sorted(BRANDS))
def test_brand_name_is_lowercase_with_a_domain(name):
    # Some comparisons use the name as written, so a capital letter gives the wrong evidence
    assert name == name.lower()
    # The first domain is named in the evidence
    assert BRANDS[name]


@pytest.mark.parametrize("word", sorted(JOIN_WORDS | ALLOWED_NAMES))
def test_join_word_or_allowed_name_is_written_like_a_domain_word(word):
    # Compared with the pieces of a domain between dots and dashes, lowercased and with
    # lookalike digits swapped (3 to e), so Metra, metra.com or 3m would never match
    assert re.fullmatch(r"[a-z0-9]+", word)
    assert word in lookalike_forms(word)


@pytest.mark.parametrize("suffix", sorted(SHARED_HOSTING))
def test_shared_hosting_keeps_the_customer_label(suffix):
    # Matched against the end of a host, which has no dot at either end. Checked on its
    # own, since ".github.io" would also make the host below end in "..github.io".
    assert suffix == suffix.strip(".")
    assert base_domain(f"login.customer.{suffix}") == f"customer.{suffix}"


def test_free_webmail_isnt_a_brand_or_own_domain():
    # Anyone can sign up at a free provider. Listing outlook.com under Microsoft would let any
    # outlook.com account use Microsoft's name, and listing gmail.com in OWN_DOMAINS would
    # let any Gmail account use your executives' names.
    owned = BRAND_DOMAINS | {base_domain(d) for d in OWN_DOMAINS}
    assert not owned & FREE_EMAIL_DOMAINS
