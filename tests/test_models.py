"""Tests for triage/models.py: what a check can return, how evidence lists are cut short, and
running the checks that compare the From on every From address."""

import pytest

from triage import models
from triage.checks import run_checks
from triage.models import Address, Check, Result, encoded_addresses, join_first_five
from triage.parser import parse_bytes

PASS, FLAG, INCONCLUSIVE = Result.PASS, Result.FLAG, Result.INCONCLUSIVE


def test_check_refuses_a_typo():
    # "fail" for "flag" raises here, instead of printing a result nothing else looks for
    with pytest.raises(ValueError):
        Check("SPF", "fail", "medium", "")
    with pytest.raises(ValueError):
        Check("SPF", "flag", "high", "")


@pytest.mark.parametrize("count, expected", [
    (5, "1; 2; 3; 4; 5"),
    (6, "1; 2; 3; 4; 5 (and 1 more)"),
])
def test_join_first_five(count, expected):
    assert join_first_five([str(n) for n in range(1, count + 1)]) == expected


def test_encoded_addresses_are_one_sentence():
    addresses = [Address("", f"=?q?{n}?=@evil.com", "evil.com", f"{n}@paypal.com") for n in range(7)]
    assert encoded_addresses(addresses[:1], "To") == (
        "To address =?q?0?=@evil.com has encoded text in it, which isn't allowed in an address. Some mail clients "
        "decode it and show 0@paypal.com")
    assert encoded_addresses(addresses) == (
        "7 addresses have encoded text in them, which isn't allowed in an address. Some mail clients decode them and "
        "show 0@paypal.com for =?q?0?=@evil.com; 1@paypal.com for =?q?1?=@evil.com; 2@paypal.com for "
        "=?q?2?=@evil.com; 3@paypal.com for =?q?3?=@evil.com; 4@paypal.com for =?q?4?=@evil.com (and 2 more)")


def checks_of(*header_lines: str) -> dict[str, Check]:
    raw = "\r\n".join([*header_lines, "To: someone@example.net", "Subject: s", "", "Hello"])
    return {check.name: check for check in run_checks(parse_bytes(raw.encode()))}


def test_a_dmarc_pass_for_one_from_doesnt_cover_another():
    # The attacker passes DMARC with their own domain, and some mail clients show the other From
    found = checks_of("Authentication-Results: mx.example.net; dmarc=pass header.from=evil.com",
                      "From: x@evil.com", "From: service@paypal.com")
    assert (found["DMARC"].result, found["DMARC"].evidence) == (INCONCLUSIVE, (
        "dmarc=pass for evil.com (from mx.example.net). The provider checked a different From than the one "
        "shown (paypal.com)"))


@pytest.mark.parametrize("header_lines, name, evidence", [
    (("From: a@example.org", "From: x@gmail.com"), "Free webmail sender",
     "Sent from a free gmail.com account, which anyone can create"),
    (("From: a@evil.com, b@paypal.com", "Reply-To: x@evil.com"), "Reply-To", "Replies go to evil.com, not paypal.com"),
    (("From: a@evil.com", 'From: "PayPal" <x@evil.net>'), "Display name",
     '"PayPal" mentions "paypal" but the mail is from evil.net'),
])
def test_a_flag_on_any_from_counts(header_lines, name, evidence):
    found = checks_of(*header_lines)[name]
    assert (found.result, found.evidence) == (FLAG, evidence)


def test_a_pass_needs_every_from():
    found = checks_of("From: a@example.org, undisclosed", "Return-Path: <bounce@example.org>")
    assert found["Return-Path domain"].result == INCONCLUSIVE
    # Said once when every From gives the same reason
    found = checks_of("From: a@example.org", "From: b@mail.example.org")
    assert (found["Free webmail sender"].result, found["Free webmail sender"].evidence) == (
        PASS, "example.org isn't on the free webmail list")


def test_caveats_are_said_once():
    found = checks_of("From: a@example.org", "From: b@example.org", "Reply-To: a@example.org",
                      "Reply-To: b@example.org")
    assert len(found["Reply-To"].caveats) == 1


def test_past_the_limit_a_check_cant_pass(monkeypatch):
    monkeypatch.setattr(models, "MAX_FROMS", 2)
    found = checks_of("From: a@example.org, b@example.org, c@example.org")
    assert (found["Free webmail sender"].result, found["Free webmail sender"].evidence) == (
        INCONCLUSIVE, "example.org isn't on the free webmail list. Only the first 2 of 3 From addresses were checked")
    # A flag in the ones checked still counts
    assert checks_of("From: a@gmail.com, b@example.org, c@example.org")["Free webmail sender"].result == FLAG


def test_spf_runs_once_since_it_doesnt_read_the_from(monkeypatch):
    monkeypatch.setattr(models, "MAX_FROMS", 2)
    found = checks_of("Authentication-Results: mx.example.net; spf=pass",
                      "From: a@example.org, b@example.org, c@example.org")
    assert found["SPF"].result == PASS


def test_the_lookalike_checks_read_every_from():
    assert checks_of("From: service@paypal.com", "From: x@paypa1.com")["Lookalike domain"].result == FLAG
