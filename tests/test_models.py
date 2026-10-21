"""Tests for triage/models.py: what a check can return, and how its evidence is written."""

import pytest

from triage.models import Address, Check, describe_encoded_addresses, join_first_five


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
    assert describe_encoded_addresses(addresses[:1], "To") == (
        "To address =?q?0?=@evil.com has encoded text in it, which isn't allowed in an address. Some mail clients "
        "decode it and show 0@paypal.com")
    assert describe_encoded_addresses(addresses) == (
        "7 addresses have encoded text in them, which isn't allowed in an address. Some mail clients decode them and "
        "show 0@paypal.com for =?q?0?=@evil.com; 1@paypal.com for =?q?1?=@evil.com; 2@paypal.com for "
        "=?q?2?=@evil.com; 3@paypal.com for =?q?3?=@evil.com; 4@paypal.com for =?q?4?=@evil.com (and 2 more)")
