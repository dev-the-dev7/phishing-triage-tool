"""Tests for triage/models.py: what a check can return, and how evidence lists are cut short."""

import pytest

from triage.models import Check, join_first_five


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
