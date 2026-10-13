"""Setup shared by every test file."""

import pytest

from triage import headers, impersonation


@pytest.fixture(autouse=True)
def lists_as_shipped(monkeypatch):
    # lists.py is meant to be filled in for your own organization, and the tests expect these
    # empty, the way it ships. They're emptied where the checks import them, so lists.py
    # keeps your entries for test_lists.py to check. A test that needs one sets it itself.
    monkeypatch.setattr(headers, "TRUSTED_AUTHSERV_IDS", set())
    monkeypatch.setattr(impersonation, "OWN_NAMES", set())
    monkeypatch.setattr(impersonation, "OWN_DOMAINS", [])
    monkeypatch.setattr(impersonation, "EXECUTIVES", set())
