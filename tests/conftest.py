"""Setup shared by every test file."""

import itertools
import socket

import pytest

from triage import enrich, headers, impersonation


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    # The tests never go online. Downloads are mocked, and anything that still tries to look
    # up a name or connect fails here, so a missing mock can't send a real request.
    def refuse(*args, **kwargs):
        raise OSError("the tests don't go online")
    monkeypatch.setattr(socket, "getaddrinfo", refuse)
    monkeypatch.setattr(socket.socket, "connect", refuse)


@pytest.fixture(autouse=True)
def settings_as_shipped(monkeypatch):
    # The first part of settings.py is meant to be filled in for your own organization, and
    # the tests expect it empty, the way it ships. It's emptied where the checks import it, so
    # settings.py keeps your entries for test_settings.py to check. A test that needs one sets it.
    monkeypatch.setattr(headers, "TRUSTED_AUTHSERV_IDS", set())
    monkeypatch.setattr(impersonation, "OWN_NAMES", set())
    monkeypatch.setattr(impersonation, "OWN_DOMAINS", [])
    monkeypatch.setattr(impersonation, "EXECUTIVES", set())
    monkeypatch.setattr(enrich, "OWN_DOMAINS", [])
    # Names you add to ALLOWED_NAMES would change what the tests expect, so they get the shipped ones
    monkeypatch.setattr(impersonation, "ALLOWED_NAMES", {"mega", "metadata"})


class FakeTime:
    # Stands in for the time module in enrich.py. Time stands still unless a test moves it or
    # the code waits, and a wait is counted instead of taken.
    def __init__(self):
        self.now = 1_800_000_000.0
        self.slept = []

    def time(self):
        return self.now

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        self.slept.append(seconds)
        self.now += seconds


@pytest.fixture(autouse=True)
def clock(monkeypatch):
    fake = FakeTime()
    monkeypatch.setattr(enrich, "time", fake)
    return fake


TEST_NUMBERS = itertools.count()


@pytest.fixture(autouse=True)
def no_keys_or_saved_lookups(monkeypatch, tmp_path_factory):
    # Your own API keys and lookup cache are never used. A test that needs a key sets one.
    monkeypatch.delenv("VT_API_KEY", raising=False)
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    # Each test gets its own cache file. Not tmp_path, which makes a folder for every test and
    # slows the run down by a third.
    folder = tmp_path_factory.getbasetemp() / "lookups" / str(next(TEST_NUMBERS))
    monkeypatch.setattr(enrich, "CACHE_FILE", folder / "lookups.json")
