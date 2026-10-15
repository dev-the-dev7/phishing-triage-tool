"""Tests for triage/link_wrappers.py: reading the real link out of Safe Links, Proofpoint, and
Google's redirect."""

from urllib.parse import quote

import pytest

from triage.link_wrappers import MAX_WRAPPERS, destinations, unwrap

# The recipient's address is in data=, the way Safe Links writes it
SAFE_LINK = ("https://nam02.safelinks.protection.outlook.com/?url=https%3A%2F%2Fevil.com%2Flogin%3Fid%3D1"
             "&data=05%7C02%7Cjordan.lee%40example.com%7C0a1b%7C0%7C0%7C638&sdata=abc%3D&reserved=0")


@pytest.mark.parametrize("wrapped, real", [
    (SAFE_LINK, "https://evil.com/login?id=1"),
    ("https://gcc02.safelinks.protection.office365.us/?url=https%3A%2F%2Fevil.com%2F&data=x", "https://evil.com/"),
    ("https://urldefense.proofpoint.com/v1/url?u=http://evil.com/a&k=abc", "http://evil.com/a"),
    ("https://urldefense.proofpoint.com/v2/url?u=https-3A__evil.com_login-3Fid-3D1&d=DwMF&c=x&r=y&m=z&s=w&e=",
     "https://evil.com/login?id=1"),
    # Proofpoint's own example. Kw after the link is base64 for +.
    ("https://urldefense.com/v3/__https://google.com:443/search?q=a*test&gs=ps__;Kw!-612Flbf0JvQ3kNJkRi5Jg!"
     "Ue6tQudNKaShHg93trcdjqDP8se2ySE65jyCIe2K1D_uNjZ1Lnf6YLQERujngZv9UWf66ujQIQ$",
     "https://google.com:443/search?q=a+test&gs=ps"),
    # **A is a run of 2, and KyUl is +%%
    ("https://urldefense.com/v3/__https://evil.com/a*b**Ac__;KyUl!!x!y$", "https://evil.com/a+b%%c"),
    ("https://urldefense.com/v3/__https://evil.com/__;!!x!y$", "https://evil.com/"),
    ("https://urldefense.com/v2/url?u=https-3A__evil.com_&d=x", "https://evil.com/"),
    ("https://urldefense.proofpoint.com/v3/__https://evil.com/__;!!x!y$", "https://evil.com/"),
    ("https://www.google.com/url?q=https://evil.com/&sa=D&source=editors&usg=AOv", "https://evil.com/"),
    # A search result, where q= is the search
    ("https://www.google.com/url?q=phishing+triage&sa=t&url=https://evil.com/&usg=x", "https://evil.com/"),
    # A browser drops the space and the tab, and reads //evil.com as https
    ("https://nam02.safelinks.protection.outlook.com/?url=%20https%3A%2F%2Fevil.com%2F&data=x", "https://evil.com/"),
    ("https://nam02.safelinks.protection.outlook.com/?url=ht%09tps%3A%2F%2Fevil.com%2F&data=x", "https://evil.com/"),
    ("https://nam02.safelinks.protection.outlook.com/?url=%2F%2Fevil.com%2F&data=x", "https://evil.com/"),
    # Wrapped by the sender's service, then the reader's
    ("https://nam02.safelinks.protection.outlook.com/?url=https%3A%2F%2Furldefense.proofpoint.com%2Fv2%2Furl"
     "%3Fu%3Dhttps-3A__evil.com_%26d%3Dx&data=x", "https://evil.com/"),
], ids=["Safe Links", "Safe Links, US government", "Proofpoint v1", "Proofpoint v2", "Proofpoint v3",
        "Proofpoint v3 run", "Proofpoint v3, nothing swapped", "Proofpoint v2, other host",
        "Proofpoint v3, other host", "Google", "Google search result", "space in front", "tab inside",
        "no scheme", "wrapped twice"])
def test_the_real_link_is_read_out(wrapped, real):
    assert unwrap(wrapped) == real


@pytest.mark.parametrize("url", [
    # Someone else's hosts, made to look like the services
    "https://nam02.safelinks.protection.outlook.com.evil.com/?url=https%3A%2F%2Fwww.paypal.com%2F",
    "https://urldefense.com.evil.net/v3/__https://www.paypal.com/__;!!x$",
    "https://evil.com/url?q=https://www.paypal.com/",
    # Two different links
    "https://www.google.com/url?q=https://www.paypal.com/&url=https://evil.com/",
    "https://nam02.safelinks.protection.outlook.com/?url=https%3A%2F%2Fwww.paypal.com%2F&url=https%3A%2F%2Fevil.com%2F",
    # Nothing to read out
    "https://nam02.safelinks.protection.outlook.com/?data=x",
    "https://nam02.safelinks.protection.outlook.com/?url=not-a-link",
    "https://www.google.com/search?q=https://evil.com/",
    "https://urldefense.com/v3/__https://evil.com/",
    "https://urldefense.com/v3/__https://evil.com/a*b*c__;Kw!!x$",
    "https://urldefense.com/v3/__https://evil.com/a**!b__;KyUl!!x$",
    "https://urldefense.com/v3/__https://evil.com/__;K!!x$",
    "https://www.paypal.com/signin",
    "mailto:help@example.com",
], ids=["Safe Links lookalike", "Proofpoint lookalike", "redirect on another site", "Google, two links",
        "Safe Links, two links", "no url=", "url= not a link",
        "Google search", "Proofpoint v3 cut short", "more marks than characters", "run length that isn't one",
        "base64 that doesn't decode", "not wrapped", "no host"])
def test_what_isnt_a_wrapper_is_kept(url):
    assert unwrap(url) == url


def test_where_a_link_goes():
    assert destinations("https://www.paypal.com/") == ["https://www.paypal.com/"]
    assert destinations(SAFE_LINK) == ["https://evil.com/login?id=1"]
    two = "https://www.google.com/url?q=https://www.paypal.com/&url=https://evil.com/"
    assert destinations(two) == ["https://evil.com/", "https://www.paypal.com/"]
    google = "https://www.google.com/url?q=" + quote("https://evil.com/", safe="")
    nested = ("https://nam02.safelinks.protection.outlook.com/?url=" + quote(google, safe="")
              + "&url=" + quote("https://www.paypal.com/", safe=""))
    assert destinations(nested) == ["https://evil.com/", "https://www.paypal.com/"]


def test_without_redirects_only_mail_security_services_are_read():
    google = "https://www.google.com/url?q=https://evil.com/"
    assert (unwrap(SAFE_LINK, redirects=False), unwrap(google, redirects=False)) == (
        "https://evil.com/login?id=1", google)


def test_a_search_isnt_a_link_on_googles_redirect():
    # The search has a colon, so it looks like a link with a scheme
    result = "https://www.google.com/url?q=site:example.com+invoice&sa=t&url=https://example.com/invoice"
    assert destinations(result) == ["https://example.com/invoice"]


def test_two_links_inside_two_links_are_read_only_so_deep():
    url = "https://evil.com/"
    for n in range(MAX_WRAPPERS + 1):
        url = "https://www.google.com/url?q=" + quote(url, safe="") + f"&url=https://a{n}.com/"
    places = destinations(url)
    # The wrappers inside are read out, and the last one past the limit is kept
    assert places[:MAX_WRAPPERS] == [f"https://a{n}.com/" for n in range(1, MAX_WRAPPERS + 1)]
    assert len(places) == MAX_WRAPPERS + 1 and "a0.com" in places[-1]


def test_wrapping_is_read_only_so_deep():
    url = "https://evil.com/"
    for _ in range(MAX_WRAPPERS + 1):
        url = "https://www.google.com/url?q=" + quote(url, safe="")
    assert unwrap(url) == "https://www.google.com/url?q=https%3A%2F%2Fevil.com%2F"
