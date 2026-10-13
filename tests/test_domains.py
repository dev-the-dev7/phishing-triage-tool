"""Tests for triage/domains.py: reading a link's host, and swapping lookalike characters back."""

import unicodedata

import pytest

from triage.domains import (LOOKALIKE_CHARS, base_domain, decode_idn, lookalike_forms, normalize_unicode,
                            registered_name, unmask_lookalikes, url_host)


def fullwidth(text: str) -> str:
    # The fullwidth forms of ASCII letters and digits sit 0xFEE0 above them: p becomes U+FF50
    return "".join(chr(ord(ch) + 0xFEE0) for ch in text)


# Where a browser goes for each link, checked with Node's new URL(), which follows the same
# URL standard as browsers. Links without a host of their own were resolved against a
# webmail page, and None means the link stays on that page. Backslashes are doubled in the
# strings with \t or \n in them: "http:\\\\evil.com" is http:\\evil.com.
BROWSER_HOSTS = [
    # \ counts as /, so @paypal.com is part of the path, not a login in front of the host
    (r"http://evil.com\@paypal.com/", "evil.com"),
    # The login part up to the last @ is skipped, even with a [ or ], which Python's parser refuses
    ("https://x[@paypa1.com/", "paypa1.com"),
    ("https://[::1]@paypa1.com/", "paypa1.com"),
    # It ends where the path, query or fragment starts, so here @paypal.com is in the query
    ("https://evil.com?@paypal.com/", "evil.com"),
    # Any slashes after http: work, and the scheme ignores case
    (r"http:\\evil.com/", "evil.com"),
    (r"HTTP:\\evil.com/", "evil.com"),
    ("http:/evil.com/", "evil.com"),
    ("http:///evil.com/", "evil.com"),
    ("http:evil.com/", "evil.com"),
    # With no scheme, two slashes of either kind take the webmail page's https
    ("//evil.com/x", "evil.com"),
    (r"\\evil.com/x", "evil.com"),
    (r"/\evil.com/x", "evil.com"),
    (r"\/evil.com/x", "evil.com"),
    ("/evil.com/x", None),
    ("evil.com/x", None),
    # The host is percent-decoded, and fullwidth or styled letters and other dots become plain
    ("http://%70aypa1.com/", "paypa1.com"),
    (f"http://{fullwidth('paypa1')}.com/", "paypa1.com"),
    ("http://paypa1\N{IDEOGRAPHIC FULL STOP}com/", "paypa1.com"),
    ("http://paypa1\N{FULLWIDTH FULL STOP}com/", "paypa1.com"),
    ("http://paypa1\N{HALFWIDTH IDEOGRAPHIC FULL STOP}com/", "paypa1.com"),
    ("http://\N{MATHEMATICAL BOLD SMALL P}aypa1.com/", "paypa1.com"),
    # Tabs and line breaks are dropped anywhere, and control characters and spaces at either end
    ("h\tttp:\\\\evil.com", "evil.com"),
    ("ht\ntp:\\evil.com\\@paypal.com", "evil.com"),
    ("http:/\n/evil.com", "evil.com"),
    ("http:\\\t\\evil.com", "evil.com"),
    ("\\\t\\evil.com", "evil.com"),
    ("/\n\\evil.com", "evil.com"),
    ("http://ev\nil.com/x", "evil.com"),
    ("\x01http:\\\\evil.com", "evil.com"),
    ("\x01\\\\evil.com", "evil.com"),
    ("http://evil.com\x01", "evil.com"),
    (" \r\nhttps:\\\\evil.com ", "evil.com"),
    # Dropping the tab leaves http://evil.com@paypal.com, where paypal.com really is the host
    ("http://evil.com\t@paypal.com", "paypal.com"),
    # Browsers trim only control characters and the space, so a no-break space or a ! in
    # front stays, and the link isn't read as a web link
    ("\N{NO-BREAK SPACE}http:\\\\evil.com", None),
    ("!http:\\\\evil.com", None),
    # Invisible characters are ignored in a host
    ("http://pay\N{ZERO WIDTH SPACE}pal.com/", "paypal.com"),
    ("http://pay\N{SOFT HYPHEN}pal.com/", "paypal.com"),
    ("http://pay\N{WORD JOINER}pal.com/", "paypal.com"),
    ("http://pay\N{ZERO WIDTH NO-BREAK SPACE}pal.com/", "paypal.com"),
    ("http://pay\N{MONGOLIAN VOWEL SEPARATOR}pal.com/", "paypal.com"),
]


@pytest.mark.parametrize("href, host", BROWSER_HOSTS)
def test_url_host_matches_the_browser(href, host):
    assert url_host(href) == host


def test_url_host_drops_a_trailing_dot():
    # The browser keeps it (paypal.com.), but it's the same site in DNS
    assert url_host("http://paypal.com./") == "paypal.com"


@pytest.mark.parametrize("href", ["mailto:a@evil.com", "javascript:alert(1)", "", "http://"])
def test_url_host_is_none_without_a_web_host(href):
    assert url_host(href) is None


@pytest.mark.parametrize("domain, base", [
    ("paypal.com", "paypal.com"),
    ("mail.PayPal.com.", "paypal.com"),
    # Countries that register under a second level
    ("a.b.co.uk", "b.co.uk"),
    ("www.amazon.com.au", "amazon.com.au"),
    ("x.example.ne.jp", "example.ne.jp"),
    # Shared hosting keeps the customer's own label, since each one is a different owner
    ("paypal-login.github.io", "paypal-login.github.io"),
    ("www.paypal-login.github.io", "paypal-login.github.io"),
    ("evil.blob.core.windows.net", "evil.blob.core.windows.net"),
    ("files.evil.r2.dev", "evil.r2.dev"),
    ("contoso.onmicrosoft.com", "contoso.onmicrosoft.com"),
    ("203.0.113.5", "203.0.113.5"),
])
def test_base_domain(domain, base):
    assert base_domain(domain) == base


def test_registered_name():
    assert registered_name(base_domain("mail.chose.com")) == "chose"


@pytest.mark.parametrize("domain, expected", [
    ("xn--pypal-4ve.com", "p\N{CYRILLIC SMALL LETTER A}ypal.com"),
    # Labels are decoded one at a time, so a broken one doesn't stop the rest
    ("xn--zz.xn--pypal-4ve.com", "xn--zz.p\N{CYRILLIC SMALL LETTER A}ypal.com"),
    ("paypal.com", "paypal.com"),
])
def test_decode_idn(domain, expected):
    assert decode_idn(domain) == expected


@pytest.mark.parametrize("text, expected", [
    ("Pay\N{ZERO WIDTH SPACE}Pal", "paypal"),
    ("Pay\N{SOFT HYPHEN}Pal", "paypal"),
    (fullwidth("PayPal"), "paypal"),
    ("\N{MATHEMATICAL BOLD SMALL P}aypal", "paypal"),
    ("paypal\N{IDEOGRAPHIC FULL STOP}com", "paypal.com"),
])
def test_normalize_unicode(text, expected):
    assert normalize_unicode(text) == expected


@pytest.mark.parametrize("text, expected", [
    ("paypa1", "paypal"),
    ("g00gle", "google"),
    ("rnicrosoft", "microsoft"),
    ("annazon", "amazon"),
    ("vvellsfargo", "wellsfargo"),
    ("clocusign", "docusign"),
    # Characters are swapped before pairs, so c1 becomes cl and then d
    ("c1ocusign", "docusign"),
    # lc isn't a pair for k: 1 also stands for i, and m1crosoft would become mkrosoft
    ("m1crosoft", "mlcrosoft"),
    ("p\N{CYRILLIC SMALL LETTER A}ypal", "paypal"),
    ("g\N{GREEK SMALL LETTER OMICRON}\N{GREEK SMALL LETTER OMICRON}gle", "google"),
    # Lowercased first, so a capital with a listed lowercase form is covered
    ("P\N{CYRILLIC CAPITAL LETTER A}YPAL", "paypal"),
])
def test_unmask_lookalikes(text, expected):
    assert unmask_lookalikes(text) == expected


@pytest.mark.parametrize("char, letter", sorted(LOOKALIKE_CHARS.items()))
def test_lookalike_table_is_written_the_way_text_is_compared(char, letter):
    # Text is normalized and lowercased before the swap, so a key has to come through that
    # unchanged to ever match
    char = chr(char)
    assert unmask_lookalikes(char) == letter
    assert char.isdigit() or unicodedata.name(char).split()[0] in ("CYRILLIC", "GREEK", "COPTIC")
    assert len(letter) == 1 and "a" <= letter <= "z"


def test_unmask_lookalikes_without_pairs():
    assert unmask_lookalikes("rnicrosoft", pairs=False) == "rnicrosoft"


@pytest.mark.parametrize("text, expected", [
    # Swapping nn hides amazon, so the form without pairs is kept too
    ("amazonnow", {"amazonnow", "amazomow"}),
    # A capital I reads as l, and the form as written is kept for names like Ian
    ("PayPaI", {"paypai", "paypal"}),
    ("IAN", {"ian", "lan"}),
    ("Face\N{CYRILLIC CAPITAL LETTER SOFT SIGN}ook", {"face\N{CYRILLIC SMALL LETTER SOFT SIGN}ook", "facebook"}),
])
def test_lookalike_forms(text, expected):
    assert lookalike_forms(text) == expected
