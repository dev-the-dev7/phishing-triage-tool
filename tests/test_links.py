"""Tests for links: finding them the way a mail client shows them (parser.py), and link text
that shows one domain but goes to another (links.py)."""

import pytest

from triage import parser
from triage.links import check_link_mismatch
from triage.models import Link, ParsedEmail, Result
from triage.parser import parse_bytes

HEADERS = "From: a@example.org\r\nTo: someone@example.net\r\nSubject: s\r\n"


def mismatch(href: str, text: str):
    return check_link_mismatch(ParsedEmail(links=[Link(href, text)]))


def html_email(html: str) -> ParsedEmail:
    return parse_bytes((HEADERS + "Content-Type: text/html; charset=utf-8\r\n\r\n" + html).encode())


def multipart_email(subtype: str, *parts: str) -> ParsedEmail:
    body = "".join(f"--B\r\n{part}\r\n" for part in parts) + "--B--"
    return parse_bytes((HEADERS + f'Content-Type: multipart/{subtype}; boundary="B"\r\n\r\n' + body).encode())


def links_in(parsed: ParsedEmail) -> list[tuple[str, str]]:
    return [(link.href, link.text) for link in parsed.links]


@pytest.mark.parametrize("href, text, shown, goes_to", [
    ("https://evil.com/login", "paypal.com", "paypal.com", "evil.com"),
    ("https://evil.com/", "https://www.paypal.com/signin", "www.paypal.com", "evil.com"),
    ("https://evil.com/", "Visit paypal.com today", "paypal.com", "evil.com"),
    ("https://evil.com/", "PAYPAL.COM", "paypal.com", "evil.com"),
    ("https://evil.com/", "Go to paypal.com.", "paypal.com", "evil.com"),
    # .zip is a real TLD, so it isn't skipped like a file name
    ("https://evil.com/", "invoice.zip", "invoice.zip", "evil.com"),
    # The text is normalized like the host: fullwidth letters and invisible characters
    ("https://evil.net/", "\N{FULLWIDTH LATIN SMALL LETTER P}aypal.com", "paypal.com", "evil.net"),
    ("https://evil.net/", "paypal\N{ZERO WIDTH SPACE}.com", "paypal.com", "evil.net"),
    # The host is read the way a browser reads it
    ("h\tttps:\\\\evil.com/login", "paypal.com", "paypal.com", "evil.com"),
    (r"\\evil.com/login", "paypal.com", "paypal.com", "evil.com"),
    (r"https://evil.com\@paypal.com/", "paypal.com", "paypal.com", "evil.com"),
    ("https://x[@evil.com/", "paypal.com", "paypal.com", "evil.com"),
])
def test_text_showing_another_domain_flags(href, text, shown, goes_to):
    check = mismatch(href, text)
    assert check.result == Result.FLAG
    assert check.evidence == f"text shows {shown} but goes to {goes_to}"


@pytest.mark.parametrize("text", [
    "p\N{CYRILLIC SMALL LETTER A}ypal.com",
    # Cyrillic letters in the TLD too, so the TLD can't be limited to a-z
    "paypal.\N{CYRILLIC SMALL LETTER ES}\N{CYRILLIC SMALL LETTER O}m",
])
def test_cyrillic_text_showing_another_domain_flags(text):
    assert mismatch("https://evil.net/", text).result == Result.FLAG


@pytest.mark.parametrize("href, text", [
    ("https://paypal.com/", "paypal.com"),
    # The same organization
    ("https://www.paypal.com/signin", "paypal.com"),
    ("https://paypal.com/", "https://www.paypal.com/signin"),
    # No domain in the text to compare
    ("https://evil.com/", "Click here"),
    ("https://evil.com/", "Sign in to PayPal"),
    # File names look like domains
    ("https://evil.com/", "invoice.pdf"),
    ("https://evil.com/", "Q3 report.docx"),
    # No web host to compare
    ("mailto:x@evil.com", "support@paypal.com"),
    # Unicode text going to its own xn-- form is a match. The lookalike check flags the domain.
    ("https://xn--pypal-4ve.com/", "p\N{CYRILLIC SMALL LETTER A}ypal.com"),
])
def test_matching_or_missing_domain_passes(href, text):
    assert mismatch(href, text).result == Result.PASS


def test_evidence_lists_five_links():
    links = [Link(f"https://evil{i}.com/", "paypal.com") for i in range(7)]
    evidence = check_link_mismatch(ParsedEmail(links=links)).evidence
    assert evidence.count("text shows paypal.com") == 5
    assert evidence.endswith("(and 2 more)")


@pytest.mark.parametrize("html", [
    # An HTML entity for a tab in the link, which the browser drops
    r'<a href="h&#9;ttp:\\evil.com/login">paypal.com</a>',
    # An entity for the dot in the text
    '<a href="https://evil.com/">paypal&#46;com</a>',
    # The same with no semicolon, at the very end, where the parser waits for the rest of it
    '<a href="https://evil.com/">paypal&#46com',
])
def test_entities_are_read_like_a_browser(html):
    assert check_link_mismatch(html_email(html)).result == Result.FLAG


# Finding links. HTML is only read as text, never rendered.

def test_every_html_part_is_read():
    # Clients show the last alternative they can, and some show every inline part
    alternative = multipart_email(
        "alternative",
        'Content-Type: text/html\r\n\r\n<a href="https://paypal.com/">paypal.com</a>',
        'Content-Type: text/html\r\n\r\n<a href="https://paypa1.com/">paypal.com</a>',
    )
    assert [href for href, _ in links_in(alternative)] == ["https://paypal.com/", "https://paypa1.com/"]
    mixed = multipart_email(
        "mixed",
        "Content-Type: text/html\r\n\r\n<p>Hello</p>",
        'Content-Type: text/html\r\nContent-Disposition: inline\r\n\r\n<a href="https://paypa1.com/">paypal.com</a>',
    )
    assert links_in(mixed) == [("https://paypa1.com/", "paypal.com")]


@pytest.mark.parametrize("content_type, hrefs", [
    # MIME types ignore case (RFC 2045), so mail clients show this as HTML
    ("TEXT/HTML", ["https://evil.com/"]),
    # Shown as written, so evil.com is on screen and the text hides nothing
    ("text/plain", []),
])
def test_content_type_decides_what_is_html(content_type, hrefs):
    raw = HEADERS + f"Content-Type: {content_type}\r\n\r\n" + '<a href="https://evil.com/">paypal.com</a>'
    assert [link.href for link in parse_bytes(raw.encode()).links] == hrefs


def test_empty_html_part():
    parsed = multipart_email("alternative", "Content-Type: text/plain\r\n\r\nHello", "Content-Type: text/html\r\n\r\n")
    assert parsed.links == []
    assert parsed.parse_warnings == []


def test_html_attachment_isnt_read_as_the_body():
    parsed = multipart_email(
        "mixed",
        "Content-Type: text/plain\r\n\r\nSee attached",
        'Content-Type: text/html\r\nContent-Disposition: attachment; filename="invoice.html"\r\n\r\n'
        '<a href="https://evil.com/">paypal.com</a>',
    )
    assert parsed.links == []


def test_first_href_is_used():
    # Browsers use the first when a tag has two
    parsed = html_email('<a href="https://evil.com/" href="https://paypal.com/">paypal.com</a>')
    assert links_in(parsed) == [("https://evil.com/", "paypal.com")]


@pytest.mark.parametrize("html", [
    "<A HREF=https://evil.com/>x</A>",
    '<a href = "https://evil.com/" >x</a>',
    '<a\thref="https://evil.com/">x</a>',
    '<a/href="https://evil.com/">x</a>',
    # Spaces around the link are dropped
    '<a href=" https://evil.com/ ">x</a>',
    # An SVG link can give its address in xlink:href, and href wins when it has both
    '<svg><a xlink:href="https://evil.com/">x</a></svg>',
    '<svg><a xlink:href="https://paypal.com/" href="https://evil.com/">x</a></svg>',
])
def test_tag_spellings_browsers_accept(html):
    assert links_in(html_email(html)) == [("https://evil.com/", "x")]


def test_unclosed_and_nested_links():
    assert links_in(html_email('<a href="https://evil.com/">paypal.com')) == [("https://evil.com/", "paypal.com")]
    # A new <a> ends the one before it
    parsed = html_email('<a href="https://evil.com/">paypal.com<a href="https://paypal.com/">paypal.com</a>')
    assert links_in(parsed) == [("https://evil.com/", "paypal.com"), ("https://paypal.com/", "paypal.com")]


def test_link_text_whitespace_is_collapsed():
    assert links_in(html_email('<a href="https://x.com/">  Sign\r\n  in </a>')) == [("https://x.com/", "Sign in")]


def test_link_text_is_what_shows_between_the_tags():
    # Tags inside the text don't show, so a <span> can't split paypal.com to hide it.
    # Text after </a> isn't part of the link.
    parsed = html_email('<a href="https://evil.com/">pay<span>pal</span>.com</a> and evil.com')
    assert links_in(parsed) == [("https://evil.com/", "paypal.com")]


@pytest.mark.parametrize("hidden", ["<style> </style>", "<span hidden> </span>", '<span style="display:none"> </span>'])
@pytest.mark.xfail(reason="README limitation: text hidden inside a link is still read", raises=AssertionError)
def test_text_hidden_inside_a_link(hidden):
    # The reader sees paypal.com, and the tool reads "paypal .com", which isn't a domain
    parsed = html_email(f'<a href="https://evil.com/">paypal{hidden}.com</a>')
    assert check_link_mismatch(parsed).result == Result.FLAG


@pytest.mark.parametrize("html, href", [
    # <base href> sends relative links to another site (baseStriker)
    ('<base href="https://evil.com/"><a href="/login">Sign in</a>', "https://evil.com/login"),
    ('<base href=" https://evil.com/ "><a href="/login">Sign in</a>', "https://evil.com/login"),
    # The same base twice, spelled two ways, is one base
    (r'<base href="https://evil.com/"><base href="https:\\evil.com\"><a href="/login">Sign in</a>',
     "https://evil.com/login"),
    # Links with a host of their own keep it
    ('<base href="https://evil.com/"><a href="https://paypal.com/x">Sign in</a>', "https://paypal.com/x"),
    (r'<base href="https://evil.com/"><a href="\\other.net/x">Sign in</a>', r"\\other.net/x"),
    # A base is read like a link, so backslashes and a [ in the login part work there too
    (r'<base href="https:\\evil.com\"><a href="/login">Sign in</a>', "https://evil.com/login"),
    ('<base href="https://x[@evil.com/"><a href="/login">Sign in</a>', "https://evil.com/login"),
    # Repeating the base's scheme without two slashes is a page on the base's site. The
    # scheme ignores case.
    ('<base href="https://evil.com/"><a href="https:paypal.com">Sign in</a>', "https://evil.com/paypal.com"),
    ('<base href="HTTPS://evil.com/"><a href="https:paypal.com">Sign in</a>', "https://evil.com/paypal.com"),
    ('<base href="https://evil.com/"><a href="HTTPS:paypal.com">Sign in</a>', "https://evil.com/paypal.com"),
    # Another scheme is its own link: on an https base, http:paypal.com goes to paypal.com
    ('<base href="https://evil.com/"><a href="http:paypal.com">Sign in</a>', "http:paypal.com"),
    # An empty link goes to the base itself, and so does an href with no value
    ('<base href="https://evil.com/login"><a href="">Sign in</a>', "https://evil.com/login"),
    ('<base href="https://evil.com/login"><a href>Sign in</a>', "https://evil.com/login"),
    # A broken base leaves the link as written
    ('<base href="http://[broken"><a href="/login">Sign in</a>', "/login"),
])
def test_base_href(html, href):
    parsed = html_email(html)
    assert links_in(parsed) == [(href, "Sign in")]
    # One base gives no warning
    assert parsed.parse_warnings == []


@pytest.mark.parametrize("decoy", [
    # Browsers use the first base
    '<base href="https://paypal.com/">',
    # Browsers skip a base inside these, and Python's parser can't tell where a tag sits
    '<template><base href="https://paypal.com/"></template>',
    '<svg><base href="https://paypal.com/"></base></svg>',
])
def test_links_are_read_against_every_base(decoy):
    # Each reading is listed, so a decoy in front can't hide the real one. A link with its
    # own host is listed once.
    parsed = html_email(decoy + '<base href="https://evil.com/"><a href="/login">Sign in</a>'
                                '<a href="https://other.net/">Other</a>')
    assert links_in(parsed) == [("https://paypal.com/login", "Sign in"), ("https://evil.com/login", "Sign in"),
                                ("https://other.net/", "Other")]
    assert parsed.parse_warnings == ["The HTML has 2 different <base> tags. Browsers use one, "
                                     "so links were read against each."]


def test_base_limit(monkeypatch):
    # Up to the limit every base is read. Past it, the warning says to check the rest by hand.
    monkeypatch.setattr(parser, "MAX_BASES", 2)
    bases = '<base href="https://one.com/"><base href="https://two.com/">'
    at_limit = html_email(bases + '<a href="/login">Sign in</a>')
    assert [href for href, _ in links_in(at_limit)] == ["https://one.com/login", "https://two.com/login"]
    assert at_limit.parse_warnings == ["The HTML has 2 different <base> tags. Browsers use one, "
                                       "so links were read against each."]
    over_limit = html_email(bases + '<base href="https://evil.com/"><a href="/login">Sign in</a>')
    assert [href for href, _ in links_in(over_limit)] == ["https://one.com/login", "https://two.com/login"]
    assert over_limit.parse_warnings == ["The HTML has 3 different <base> tags, which set where links go. "
                                         "Links were read against the first 2. Check the rest by hand."]


def test_no_break_space_before_a_link_isnt_trimmed():
    # Browsers trim only control characters and spaces, so this is a page on the base's
    # site, not a link to paypal.com
    parsed = html_email('<base href="https://evil.com/"><a href="\N{NO-BREAK SPACE}https://paypal.com/">paypal.com</a>')
    assert check_link_mismatch(parsed).evidence == "text shows paypal.com but goes to evil.com"


def test_html_that_cant_be_parsed_keeps_the_links_before_it(monkeypatch):
    # Python's HTML parser no longer raises on broken markup like <![, so the test raises an
    # error at the <b> inside the second link. That link is kept with its text so far.
    read_tag = parser._LinkCollector.handle_starttag

    def fail_at_bold(self, tag, attrs):
        if tag == "b":
            raise ValueError("broken markup")
        read_tag(self, tag, attrs)

    monkeypatch.setattr(parser._LinkCollector, "handle_starttag", fail_at_bold)
    parsed = html_email('<a href="https://one.com/">one</a><a href="https://two.com/">two <b>bold</b></a>'
                        '<a href="https://three.com/">three</a>')
    assert links_in(parsed) == [("https://one.com/", "one"), ("https://two.com/", "two")]
    assert any("HTML body couldn't be fully parsed (ValueError)" in w for w in parsed.parse_warnings)
