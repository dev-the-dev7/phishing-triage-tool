"""Tests for what the body shows (html_reader.py) and the checks on it (content.py): text
hidden inside words, an email that's only an image, and text added by CSS."""

import pytest

from triage.checks.content import check_css_added_text, check_hidden_text, check_image_only
from triage.models import Attachment, ParsedEmail, Result, Strength
from triage.reading.parser import parse_bytes

HEADERS = "From: a@example.org\r\nTo: someone@example.net\r\nSubject: s\r\n"


def html_email(html: str) -> ParsedEmail:
    return parse_bytes((HEADERS + "Content-Type: text/html; charset=utf-8\r\n\r\n" + html).encode())


def test_shown_text():
    # One line per block, with whitespace collapsed, and without what a browser hides
    parsed = html_email("<html><head><title>T</title><style>p{}</style></head><body>\n"
                        "<p>Dear  customer,\n your <b>account</b> is limited.</p>"
                        "<div hidden>Preview text</div><table><tr><td>Sign</td><td>in</td></tr></table>"
                        "Thanks<br>Support<script>x</script></body></html>")
    assert parsed.html_text == "Dear customer, your account is limited.\nSign\nin\nThanks\nSupport"


@pytest.mark.parametrize("css, text", [
    ('.x::before { content: "." }', '"."'),
    ("a:after{content:'paypal.com'}", '"paypal.com"'),
    # Escapes are decoded: \2e is a dot
    (r'.x::before{content:"\2e"}', '"."'),
    # The last character there is, and what CSS reads as the replacement character: one past
    # it, which Python can't make, a surrogate, which can't be written to a file, and zero
    (r'.x::before{content:"a\10FFFF"}', '"a\U0010ffff"'),
    (r'.x::before{content:"a\110000"}', '"a\N{REPLACEMENT CHARACTER}"'),
    (r'.x::before{content:"a\D800"}', '"a\N{REPLACEMENT CHARACTER}"'),
    (r'.x::before{content:"a\0"}', '"a\N{REPLACEMENT CHARACTER}"'),
    ('.x::before{CONTENT: "@"}', '"@"'),
    # Text from an attribute
    (".x::after{content: attr(title)}", '"attr(title)"'),
    (".x::after{content: ATTR(title)}", '"ATTR(title)"'),
    # Text after an image still counts
    ('.x::after{content: url("dot.png") "paypal.com"}', '"paypal.com"'),
    # Long text is cut short, and each text is listed once
    ('.x::before{content:"' + "a" * 50 + '"}', '"' + "a" * 40 + '..."'),
    ('.x::before{content:"."} .y::after{content:"."} .z::after{content:"b"}', '"."; "b"'),
])
def test_css_that_adds_text_flags(css, text):
    parsed = html_email(f"<style>{css}</style><p>Hello</p>")
    # By its name too, which the link check's caveat points to
    assert [(c.name, c.result, c.strength, c.evidence) for c in check_css_added_text(parsed)] == [
        ("Text added by CSS", Result.FLAG, Strength.WEAK,
         f"CSS adds {text} to what the email shows, and the tool doesn't read CSS. Check what the email looks "
         "like in a mail client.")]
    assert parsed.parse_warnings == []


@pytest.mark.parametrize("css", [
    # Icon fonts add a symbol, and layout tricks add nothing
    r'.icon::before{content:"\f101"}',
    '.clearfix::after{content:""; display:table}',
    '.q::before{content:"\N{LEFT DOUBLE QUOTATION MARK}"}',
    # An image, the way email trackers load one, isn't text
    '#t::after{content:url("https://tracker.example.net/open?id=1")}',
    "#t::after{content: URL('https://tracker.example.net/open?id=1')}",
    # Not the content property, or in a comment
    ".row{justify-content:center; align-content:start}",
    '/* .x::before { content: "." } */',
])
def test_css_that_adds_nothing_readable_isnt_listed(css):
    assert check_css_added_text(html_email(f"<style>{css}</style><p>Hello</p>")) == []


def test_css_is_only_read_from_style_blocks():
    # content only adds text to ::before and ::after, which a style attribute can't reach
    assert check_css_added_text(html_email('<p style="content:\'x\'">Hello</p>')) == []


def test_title_is_only_ended_by_its_own_end_tag():
    # Browsers ignore the / and read everything up to </title> as the title
    assert html_email("a<title/>secret</style>more</title>b").html_text == "ab"


def test_shown_text_of_every_html_part():
    body = ("--B\r\nContent-Type: text/html\r\n\r\n<p>One</p>\r\n"
            "--B\r\nContent-Type: text/html\r\n\r\n<p hidden>x</p>\r\n"
            "--B\r\nContent-Type: text/html\r\n\r\n<p>Two</p>\r\n--B--")
    parsed = parse_bytes((HEADERS + 'Content-Type: multipart/alternative; boundary="B"\r\n\r\n' + body).encode())
    assert parsed.html_text == "One\nTwo"


@pytest.mark.parametrize("html, found", [
    ('Mic<span style="font-size:0">xyz</span>rosoft', "Mic[xyz]rosoft shows as Microsoft"),
    ('Pay<span style="display:none">x</span><b>Pal</b> account', "Pay[x]Pal shows as PayPal"),
    # Several hidden pieces in a row are one
    ('Your Mic<i hidden>a</i><i hidden> b</i>rosoft account', "Mic[a b]rosoft shows as Microsoft"),
    ("1<template>0</template>00", "1[0]00 shows as 100"),
    # One letter on either side is enough
    ('Your M<span style="font-size:0">x</span>icrosoft account', "M[x]icrosoft shows as Microsoft"),
    ('Your Microsof<span style="font-size:0">x</span>t account', "Microsof[x]t shows as Microsoft"),
    # Other ways to hide it
    ('Pay<span style="visibility:collapse">x</span>Pal account', "Pay[x]Pal shows as PayPal"),
    ('Pay<span style="display:/**/none">x</span>Pal account', "Pay[x]Pal shows as PayPal"),
    # The hidden span still holds the text after the span inside it
    ('Pay<span hidden>x<span>y</span>z</span>Pal account', "Pay[xyz]Pal shows as PayPal"),
])
def test_text_hidden_inside_a_word(html, found):
    parsed = html_email(html)
    assert parsed.hidden_in_words == [found]
    check = check_hidden_text(parsed)
    assert [(c.name, c.result, c.evidence) for c in check] == [
        ("Hidden text", Result.FLAG,
         "Text is hidden inside words, so filters read something other than what the reader sees: " + found)]


@pytest.mark.parametrize("html", [
    # The preview line marketing emails hide at the top
    '<div style="display:none;max-height:0">Your order has shipped</div><p>Hello</p>',
    # Hidden between words, or between blocks
    'Hello <span hidden>x</span>world',
    '<p>Hello</p><p hidden>x</p><p>world</p>',
    "Hello<br><span hidden>x</span>world",
    # A hidden element left open ends with the block it's in, which still takes up its line
    "<div>Hello<span hidden>x</div>world",
    # Only spaces or invisible characters hidden, the way templates close the gaps between images
    '<div style="font-size:0"><span style="font-size:14px">A</span> <span style="font-size:14px">B</span></div>',
    'Pay<span style="display:none">&zwnj;&#8203;</span>ment',
    # Blocks with font size 0 or visibility:hidden still take up their lines, so text in the
    # next cell isn't the same word
    '<table><tr><td style="font-size:0"><span style="font-size:14px">Total</span>x</td>'
    '<td style="font-size:0">y<span style="font-size:14px">Due</span></td></tr></table>',
    'Total<div style="visibility:hidden">x</div>Due',
    # Hidden at the very end
    "Hello<span hidden>x</span>",
])
def test_hidden_text_that_isnt_inside_a_word(html):
    parsed = html_email(html)
    assert parsed.hidden_in_words == []
    assert check_hidden_text(parsed) == []


@pytest.mark.parametrize("html", [
    '<img src="cid:qr">',
    '<a href="https://evil.com/"><img src="https://evil.com/scan.png" alt="Scan this code"></a>',
    # Hidden text isn't text the reader sees
    '<img src="cid:a"><img src="cid:b"><span style="font-size:0">Your invoice</span>',
    # Font size doesn't shrink an image, so templates put rows of images in font-size:0 cells
    '<table><tr><td style="font-size:0"><img src="cid:a"><img src="cid:b"></td></tr></table>',
])
def test_email_that_is_only_an_image(html):
    check = check_image_only(html_email(html))
    assert [(c.name, c.result, c.evidence) for c in check] == [
        ("Image-only email", Result.FLAG, "The email shows images and no text. Any text or QR code in them can't be "
         "checked, so look at them by hand, and don't scan a QR code to see where it goes.")]


@pytest.mark.parametrize("html", [
    '<p>Scan the code to sign in</p><img src="cid:qr">',
    # Images a browser wouldn't show, or with nothing to load
    '<img src="cid:qr" hidden><div style="display:none"><img src="cid:qr"></div><img><img src="">',
    # No images and no text
    "<p> </p>",
])
def test_email_with_text_or_without_images(html):
    assert check_image_only(html_email(html)) == []


def test_image_attachment_with_no_text():
    image = Attachment("scan.png", "image/png", 100, "0" * 64)
    assert check_image_only(ParsedEmail(text_body=" \n", attachments=[image]))[0].result == Result.FLAG
    # The HTML is what the reader sees, when there is some
    assert check_image_only(ParsedEmail(text_body="Hello", html_body="<p></p>", attachments=[image])) != []
    assert check_image_only(ParsedEmail(text_body="Hello", attachments=[image])) == []
