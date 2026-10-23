"""Tests for links: finding them the way a mail client shows them (parser.py and
html_reader.py), and link text that shows one domain but goes to another (links.py)."""

from urllib.parse import quote

import pytest

from triage.checks.impersonation import check_lookalike
from triage.checks.links import check_google_redirect, check_link_mismatch, check_link_type
from triage.models import Check, Link, ParsedEmail, Result
from triage.reading import html_reader
from triage.reading.iocs import indicators_from_email
from triage.reading.parser import parse_bytes

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


def test_a_link_with_no_host_doesnt_end_the_check():
    # Or a mailto: link first would hide every link after it
    links = [Link("mailto:help@paypal.com", "help@paypal.com"), Link("https://evil.com/", "paypal.com")]
    assert check_link_mismatch(ParsedEmail(links=links)).evidence == "text shows paypal.com but goes to evil.com"


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


# Finding links

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


@pytest.mark.parametrize("content_type, text", [
    # MIME types ignore case (RFC 2045), so mail clients show this as HTML
    ("TEXT/HTML", "paypal.com"),
    # Shown as written, so the URL is on screen and the text hides nothing
    ("text/plain", "https://evil.com/"),
])
def test_content_type_decides_what_is_html(content_type, text):
    raw = HEADERS + f"Content-Type: {content_type}\r\n\r\n" + '<a href="https://evil.com/">paypal.com</a>'
    assert links_in(parse_bytes(raw.encode())) == [("https://evil.com/", text)]


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


def test_links_only_outlook_shows():
    # Outlook for Windows shows what's in <!--[if mso]>, and draws <v:roundrect href> as a button.
    # Other clients read it all as a comment.
    parsed = html_email('<p>Hi</p><!--[if mso]><a href="https://evil.com/">paypal.com</a><![endif]-->'
                        '<!--[if gte mso 9]><v:roundrect href="https://evil.net/x"><center>Sign in</center>'
                        '</v:roundrect><img src="https://evil.org/p.gif"><![endif]-->'
                        "<!--[if !mso]><!--><a href=\"https://shown.com/\">shown</a><!--<![endif]-->"
                        '<!-- <a href="https://not-a-link.com/">x</a> -->')
    # The links every client shows, then the ones only Outlook does
    assert links_in(parsed) == [("https://shown.com/", "shown"), ("https://evil.com/", "paypal.com"),
                                ("https://evil.net/x", "")]
    assert parsed.other_urls == ["https://evil.org/p.gif"]
    assert parsed.html_text == "Hi\nshown"
    assert check_link_mismatch(parsed).evidence == "text shows paypal.com but goes to evil.com"


@pytest.mark.parametrize("other_clients_only", [
    # The parts every client but Outlook shows, written the two ways templates write them
    '<!--[if !mso]><!--><a href="https://shown.com/">shown</a><!--<![endif]-->',
    '<!--[if !mso]><!-- --><a href="https://shown.com/">shown</a><!-- <![endif]-->',
])
def test_outlook_link_after_a_part_outlook_skips(other_clients_only):
    parsed = html_email(other_clients_only + '<p>x</p><!--[if mso]><a href="https://evil.com/">paypal.com</a>'
                                             "<![endif]-->")
    assert links_in(parsed) == [("https://shown.com/", "shown"), ("https://evil.com/", "paypal.com")]


def test_link_split_across_outlook_parts():
    # Outlook sees <a href="https://evil.com/">paypal.com</a>, and other clients see plain text
    parsed = html_email('<!--[if mso]><a href="https://evil.com/"><![endif]-->paypal.com'
                        "<!--[IF MSO]></a><![endif]-->")
    assert links_in(parsed) == [("https://evil.com/", "paypal.com")]
    assert check_link_mismatch(parsed).evidence == "text shows paypal.com but goes to evil.com"


def test_outlook_markers_in_capitals():
    # Read in capitals too, so a link Outlook might show isn't missed
    parsed = html_email('<!--[IF MSO]><a href="https://evil.com/">paypal.com</a><![ENDIF]-->')
    assert links_in(parsed) == [("https://evil.com/", "paypal.com")]


def test_image_map_area_is_a_link():
    # A clickable part of an image, with no text of its own. An open <a> around it carries on.
    parsed = html_email('<a href="https://one.com/">one<map><area href="https://evil.com/"></map> more</a>'
                        "<area alt=x>")
    assert links_in(parsed) == [("https://evil.com/", ""), ("https://one.com/", "one more")]


@pytest.mark.parametrize("html", [
    '<img src="https://evil.com/x">',
    '<form action="https://evil.com/x"><input name=password></form>',
    '<button formaction="https://evil.com/x">Sign in</button>',
    '<td background="https://evil.com/x">',
    '<video poster="https://evil.com/x"></video>',
    '<link rel=stylesheet href="https://evil.com/x">',
    '<svg><image xlink:href="https://evil.com/x"/></svg>',
    # Read like a link: trimmed, and against the <base>
    '<img src=" https://evil.com/x ">',
    '<base href="https://evil.com/"><img src="/x">',
])
def test_other_urls_the_html_loads_or_sends_to(html):
    parsed = html_email(html)
    assert parsed.other_urls == ["https://evil.com/x"]
    assert parsed.links == []


def test_urls_written_in_plain_text_are_links():
    parsed = parse_bytes((HEADERS + "Content-Type: text/plain\r\n\r\n"
                          "Sign in at https://paypa1.com/login. Or www.evil.com/x, not hxxps://evil[.]com").encode())
    # A www. link with no scheme opens as http
    assert links_in(parsed) == [("https://paypa1.com/login", "https://paypa1.com/login"),
                                ("http://www.evil.com/x", "www.evil.com/x")]


def test_plain_text_url_with_a_login_part():
    # The reader sees paypal.com at the start, and the browser goes to evil.com
    parsed = parse_bytes((HEADERS + "\r\nhttps://paypal.com@evil.com/login").encode())
    assert check_link_mismatch(parsed).evidence == "text shows paypal.com but goes to evil.com"


@pytest.mark.parametrize("href, text", [
    # A URL in the text is only read up to its path, where login.aspx isn't a site
    ("http://10.0.0.5/app/login.aspx", "http://10.0.0.5/app/login.aspx"),
    ("https://evil.com/", "See https://evil.com/files/paypal.com.html today"),
    ("https://evil.com/", r"https://evil.com\paypal.com"),
])
def test_url_in_the_text_is_read_up_to_its_path(href, text):
    assert mismatch(href, text).result == Result.PASS


def safe_link(url: str) -> str:
    return "https://nam02.safelinks.protection.outlook.com/?url=" + quote(url, safe="") + "&amp;data=x&amp;reserved=0"


@pytest.mark.parametrize("goes_to, result, evidence", [
    ("https://www.paypal.com/signin", Result.PASS, "No link shows one domain and goes to another"),
    ("https://evil.com/", Result.FLAG, "text shows www.paypal.com but goes to evil.com"),
])
def test_a_wrapped_link_is_checked_where_it_really_goes(goes_to, result, evidence):
    parsed = html_email(f'<a href="{safe_link(goes_to)}">www.paypal.com</a>')
    assert links_in(parsed) == [(goes_to, "www.paypal.com")]
    check = check_link_mismatch(parsed)
    assert (check.result, check.evidence) == (result, evidence)


def test_a_wrapped_url_in_plain_text_matches_where_it_goes():
    # Safe Links rewrites a plain text part's URLs too
    url = safe_link("https://www.paypal.com/").replace("&amp;", "&")
    parsed = parse_bytes((HEADERS + f"\r\nSign in at {url} today").encode())
    assert links_in(parsed) == [("https://www.paypal.com/", url)]
    assert check_link_mismatch(parsed).result == Result.PASS


def test_a_wrapper_naming_two_links_is_a_link_to_each():
    parsed = html_email('<a href="https://www.google.com/url?q=https://www.paypal.com/&amp;url=https://paypa1.com/">'
                        'www.paypal.com</a>')
    assert links_in(parsed) == [("https://paypa1.com/", "www.paypal.com"),
                                ("https://www.paypal.com/", "www.paypal.com")]
    assert check_link_mismatch(parsed).evidence == "text shows www.paypal.com but goes to paypa1.com"
    assert check_lookalike(parsed).result == Result.FLAG
    assert indicators_from_email(parsed, None).urls == ["https://paypa1.com/", "https://www.paypal.com/"]


def test_a_wrapper_naming_two_links_warns():
    two = '<a href="https://www.google.com/url?q=https://www.paypal.com/&amp;url=https://evil.com/">Click here</a>'
    assert html_email(two * 2).parse_warnings == [
        "Where a link goes isn't known, since it names more than one place: hxxps://evil[.]com/ or "
        "hxxps://www[.]paypal[.]com/. Check it by hand."]


def test_many_wrappers_naming_two_links_give_one_warning():
    links = "".join(f'<a href="https://www.google.com/url?q=https://a{n}.com/&amp;url=https://b{n}.com/">x</a>'
                    for n in range(7))
    first_five = "; ".join(f"hxxps://a{n}[.]com/ or hxxps://b{n}[.]com/" for n in range(5))
    assert html_email(links).parse_warnings == [
        f"Where a link goes isn't known, since it names more than one place: {first_five} (and 2 more). "
        "Check it by hand."]


def test_a_google_redirect_shown_in_text_flags():
    body = "Sign in at https://www.google.com/url?q=https://evil.com/login today"
    parsed = parse_bytes((HEADERS + "\r\n" + body).encode())
    assert check_link_mismatch(parsed).evidence == "text shows www.google.com but goes to evil.com"


def test_a_link_behind_googles_redirect_flags():
    parsed = html_email('<a href="https://www.google.com/url?q=https://www.paypal.com/&amp;url=https://evil.com/">'
                        'Click here</a><a href="https://www.example.com/">example.com</a>')
    assert [link.through_google for link in parsed.links] == [True, True, False]
    assert check_google_redirect(parsed) == [Check(
        "Google redirect", "flag", "weak", "Google's redirect page sends links on to evil.com; www.paypal.com, so a "
        "filter that reads where a link points sees google.com")]
    assert check_google_redirect(html_email('<a href="https://www.example.com/">example.com</a>')) == []


def test_a_lookalike_behind_a_wrapper_is_found():
    # The wrapper is Microsoft's, and where the link goes is the phisher's
    parsed = html_email(f'<a href="{safe_link("https://paypa1.com/login")}">Sign in</a>')
    assert check_lookalike(parsed).evidence == (
        "paypa1.com [link] spells 'paypal' with lookalike characters but isn't paypal.com")


@pytest.mark.parametrize("href, evidence", [
    ("javascript:alert(1)", "javascript:alert(1) runs a script"),
    ("JavaScript:alert(1)", "JavaScript:alert(1) runs a script"),
    # Browsers drop tabs and line breaks in a link, so this still runs
    ("java&#9;script:alert(1)", "java\tscript:alert(1) runs a script"),
    ("vbscript:msgbox", "vbscript:msgbox runs a script"),
    ("data:text/html,<script>x</script>", "data:text/html,<script>x</script> holds a whole page or file inside "
     "the link"),
    ("data:image/png;base64,AAAA", "data:image/png;base64,AAAA holds a whole page or file inside the link"),
    ("data:text/html;base64," + "A" * 100, "data:text/html;base64,AAAAAAAAAAAAAAAAAA... holds a whole page or "
     "file inside the link"),
    ("file://evil.com/share/x.exe", "file://evil.com/share/x.exe opens a file or a file share"),
    (r"\\evil.com\share", r"\\evil.com\share opens a file share in Outlook for Windows"),
    ("\\&#9;\\evil.com\\share", "\\\t\\evil.com\\share opens a file share in Outlook for Windows"),
    (r"C:\Users\Public\x.exe", r"C:\Users\Public\x.exe opens a file on the reader's computer"),
    # Any other link type opens a program. Phishing has used these two to run malware.
    ("search-ms:query=invoice", "search-ms:query=invoice opens another program, not a web page"),
    ("ms-appinstaller:?source=https://e.com/x", "ms-appinstaller:?source=https://e.com/x opens another program, "
     "not a web page"),
])
def test_script_file_or_app_link_flags(href, evidence):
    check = check_link_type(html_email(f'<a href="{href}">Open</a>'))
    assert (check.result, check.evidence) == (Result.FLAG, evidence)


def test_the_same_link_is_listed_once():
    check = check_link_type(html_email('<a href="javascript:x()">a</a>' * 3))
    assert check.evidence == "javascript:x() runs a script"


def test_script_or_file_url_the_html_loads_flags():
    check = check_link_type(html_email('<form action="javascript:steal()"><img src="file://evil.com/x.png">'))
    assert check.evidence == "javascript:steal() runs a script; file://evil.com/x.png opens a file or a file share"


def test_web_mail_and_inline_image_links_pass():
    # Images often come inline as data: URLs, or as an attached part (cid:). Apple Mail adds
    # x-apple-data-detectors: links around dates and addresses.
    parsed = html_email('<a href="https://x.com/">x</a><a href="mailto:a@x.com">a</a><a href="/x">x</a>'
                        '<a href="tel:+15550100">call</a><a href="sms:+15550100">text</a><a href="#top">top</a>'
                        '<a href="x-apple-data-detectors://0">Tuesday</a><iframe src="about:blank"></iframe>'
                        '<img src="data:image/png;base64,AAAA"><img src="cid:logo">')
    check = check_link_type(parsed)
    assert (check.result, check.evidence) == (Result.PASS, "Every link opens a web page or an email")


def test_attributes_without_a_url_are_skipped():
    parsed = html_email('<img src><img src=""><img src=" "><link href><p class="https://evil.com/">')
    assert parsed.other_urls == []


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


@pytest.mark.parametrize("element", ["style", "script", "title", "iframe", "noembed", "noframes"])
def test_text_inside_an_element_browsers_dont_show_isnt_link_text(element):
    # The reader sees paypal.com. Reading the space inside would give "paypal .com", which isn't a domain.
    parsed = html_email(f'<a href="https://evil.com/">paypal<{element}> x </{element}>.com</a>')
    assert links_in(parsed) == [("https://evil.com/", "paypal.com")]


@pytest.mark.parametrize("hidden", [
    "<template> x </template>",
    "<span hidden> x </span>",
    '<span style="display:none"> x </span>',
    '<span style="visibility:hidden"> x </span>',
    '<span style="font-size:0"> x </span>',
    '<span style="font-size:0.0pt"> x </span>',
    '<span style="opacity:0"> x </span>',
    # Read the way CSS reads it: any case, comments, spaces, !important, and the last value wins
    '<span style="DISPLAY : None !important"> x </span>',
    '<span style="display:/* x */none"> x </span>',
    '<span style="display:block; display:none"> x </span>',
    '<span style="display:none !important; display:block"> x </span>',
    # Browsers ignore the / and leave the span open until </span>
    "<span hidden/> x </span>",
    # Inside a shown element inside a hidden one
    "<span hidden><b> x </b></span>",
    # Font size scales from the parent's, so a zero stays zero
    '<span style="font-size:0"><b style="font-size:2em"> x </b></span>',
])
def test_text_a_browser_hides_isnt_link_text(hidden):
    parsed = html_email(f'<a href="https://evil.com/">paypal{hidden}.com</a>')
    assert links_in(parsed) == [("https://evil.com/", "paypal.com")]
    assert check_link_mismatch(parsed).evidence == "text shows paypal.com but goes to evil.com"


@pytest.mark.parametrize("shown", [
    # The hidden attribute works through display, so setting display shows it again
    '<span hidden style="display:inline">x</span>',
    # A child can set visibility and font size back
    '<span style="visibility:hidden"><b style="visibility:visible">x</b></span>',
    '<span style="font-size:0"><b style="font-size:14px">x</b></span>',
    # Text after a hidden element is shown. In <svg>, the / does close an element.
    "<span hidden></span>x",
    '<svg><g style="display:none"/><text>x</text></svg>',
    # Not hidden
    '<span style="font-size:0.5px; opacity:0.5; display:inline">x</span>',
])
def test_text_a_browser_shows_is_link_text(shown):
    assert links_in(html_email(f'<a href="https://evil.com/">{shown}</a>')) == [("https://evil.com/", "x")]


@pytest.mark.parametrize("hidden", [
    # A rule in a <style> block, which the tool doesn't read
    '<style>.h{display:none}</style><a href="https://evil.com/">paypal<span class="h"> </span>.com</a>',
    # A second value browsers skip because it isn't valid, which the tool takes as the value
    '<a href="https://evil.com/">paypal<span style="display:none;display:x"> </span>.com</a>',
])
@pytest.mark.xfail(reason="Known limitation: a space hidden by CSS the tool doesn't read splits the domain",
                   raises=AssertionError)
def test_space_hidden_by_css_the_tool_doesnt_read(hidden):
    assert check_link_mismatch(html_email(hidden)).result == Result.FLAG


@pytest.mark.parametrize("text, domain", [
    ("pay<b>pal</b>.com", "paypal.com"),
    ("paypal<b>.</b>com", "paypal.com"),
    ("www.<b>paypal</b>.com", "www.paypal.com"),
    # Also read without a tag that holds only spaces or punctuation, since hiding that splits it
    ("paypal<span><i> </i></span>.com", "paypal.com"),
    ("paypal<div> </div>.com", "paypal.com"),
])
def test_tag_in_the_middle_of_a_domain(text, domain):
    assert html_email(f'<a href="https://x.com/">{text}</a>').links[0].split_domains == [domain]


@pytest.mark.parametrize("text", [
    # A domain inside one tag's text, or tags only around it
    "<span>paypal.com</span>",
    "<b>Sign in</b> to <b>example.com</b>",
    '<img src="cid:logo"> paypal.com <b>now</b>',
    # What's in <style> isn't shown, and the tool reads that
    "paypal<style>x</style>.com",
    # CSS can't make a <wbr> show anything
    "https://www.<wbr>paypal.<wbr>com/<wbr>signin",
    # No domain at all
    "<b>Sign</b> <i>in</i>",
])
def test_tags_around_a_domain(text):
    assert html_email(f'<a href="https://x.com/">{text}</a>').links[0].split_domains == []


@pytest.mark.parametrize("text", [
    "example.com<br>Sign in",
    # Browsers read </br> as <br>
    "example.com</br>Sign in",
    "<div>example.com</div><div>Sign in</div>",
    "<table><tr><td>example.com</td><td>Sign in</td></tr></table>",
])
def test_a_line_break_or_block_in_a_link_is_a_space(text):
    # A browser shows the text on either side on its own line or in its own cell. Read as
    # "example.comSign in", the text would show a domain the link doesn't go to.
    parsed = html_email(f'<a href="https://example.com/">{text}</a>')
    assert [(link.text, link.full_text) for link in parsed.links] == [("example.com Sign in", "example.com Sign in")]


def test_a_hidden_block_only_splits_the_text_read_with_the_hidden_parts():
    # A block that's gone takes up no line, so the reader sees the text on either side joined
    link, = html_email('<a href="https://evil.com/">pay<div hidden>x</div>pal.com</a>').links
    assert (link.text, link.full_text) == ("paypal.com", "pay x pal.com")


@pytest.mark.parametrize("text", ["example.com<br>Sign in", "<div>example.com</div><div>Sign in</div>"])
def test_a_domain_at_the_end_of_a_line_in_a_link(text):
    # Read across the tag, it's example.comsign, and comsign isn't a TLD
    assert check_link_mismatch(html_email(f'<a href="https://example.com/">{text}</a>')).result == Result.PASS


@pytest.mark.parametrize("href", ["mailto:x@evil.com", "javascript:void(0)"])
def test_a_tag_in_a_domain_in_a_link_with_no_host(href):
    # The text can't be compared with a site the link doesn't go to, split or not
    check = check_link_mismatch(html_email(f'<a href="{href}">support@pay<b>pal</b>.com</a>'))
    assert check.result == Result.PASS


@pytest.mark.parametrize("text, domain", [
    # A space hidden by CSS the tool doesn't read, which it can't flag but doesn't pass either
    ('<style>.h{display:none}</style>paypal<span class="h"> </span>.com', "paypal.com"),
    ('paypal<span style="display:none;display:x"> </span>.com', "paypal.com"),
    # Hidden by CSS, .evil makes the text match where the link goes
    ('paypal<span class="h">.evil</span>.com', "paypal.evil.com"),
    # A <br> hidden by CSS joins the lines, like a hidden space
    ('<style>.h{display:none}</style>paypal<br class="h">.com', "paypal.com"),
    # On a line of its own, so the next line's text doesn't join it
    ('paypal<i> </i>.com<br>Sign in', "paypal.com"),
    ('<div>paypal<i> </i>.com</div><div>Sign in</div>', "paypal.com"),
])
def test_tag_in_the_middle_of_a_domain_makes_the_link_check_inconclusive(text, domain):
    # The tool can't tell what the reader sees there, so it doesn't pass
    check = check_link_mismatch(html_email(f'<a href="https://evil.com/">{text}</a>'))
    assert (check.result, check.evidence) == (
        Result.INCONCLUSIVE, f"A tag sits in the middle of {domain} in a link to evil.com, where CSS could change "
                             "what the reader sees. Check what the link looks like in a mail client, without "
                             "clicking it.")


def test_a_mismatch_still_flags_and_each_split_is_listed_once():
    split = '<a href="https://evil.com/">paypal<i> </i>.com</a>'
    check = check_link_mismatch(html_email(split * 2 + '<a href="https://evil.net/">paypal<b> </b>.com</a>'))
    assert check.evidence == ("A tag sits in the middle of paypal.com in a link to evil.com; paypal.com in a link "
                              "to evil.net, where CSS could change what the reader sees. Check what the link looks "
                              "like in a mail client, without clicking it.")
    assert check.caveats == []
    # With a mismatch too, the check flags, and the split is kept as a caveat
    check = check_link_mismatch(html_email(split + '<a href="https://evil.net/">paypal.com</a>'))
    assert (check.result, check.evidence) == (Result.FLAG, "text shows paypal.com but goes to evil.net")
    assert check.caveats == ["A tag sits in the middle of paypal.com in a link to evil.com, where CSS could change "
                           "what the reader sees. Check what the link looks like in a mail client, without "
                           "clicking it."]


CSS_CAVEAT = ('CSS adds text to what the email shows, so a link can show more than the tool reads. '
            'See "Text added by CSS".')


@pytest.mark.parametrize("links, result", [
    ('<a href="https://paypal.com/">paypal.com</a>', Result.PASS),
    ('<a href="https://evil.com/">paypal.com</a>', Result.FLAG),
    ('<a href="https://evil.com/">paypal<i> </i>.com</a>', Result.INCONCLUSIVE),
])
def test_css_that_adds_text_is_a_caveat_on_the_link_check(links, result):
    # Whatever the result, a link could show more than the tool reads
    check = check_link_mismatch(html_email('<style>.x::before{content:"."}</style>' + links))
    assert (check.result, check.caveats[-1]) == (result, CSS_CAVEAT)


def test_text_is_read_with_and_without_the_hidden_parts():
    # If the tool took shown text for hidden, reading the hidden parts too still finds the domain
    check = check_link_mismatch(ParsedEmail(links=[Link("https://evil.com/", "", "paypal.com")]))
    assert check.evidence == "text shows paypal.com but goes to evil.com"
    # The full text is only read when the shown text doesn't find a mismatch
    check = check_link_mismatch(ParsedEmail(links=[Link("https://evil.com/", "paypal.com", "paypalx.com")]))
    assert check.evidence == "text shows paypal.com but goes to evil.com"


@pytest.mark.parametrize("html, text", [
    # A browser ends an open element at these tags, so the hidden one doesn't carry on
    ("<p hidden>x<p>shown", "shown"),
    ("<p hidden>x<div>shown", "shown"),
    ("<ul><li hidden>x<li>shown</ul>", "shown"),
    ("<dl><dt hidden>x<dd>shown</dl>", "shown"),
    ("<table><tr><td hidden>x<td>shown</table>", "shown"),
    ("<table><tr hidden><td>x<tr><td>shown</table>", "shown"),
    ("<select><option hidden>x<option>shown</select>", "shown"),
    ("<h1 hidden>x<h2>shown</h2>", "shown"),
    # An end tag closes what's open inside its element. One with nothing to close is skipped.
    ("<div><span hidden>x</div>shown", "shown"),
    ("<span hidden>x</b>y</span>shown", "shown"),
    # But not past a button or a list opened inside it
    ("<p hidden><button><p>x</button></p>shown", "shown"),
    ("<ul><li hidden><ul><li>x</ul></ul>shown", "shown"),
    # Text or a tag put straight into a table is moved in front of it, so a hidden table
    # doesn't hide it. What's in a cell stays hidden, and so does text in a hidden element
    # around the table.
    ('<table style="display:none">shown<tr><td>x</td></tr></table>', "shown"),
    ('<table style="display:none"><tr><span>shown</span><td>x</table>', "shown"),
    ('<div hidden><table>x</table></div>shown', "shown"),
])
def test_elements_a_browser_ends_without_an_end_tag(html, text):
    assert html_email(html).html_text == text


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
    # One base gives no warning or caveat
    assert (parsed.parse_warnings, check_link_mismatch(parsed).caveats) == ([], [])


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
    assert check_link_mismatch(parsed).caveats == ["The HTML has 2 different <base> tags, which set where links "
                                                   "go. Browsers use one, so links were read against each."]


def test_base_limit(monkeypatch):
    # Past the limit some places a link goes weren't read, so the check can't pass
    monkeypatch.setattr(html_reader, "MAX_BASES", 2)
    monkeypatch.setattr("triage.checks.links.MAX_BASES", 2)
    bases = '<base href="https://one.com/"><base href="https://two.com/">'
    at_limit = html_email(bases + '<a href="/login">Sign in</a>')
    assert [href for href, _ in links_in(at_limit)] == ["https://one.com/login", "https://two.com/login"]
    assert check_link_mismatch(at_limit).result == Result.PASS
    over_limit = html_email(bases + '<base href="https://evil.com/"><a href="/login">Sign in</a>')
    assert [href for href, _ in links_in(over_limit)] == ["https://one.com/login", "https://two.com/login"]
    unread = ("The HTML has 3 different <base> tags, which set where links go. Links were read against the "
              "first 2. Check the rest by hand.")
    assert check_link_mismatch(over_limit) == Check("Link mismatch", Result.INCONCLUSIVE, "strong", unread)
    flagged = check_link_mismatch(html_email(bases + '<base href="https://evil.com/">'
                                                     '<a href="/login">paypal.com</a>'))
    assert (flagged.result, flagged.caveats) == (Result.FLAG, [unread])


def test_bases_no_link_uses_dont_count(monkeypatch):
    monkeypatch.setattr(html_reader, "MAX_BASES", 2)
    monkeypatch.setattr("triage.checks.links.MAX_BASES", 2)
    bases = '<base href="https://one.com/"><base href="https://two.com/"><base href="https://evil.com/">'
    check = check_link_mismatch(html_email(bases + '<a href="https://example.org/">example.org</a>'))
    assert (check.result, check.caveats) == (Result.PASS, [])


def test_bases_are_counted_in_each_html_part():
    # A part with no base can't hide the bases in another
    parsed = multipart_email("mixed", "Content-Type: text/html\r\n\r\n<p>Hi</p>",
                             'Content-Type: text/html\r\n\r\n<base href="https://paypal.com/">'
                             '<base href="https://evil.com/"><a href="/login">Sign in</a>')
    assert parsed.base_tags == 2


def test_a_base_only_outlook_reads_is_counted():
    parsed = html_email('<base href="https://paypal.com/"><!--[if mso]><base href="https://evil.com/"><![endif]-->'
                        '<a href="/login">Sign in</a>')
    assert parsed.base_tags == 2


def test_no_break_space_before_a_link_isnt_trimmed():
    # Browsers trim only control characters and spaces, so this is a page on the base's
    # site, not a link to paypal.com
    parsed = html_email('<base href="https://evil.com/"><a href="\N{NO-BREAK SPACE}https://paypal.com/">paypal.com</a>')
    assert check_link_mismatch(parsed).evidence == "text shows paypal.com but goes to evil.com"


def test_html_that_cant_be_parsed_keeps_the_links_before_it(monkeypatch):
    # Python's HTML parser no longer raises on broken markup like <![, so the test raises an
    # error at the <b> inside the second link. That link is kept with its text so far.
    read_tag = html_reader._HTMLCollector.handle_starttag

    def fail_at_bold(self, tag, attrs):
        if tag == "b":
            raise ValueError("broken markup")
        read_tag(self, tag, attrs)

    monkeypatch.setattr(html_reader._HTMLCollector, "handle_starttag", fail_at_bold)
    parsed = html_email('<a href="https://one.com/">one</a><a href="https://two.com/">two <b>bold</b></a>'
                        '<a href="https://three.com/">three</a>')
    assert links_in(parsed) == [("https://one.com/", "one"), ("https://two.com/", "two")]
    assert any("HTML body couldn't be fully parsed (ValueError)" in w for w in parsed.parse_warnings)
