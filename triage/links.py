"""Checks on links in the body: does the text show the same domain the link goes to, and does
the link open a web page at all."""

import re

from .domains import TAB_OR_NEWLINE, TEXT_URL, base_domain, decode_idn, domains_in_text, url_host
from .models import Check, ParsedEmail, Result, Strength, join_first_five

# Links that open a web page, an empty one (about:blank), an email, a call or a text message,
# or an image attached to the email (cid:). Apple Mail adds x-apple-data-detectors: links
# around dates and addresses it spots. Anything else hands the link to a script, a file, or
# another program.
WEB_OR_MAIL = {"http", "https", "about", "mailto", "tel", "sms", "cid", "x-apple-data-detectors"}
# What the ones phishing uses most do. Others, like search-ms: and ms-appinstaller:, open a
# Windows program, and phishing has used both to run malware.
LINK_TYPES = {
    "javascript": "runs a script",
    "vbscript": "runs a script",
    "data": "holds a whole page or file inside the link",
    "file": "opens a file or a file share",
}


def check_link_mismatch(parsed: ParsedEmail) -> Check:
    name, strength = "Link text vs destination", Strength.STRONG
    mismatches, split = [], []
    for link in parsed.links:
        href_host = url_host(link.href)
        # A link with no host (mailto:, a script) doesn't go to a site to compare the text with
        if not href_host:
            continue
        split += [f"{domain} in a link to {href_host}" for domain in link.split_domains]
        # What the reader sees, then every bit of text in the link, hidden parts too. The tool
        # can't always tell what a browser hides, and reading both means a mistake either way
        # can't hide a domain.
        for text in dict.fromkeys([link.text, link.full_text]):
            shown_domain = _shown_domain(text)
            # Both sides decoded: text showing a Unicode domain that goes to the same domain's
            # xn-- form is a match. The lookalike check is what flags that domain.
            if shown_domain and base_domain(decode_idn(shown_domain)) != base_domain(decode_idn(href_host)):
                mismatches.append(f"text shows {shown_domain} but goes to {href_host}")
                break

    # A tag in the middle of a domain is where CSS the tool doesn't read could hide part of the
    # text or add to it, so the tool can't say what the reader sees there. With no mismatch,
    # that makes the check inconclusive, since a pass would promise more than it knows. With
    # one, the check flags, and the split is a caveat.
    split = list(dict.fromkeys(split))
    split_text = (f"A tag sits in the middle of {join_first_five(split)}, where CSS could change what the reader "
                  "sees. Check what the link looks like in a mail client, without clicking it.")
    caveats = []
    if parsed.css_added_text:
        caveats.append('CSS adds text to what the email shows, so a link can show more than the tool reads. '
                       'See "Text added by CSS".')

    if mismatches:
        if split:
            caveats.insert(0, split_text)
        return Check(name, Result.FLAG, strength, join_first_five(mismatches), caveats)
    if split:
        return Check(name, Result.INCONCLUSIVE, strength, split_text, caveats)
    return Check(name, Result.PASS, strength, "No link shows one domain and goes to another", caveats)


def _shown_domain(text: str) -> str | None:
    # The first domain in the text. A URL written in it is only read up to its path, since the
    # reader takes the start as the site: in https://paypal.com@evil.com/ that's paypal.com,
    # and in http://10.0.0.5/app/login.aspx, login.aspx isn't a site anyone would trust.
    text = TEXT_URL.sub(lambda m: re.match(r"(?:https?:/*)?[^/\\?#]*", m.group(), re.I).group(), text)
    return next(iter(domains_in_text(text)), None)


def check_link_type(parsed: ParsedEmail) -> Check:
    name, strength = "Script, file or app link", Strength.MEDIUM
    # Images often come inline as data: URLs, which is normal. A link to one isn't.
    hrefs = [link.href for link in parsed.links] + [url for url in parsed.other_urls if _scheme(url) != "data"]
    found = []
    for href in hrefs:
        shown = href if len(href) <= 40 else href[:40] + "..."
        scheme = _scheme(href)
        if href.translate(TAB_OR_NEWLINE).startswith("\\\\"):
            # A browser reads \\server\path as a web link, but Outlook for Windows opens it as
            # a file share, and Windows can send the reader's sign-in to that server
            found.append(f"{shown} opens a file share in Outlook for Windows")
        elif len(scheme) == 1:
            found.append(f"{shown} opens a file on the reader's computer")  # a drive letter, C:\
        elif scheme and scheme not in WEB_OR_MAIL:
            found.append(f"{shown} {LINK_TYPES.get(scheme, 'opens another program, not a web page')}")

    if found:
        return Check(name, Result.FLAG, strength, join_first_five(list(dict.fromkeys(found))))
    return Check(name, Result.PASS, strength, "Every link opens a web page or an email")


def _scheme(href: str) -> str:
    # Lowercased, the way browsers read it, with tabs and line breaks dropped
    scheme = re.match(r"([a-z][a-z\d+.-]*):", href.translate(TAB_OR_NEWLINE), re.I)
    return scheme.group(1).lower() if scheme else ""
