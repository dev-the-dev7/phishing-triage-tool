"""Checks on links in the body: does the text show the same domain the link goes to, does the
link open a web page at all, and was it put behind Google's redirect."""

import re

from ..domains import TAB_OR_NEWLINE, TEXT_URL, decoded_base, domains_in_text, url_host
from ..models import Check, ParsedEmail, Result, Strength, join_first_five
from ..reading.html_reader import MAX_BASES
from ..reading.link_wrappers import unwrap

# Links that open a web page, an empty one (about:blank), an email, a call, a text or an
# attached image (cid:), and the ones Apple Mail adds around dates and addresses. Anything
# else goes to a script, a file or a program.
WEB_OR_MAIL = {"http", "https", "about", "mailto", "tel", "sms", "cid", "x-apple-data-detectors"}
# The ones phishing uses most. Others, like search-ms: and ms-appinstaller:, open a program,
# and phishing has used both to run malware.
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
        # What the reader sees, then all of it, hidden parts too, so a wrong guess about what's
        # hidden can't hide a domain
        for text in dict.fromkeys([link.text, link.full_text]):
            shown_domain = _shown_domain(text)
            # Both decoded, so a Unicode domain and its xn-- form match. The lookalike check
            # covers that domain.
            if shown_domain and decoded_base(shown_domain) != decoded_base(href_host):
                mismatches.append(f"text shows {shown_domain} but goes to {href_host}")
                break

    # A tag inside a domain is where CSS could change what the reader sees, and past the limit
    # some <base> tags weren't read. On their own they make the check inconclusive, and next to
    # a mismatch they're caveats.
    unsure = []
    split = list(dict.fromkeys(split))
    if split:
        unsure.append(f"A tag sits in the middle of {join_first_five(split)}, where CSS could change what the "
                      "reader sees. Check what the link looks like in a mail client, without clicking it.")
    caveats = []
    if parsed.base_tags > MAX_BASES:
        unsure.append(f"The HTML has {parsed.base_tags} different <base> tags, which set where links go. Links "
                      f"were read against the first {MAX_BASES}. Check the rest by hand.")
    elif parsed.base_tags > 1:
        # Every reading was checked, but a flag may come from a base browsers skip
        caveats.append(f"The HTML has {parsed.base_tags} different <base> tags, which set where links go. "
                       "Browsers use one, so links were read against each.")
    if parsed.css_added_text:
        caveats.append('CSS adds text to what the email shows, so a link can show more than the tool reads. '
                       'See "Text added by CSS".')

    if mismatches:
        return Check(name, Result.FLAG, strength, join_first_five(mismatches), unsure + caveats)
    if unsure:
        return Check(name, Result.INCONCLUSIVE, strength, " ".join(unsure), caveats)
    return Check(name, Result.PASS, strength, "No link shows one domain and goes to another", caveats)


def _shown_domain(text: str) -> str | None:
    # A URL is only read up to its path, since the reader takes the start as the site:
    # https://paypal.com@evil.com/ shows paypal.com. Safe Links and Proofpoint rewrite the URLs
    # a plain text part shows too, so those are read as where they go. A Google redirect isn't,
    # since the sender chose it and the reader sees google.com.
    def site(url: re.Match) -> str:
        return re.match(r"(?:https?:/*)?[^/\\?#]*", unwrap(url.group(), redirects=False), re.I).group()

    text = TEXT_URL.sub(site, text)
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


def check_google_redirect(parsed: ParsedEmail) -> list[Check]:
    # Phishing puts links behind Google's redirect so a filter reading the host sees google.com.
    # Weak, since Google's own mail, like Calendar invitations, does it too.
    hosts = list(dict.fromkeys(url_host(link.href) or link.href for link in parsed.links if link.through_google))
    if not hosts:
        return []
    return [Check("Google redirect", Result.FLAG, Strength.WEAK,
                  f"Google's redirect page sends links on to {join_first_five(hosts)}, so a filter that "
                  "reads where a link points sees google.com")]


def _scheme(href: str) -> str:
    # Lowercased, the way browsers read it, with tabs and line breaks dropped
    scheme = re.match(r"([a-z][a-z\d+.-]*):", href.translate(TAB_OR_NEWLINE), re.I)
    return scheme.group(1).lower() if scheme else ""
