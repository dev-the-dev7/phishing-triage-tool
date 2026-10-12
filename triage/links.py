"""Checks on links in the body: does the text show the same domain the link goes to."""

import re

from .domains import base_domain, decode_idn, normalize_unicode, url_host
from .models import Check, ParsedEmail, Result, Strength, join_first_five


# File names like "invoice.pdf" look like domains to the regex. .zip and .mov are
# left out on purpose because they're real TLDs that phishers use.
FILE_EXTENSIONS = {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "htm", "html",
                   "txt", "csv", "png", "jpg", "jpeg", "gif"}


def check_link_mismatch(parsed: ParsedEmail) -> Check:
    name, strength = "Link text vs destination", Strength.STRONG
    mismatches = []
    for link in parsed.links:
        href_host = url_host(link.href)
        shown_domain = _domain_in_text(link.text)
        # Both sides decoded: text showing a Unicode domain that goes to the same domain's
        # xn-- form is a match. The lookalike check is what flags that domain.
        if href_host and shown_domain and base_domain(decode_idn(shown_domain)) != base_domain(decode_idn(href_host)):
            mismatches.append(f"text shows {shown_domain} but goes to {href_host}")

    if mismatches:
        return Check(name, Result.FLAG, strength, join_first_five(mismatches))
    return Check(name, Result.PASS, strength, "No link shows one domain and goes to another")


def _domain_in_text(text: str) -> str | None:
    # Normalized like the link's host, and any letters count ([^\W\d_]), not just a-z, so
    # fullwidth or Cyrillic text that looks like paypal.com is still found.
    for m in re.finditer(r"(?<![\w.-])(?:[\w-]+\.)+([^\W\d_]{2,})(?![\w-])", normalize_unicode(text)):
        if m.group(1) not in FILE_EXTENSIONS:
            return m.group(0)
    return None
