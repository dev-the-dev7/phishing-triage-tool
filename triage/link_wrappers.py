"""Reading the real link out of one rewritten by a mail security service or Google's redirect."""

import base64
import re
import string
from urllib.parse import parse_qs, unquote, urlsplit

from .domains import browser_url, url_host

# A link can be wrapped more than once, by the sender's service and then the reader's. Real
# ones are two or three deep, and the limit keeps a link wrapped thousands of times quick.
MAX_WRAPPERS = 5

# Microsoft Defender's Safe Links, with a host for each region (nam02, eur01), and the US
# government cloud's
SAFE_LINKS = ("safelinks.protection.outlook.com", "safelinks.protection.office365.us")
# Proofpoint's decoder reads every version on either host
PROOFPOINT = {"urldefense.proofpoint.com", "urldefense.com"}
# Google's redirect page, which phishing uses so a link starts with google.com
GOOGLE = {"google.com", "www.google.com"}

SCHEME = re.compile(r"[a-z][a-z\d+.-]*:", re.I)
WEB_PAGE = re.compile(r"https?:", re.I)

# Proofpoint v2 writes % as - and / as _
PROOFPOINT_V2 = str.maketrans("-_", "%/")
# Proofpoint v3 swaps some characters for *, and a run of them for ** and a letter giving its
# length (A is 2, B is 3), and lists what they were in base64 after the link
PROOFPOINT_V3_RUNS = string.ascii_uppercase + string.ascii_lowercase + string.digits + "-_"


def unwrap(url: str, redirects: bool = True) -> str:
    # Only the services' own hosts are read, so safelinks.protection.outlook.com.evil.com stays
    # a link to evil.com. A wrapper naming two links is kept. redirects=False leaves Google's.
    for _ in range(MAX_WRAPPERS):
        links = _inner_links(url, redirects)
        if len(links) != 1:
            return url
        url = links.pop()
    return url


def destinations(url: str, depth: int = MAX_WRAPPERS) -> list[str]:
    # Where a link goes, read out of any wrappers. A wrapper naming two different links gives
    # both, each read the same way, since which one the service follows isn't known. Only so
    # deep, since a crafted link could nest hundreds of them and run out of stack.
    url = unwrap(url)
    links = _inner_links(url, redirects=True)
    if len(links) < 2 or depth == 0:
        return [url]
    return sorted({place for link in links for place in destinations(link, depth - 1)})


def through_google(url: str) -> bool:
    # Whether the sender put a link behind Google's redirect, even when Safe Links or
    # Proofpoint wrapped it again on the way in
    inner = unwrap(url, redirects=False)
    return url_host(inner) in GOOGLE and bool(_inner_links(inner, redirects=True))


def _inner_links(url: str, redirects: bool) -> set[str]:
    # The links a wrapper names, or none when it isn't one
    host = url_host(url)
    if not host:
        return set()
    url = browser_url(url)
    parts = urlsplit(url)
    query = parse_qs(parts.query)
    if any(host == name or host.endswith("." + name) for name in SAFE_LINKS):
        found = query.get("url", [])
    elif host in PROOFPOINT and parts.path == "/v1/url":
        found = query.get("u", [])
    elif host in PROOFPOINT and parts.path == "/v2/url":
        found = [unquote(value.translate(PROOFPOINT_V2)) for value in query.get("u", [])]
    elif host in PROOFPOINT and parts.path.startswith("/v3/__"):
        found = [_proofpoint_v3(url)]
    elif redirects and host in GOOGLE and parts.path == "/url":
        # q= is the link, except on a search result, where it's the search and url= is the link.
        # Google only sends on to web pages, so a search like site:example.com isn't a link.
        found = [value for value in query.get("q", []) + query.get("url", [])
                 if WEB_PAGE.match(browser_url(value))]
    else:
        return set()
    # Read the way a browser reads them, so a space in front or //evil.com still goes to
    # evil.com, and only whole links, with a scheme, count
    return {link for link in map(browser_url, found) if SCHEME.match(link)}


def _proofpoint_v3(url: str) -> str:
    # https://urldefense.com/v3/__https://example.com/a*b__;Kw!!...$ is https://example.com/a+b,
    # since Kw is base64 for +. Found with find(), not a regex, so thousands of /v3/__ stay quick.
    start = url.find("/v3/__") + len("/v3/__")
    end = url.find("__;", start)
    if end < 0:
        return ""
    swapped = re.match(r"[A-Za-z0-9_-]*", url[end + 3:]).group()
    # Anything that doesn't decode leaves the wrapper as it is
    try:
        original = base64.urlsafe_b64decode(swapped + "=" * (-len(swapped) % 4)).decode("utf-8")
    except ValueError:
        return ""
    position = 0

    def put_back(mark: re.Match) -> str:
        nonlocal position
        length = 1 if mark.group() == "*" else PROOFPOINT_V3_RUNS.index(mark.group()[2]) + 2
        characters = original[position:position + length]
        position += length
        if len(characters) < length:
            raise ValueError("more marks than characters")
        return characters

    # index() raises ValueError too, for a run length that isn't one
    try:
        return re.sub(r"\*(\*.)?", put_back, unquote(url[start:end]))
    except ValueError:
        return ""
