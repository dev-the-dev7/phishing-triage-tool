"""Helpers for reading and comparing domains, link hosts, and IP addresses."""

import ipaddress
import re
import unicodedata
from urllib.parse import unquote, urlsplit

from .lists import SHARED_HOSTING

# Private, carrier-grade NAT, loopback and link-local ranges: hops from these are the mail
# system's own servers. Not Python's is_private, which misses carrier-grade NAT and includes
# reserved ranges like 240.0.0.0/4. A hop from one of those was made up and should stay visible.
INTERNAL_NETWORKS = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10",
    "127.0.0.0/8", "169.254.0.0/16", "::1/128", "fc00::/7", "fe80::/10",
)]


# Second-level labels some countries register under, like co.uk, com.au, ne.jp
COUNTRY_SECOND_LEVEL = {"co", "com", "org", "net", "gov", "ac", "edu", "ne", "or", "go"}


def base_domain(domain: str) -> str:
    # Rough registrable domain: mail.paypal.com -> paypal.com, a.b.co.uk -> b.co.uk.
    # The Public Suffix List would be exact. Until that's added, this covers the common cases.
    domain = domain.lower().strip(".")
    if is_ip(domain):
        return domain

    parts = domain.split(".")
    for suffix in SHARED_HOSTING:
        if domain.endswith("." + suffix):
            # Keep the customer's own label: paypal-login.github.io stays whole
            return ".".join(parts[-(suffix.count(".") + 2):])
    if len(parts) >= 3 and len(parts[-1]) == 2 and parts[-2] in COUNTRY_SECOND_LEVEL:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def registered_name(base: str) -> str:
    # The name the owner registered, from a base domain: chose.com gives chose.
    # Pass it base_domain()'s result, since mail.chose.com would give mail.
    return base.split(".")[0]


# What browsers drop from a link before reading it (the WHATWG URL standard)
C0_OR_SPACE = "".join(chr(i) for i in range(0x21))  # control characters and the space
TAB_OR_NEWLINE = str.maketrans("", "", "\t\n\r")


def browser_url(url: str) -> str:
    # The link rewritten so Python's urlsplit finds the host a browser goes to. Python follows
    # the URL RFC, and browsers differ from it in ways phishers use. All of these go to evil.com:
    #   http://evil.com\@paypal.com      \ counts as /, so @paypal.com is part of the path
    #   http:\\evil.com, http:/evil.com  any slashes after http: work
    #   \\evil.com, /\evil.com           with no scheme, two slashes of either kind take the
    #                                    webmail page's https, like //evil.com does
    #   http://x[@evil.com               the login part, up to the last @, is skipped. Python's
    #                                    parser refuses a [ or ] in it and finds no host at all.
    #   h<tab>ttp://evil.com             tabs and line breaks are dropped, and so are control
    #                                    characters and spaces at either end
    url = url.strip(C0_OR_SPACE).translate(TAB_OR_NEWLINE)
    if re.match(r"[/\\]{2}", url):
        url = "https:" + url
    web_link = re.match(r"(https?):[/\\]*", url, re.I)
    if web_link:
        rest = url[web_link.end():].replace("\\", "/")
        login_and_host = re.match(r"[^/?#]*", rest).group()
        url = f"{web_link.group(1)}://{login_and_host.rpartition('@')[2]}{rest[len(login_and_host):]}"
    return url


def url_host(url: str) -> str | None:
    # The host a link goes to, read the way a browser reads it (see browser_url). The host is
    # percent-decoded (http://%65vil.com), and fullwidth letters and other dots are read as plain
    # ones (http://ｅｖｉｌ。com). A trailing dot is dropped, since evil.com. is the same site in DNS.
    try:
        name = urlsplit(browser_url(url)).hostname
    except ValueError:
        return None
    if not name:
        return None
    return normalize_unicode(unquote(name)).rstrip(".") or None


def normalize_unicode(text: str) -> str:
    # Invisible formatting characters (zero-width space, soft hyphen) are dropped. Readers
    # don't see them, browsers drop them from a link's host, and phishers hide them inside
    # names and links to get past filters (Z-WASP used this against Office 365).
    text = "".join(ch for ch in text if unicodedata.category(ch) != "Cf")
    # Fullwidth and styled letters become plain ones (ｐ, 𝐩 to p), and IDNA's other dots (。．｡)
    # become ".", as browsers do to a link's host: ｐａｙｐａ１。com goes to paypa1.com.
    return unicodedata.normalize("NFKC", text).replace("\u3002", ".").lower()


def decode_idn(domain: str) -> str:
    # xn--pypal-4ve.com -> pаypal.com (with a Cyrillic а), to compare with paypal.com.
    # Labels are decoded one at a time, and a broken one is kept as written and still checked.
    labels = []
    for label in domain.split("."):
        if label.startswith("xn--"):
            try:
                label = label.encode("ascii").decode("idna")
            except UnicodeError:
                pass
        labels.append(label)
    return ".".join(labels)


# Characters that pass for Latin letters: the digit swaps, plus every lowercase Cyrillic and
# Greek letter that Unicode's confusables list says looks like one. Text is lowercased first,
# which covers a capital whose lowercase form is listed. Written as escapes because they
# look identical on screen.
LOOKALIKE_CHARS = str.maketrans({
    "0": "o", "1": "l", "3": "e", "5": "s",
    # Cyrillic а г е о р с у х ш ѕ і ј ѡ ѵ ү һ ҽ ӏ ԁ ԛ ԝ
    "\u0430": "a", "\u0433": "r", "\u0435": "e", "\u043e": "o", "\u0440": "p", "\u0441": "c",
    "\u0443": "y", "\u0445": "x", "\u0448": "w", "\u0455": "s", "\u0456": "i", "\u0458": "j",
    "\u0461": "w", "\u0475": "v", "\u04af": "y", "\u04bb": "h", "\u04bd": "e", "\u04cf": "l",
    "\u0501": "d", "\u051b": "q", "\u051d": "w",
    # Greek α γ ι ν ο ρ σ υ ϭ ϳ ϸ
    "\u03b1": "a", "\u03b3": "y", "\u03b9": "i", "\u03bd": "v", "\u03bf": "o", "\u03c1": "p",
    "\u03c3": "o", "\u03c5": "u", "\u03ed": "o", "\u03f3": "j", "\u03f8": "p",
})

# Capitals that look like a lowercase letter in most fonts: Latin I, Cyrillic І and Greek Ι
# look like l, and Cyrillic Ь looks like b. Not in LOOKALIKE_CHARS, which runs after
# lowercasing, and only used as a second reading (see lookalike_forms).
CAPITAL_LOOKALIKES = str.maketrans({"I": "l", "\u0406": "l", "\u0399": "l", "\u042c": "b"})


# Letter pairs that pass for one letter. These can't go in LOOKALIKE_CHARS, because
# str.maketrans only takes single characters as keys.
LOOKALIKE_PAIRS = {"rn": "m", "nn": "m", "vv": "w", "cl": "d"}


def unmask_lookalikes(text: str, pairs: bool = True) -> str:
    # paypa1.com -> paypal.com, rnicrosoft.com -> microsoft.com, clocusign.com -> docusign.com
    # Characters are swapped before pairs, which catches a pair made with a swapped
    # character: c1ocusign.com -> clocusign.com -> docusign.com
    text = normalize_unicode(text).translate(LOOKALIKE_CHARS)
    if pairs:
        for pair, letter in LOOKALIKE_PAIRS.items():
            text = text.replace(pair, letter)
    return text


def lookalike_forms(text: str) -> set[str]:
    # Every way to read the text with its lookalikes swapped back. The checks count a match
    # when any form of the text matches any form of the name, so one reading can't hide another.
    #   With and without the letter pairs. Swapping a pair can break a match: amazonnow.com
    #   contains amazon, but nn makes it amazomow. linnedin is a typo of linkedin, but nn
    #   makes it limedin.
    #   With capitals as written and as the lowercase letter they look like, so "PayPaI"
    #   with a capital I passes for PayPal. Not only that way, because "IAN WRIGHT" would
    #   become "lan wrlght". Domains are lowercase, so this only matters for display names.
    forms = set()
    for shown in (text, unicodedata.normalize("NFKC", text).translate(CAPITAL_LOOKALIKES)):
        forms.add(unmask_lookalikes(shown, pairs=False))
        forms.add(unmask_lookalikes(shown))
    return forms


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def has_ip(text: str) -> bool:
    for token in re.findall(r"[0-9a-fA-F:.]+", text):
        try:
            ipaddress.ip_address(token.rstrip("."))
            return True
        except ValueError:
            continue
    return False


def is_internal_ip(ip) -> bool:
    ip = ipaddress.ip_address(ip)
    return any(ip in net for net in INTERNAL_NETWORKS)
