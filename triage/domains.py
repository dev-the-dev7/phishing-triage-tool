"""Helpers for reading and comparing domains, link hosts, and IP addresses."""

import ipaddress
import re
import unicodedata
from datetime import date
from pathlib import Path
from urllib.parse import unquote, urlsplit

from .lists import SHARED_HOSTING

# Private, carrier-grade NAT, loopback and link-local ranges: hops from these are the mail
# system's own servers. Not Python's is_private, which misses carrier-grade NAT and includes
# reserved ranges like 240.0.0.0/4. A hop from one of those was made up and should stay visible.
INTERNAL_NETWORKS = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10",
    "127.0.0.0/8", "169.254.0.0/16", "::1/128", "fc00::/7", "fe80::/10",
)]


# The Public Suffix List (publicsuffix.org): the endings people register names under, like
# com, co.uk, and github.io, so two names under one have different owners. Browsers use it
# to keep one site's cookies from another's. A copy ships with the tool, so it works
# offline, and it only changes when you run update_suffixes.py. Rules are one ending per
# line, *.ck means every name under ck is an ending, and !www.ck makes an exception to that.
PUBLIC_SUFFIX_FILE = Path(__file__).with_name("public_suffix_list.dat")


def _read_suffixes(text: str) -> tuple[set[str], set[str], set[str]]:
    rules, wildcards, exceptions = set(), set(), set()
    for line in text.splitlines():
        # A rule is the first word on its line
        words = line.split()
        if not words or words[0].startswith("//"):
            continue
        rule = words[0].lower()
        if rule.startswith("!"):
            exceptions.add(rule[1:])
        elif rule.startswith("*."):
            wildcards.add(rule[2:])
        else:
            rules.add(rule)
    return rules, wildcards, exceptions


def list_date(text: str) -> date | None:
    # When the list was published, from its "// VERSION: 2026-10-07_07-28-19_UTC" line
    found = re.search(r"^// VERSION: ([0-9]{4}-[0-9]{2}-[0-9]{2})", text, re.M)
    return date.fromisoformat(found.group(1)) if found else None


_suffix_list = PUBLIC_SUFFIX_FILE.read_text(encoding="utf-8")
SUFFIXES, WILDCARDS, EXCEPTIONS = _read_suffixes(_suffix_list)
SUFFIX_LIST_DATE = list_date(_suffix_list)
# Hosting services the list doesn't have yet (see lists.py)
SUFFIXES |= SHARED_HOSTING
# Every TLD, and the most labels a rule can match. Only that many labels at the end of a
# host are compared, so one with thousands of labels is still quick.
TLDS = {rule.rpartition(".")[2] for rule in SUFFIXES | WILDCARDS | EXCEPTIONS}
MAX_RULE_LABELS = max(rule.count(".") + 2 for rule in SUFFIXES | WILDCARDS | EXCEPTIONS)


def base_domain(domain: str) -> str:
    # The registrable domain: the public suffix and one label in front of it, which is what
    # one owner controls. mail.paypal.com gives paypal.com, a.b.co.uk gives b.co.uk, and
    # www.paypal-login.github.io gives paypal-login.github.io. A suffix on its own (co.uk)
    # is returned whole.
    domain = domain.lower().strip(".")
    if is_ip(domain):
        return domain
    labels = domain.split(".")
    # The list writes non-English endings in Unicode, so xn-- labels are compared decoded.
    # Each one decodes to one label, so the count stays the same.
    names = decode_idn(domain).split(".")
    return ".".join(labels[-(_suffix_length(names) + 1):])


def _suffix_length(labels: list[str]) -> int:
    # How many labels at the end are the public suffix. An exception wins over every other
    # rule and is registrable itself, so !www.ck makes the suffix ck. Otherwise the rule with
    # the most labels wins, and with none, the suffix is the last label.
    longest_first = range(min(len(labels), MAX_RULE_LABELS), 0, -1)
    for count in longest_first:
        if ".".join(labels[-count:]) in EXCEPTIONS:
            return count - 1
    for count in longest_first:
        if ".".join(labels[-count:]) in SUFFIXES or (count > 1 and ".".join(labels[-count + 1:]) in WILDCARDS):
            return count
    return 1


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
    host = normalize_unicode(unquote(name)).rstrip(".")
    return browser_ipv4(host) or host or None


def browser_ipv4(host: str) -> str | None:
    # Browsers read a host that ends in a number as an IPv4 address, in forms Python's ipaddress
    # refuses. These all go to 216.58.214.4: http://3627734532/, http://0xd83ad604/,
    # http://0330.072.0326.04/, http://216.58.54788/. Each part can be decimal, hex (0x) or
    # octal (a leading 0), and the last part fills the bytes that are left (WHATWG URL standard).
    # None when the host isn't one, or the browser would refuse it.
    parts = host.split(".")
    if not re.fullmatch(r"[0-9]+|0x[0-9a-f]*", parts[-1], re.I) or len(parts) > 4:
        return None
    numbers = []
    for part in parts:
        if re.fullmatch(r"0x[0-9a-f]*", part, re.I):
            numbers.append(int(part[2:] or "0", 16))
        elif re.fullmatch(r"0[0-7]+", part):
            numbers.append(int(part, 8))
        elif re.fullmatch(r"0|[1-9][0-9]{0,9}", part):
            numbers.append(int(part))
        else:
            return None
    *first, last = numbers
    if any(number > 255 for number in first) or last >= 256 ** (5 - len(numbers)):
        return None
    return str(ipaddress.IPv4Address(sum(number << (8 * (3 - i)) for i, number in enumerate(first)) + last))


def ascii_domain(domain: str) -> str:
    # The xn-- form that DNS, proxy logs and blocklists use: pаypal.com with a Cyrillic а is
    # xn--pypal-4ve.com. A domain the encoder refuses (an empty or overlong label) is kept as is.
    try:
        return domain.encode("idna").decode("ascii")
    except UnicodeError:
        return domain


# A URL written out in text, which mail clients make clickable. It runs to the next space,
# quote or backtick (Markdown's `code`), and punctuation at the end is taken as the sentence's,
# along with Markdown's *bold*.
TEXT_URL = re.compile(r"(?<![\w.])(?:https?://|www\.)[^\s<>\"'`]+", re.I)


def urls_in_text(text: str) -> list[str]:
    return [m.group().rstrip(".,;:!?)]}*") for m in TEXT_URL.finditer(text)]


def domains_in_text(text: str) -> list[str]:
    # Domains written in text, normalized like a link's host. Any letters count ([^\W\d_]), not
    # just a-z, so fullwidth or Cyrillic text that looks like paypal.com is still found. The
    # ending has to be a real TLD, or look like one to the reader (com with a Cyrillic с, or
    # corn for com), so file names (invoice.pdf) and words joined by a dot (Thanks.Regards)
    # aren't domains. .zip and .mov are real TLDs, so invoice.zip is one. A non-English TLD
    # can be in its xn-- form, the way DNS and proxy logs write it (xn--p1ai is .рф).
    found = re.finditer(r"(?<![\w.-])(?:[\w-]+\.)+([^\W\d_]{2,}|xn--[a-z0-9-]+)(?![\w-])", normalize_unicode(text))
    return [m.group(0) for m in found if _passes_for_tld(decode_idn(m.group(1)))]


def _passes_for_tld(label: str) -> bool:
    return any(form in TLDS for form in (label, unmask_lookalikes(label, pairs=False), unmask_lookalikes(label)))


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
