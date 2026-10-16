"""Helpers for reading and comparing domains, link hosts, and IP addresses."""

import ipaddress
import re
import unicodedata
from datetime import date
from pathlib import Path
from urllib.parse import unquote, urlsplit

from .lists import SHARED_HOSTING

# The mail system's own servers. Not Python's is_private, which misses carrier-grade NAT and
# includes reserved ranges. A hop from one of those was made up and should stay visible.
INTERNAL_NETWORKS = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10",
    "127.0.0.0/8", "169.254.0.0/16", "::1/128", "fc00::/7", "fe80::/10",
)]


# The Public Suffix List (publicsuffix.org): endings like com, co.uk and github.io, where
# names under one have different owners. The copy only changes with update_suffixes.py.
PUBLIC_SUFFIX_FILE = Path(__file__).with_name("public_suffix_list.dat")


def _read_suffixes(text: str) -> tuple[set[str], set[str], set[str]]:
    rules, wildcards, exceptions = set(), set(), set()
    for line in text.splitlines():
        # The first word on a line. *.ck covers every name under ck, and !www.ck is an exception.
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
# Hosting services the list doesn't have yet
SUFFIXES |= SHARED_HOSTING
ALL_RULES = (SUFFIXES, WILDCARDS, EXCEPTIONS)
# The list's first section, the endings registries sell names under. The private section after
# it is services that hand out names under their own domain, like github.io.
ICANN_RULES = _read_suffixes(_suffix_list.partition("// ===BEGIN PRIVATE DOMAINS===")[0])
# Every TLD, and the most labels a rule can match, so a host with thousands is still quick
TLDS = {rule.rpartition(".")[2] for rule in SUFFIXES | WILDCARDS | EXCEPTIONS}
MAX_RULE_LABELS = max(rule.count(".") + 2 for rule in SUFFIXES | WILDCARDS | EXCEPTIONS)


def base_domain(domain: str) -> str:
    # The part one owner controls: mail.paypal.com gives paypal.com, and
    # www.paypal-login.github.io gives paypal-login.github.io
    return _owned_part(domain, ALL_RULES)


def hosting_service(domain: str) -> str:
    # The service that handed out a name, like github.io for paypal-login.github.io, or "" for
    # a name someone registered. Only the service's own domain was registered.
    registered = _owned_part(domain, ICANN_RULES)
    return registered if registered != base_domain(domain) else ""


def _owned_part(domain: str, rules: tuple[set[str], set[str], set[str]]) -> str:
    domain = domain.lower().strip(".")
    if is_ip(domain):
        return domain
    labels = domain.split(".")
    # The list writes non-English endings in Unicode, so xn-- labels are compared decoded.
    # Each still decodes to one label, so the count matches.
    names = decode_idn(domain).split(".")
    return ".".join(labels[-(_suffix_length(names, rules) + 1):])


def _suffix_length(labels: list[str], rules: tuple[set[str], set[str], set[str]]) -> int:
    # How many labels at the end are the suffix. An exception wins and is registrable itself,
    # then the longest rule, and with none, the last label.
    suffixes, wildcards, exceptions = rules
    longest_first = range(min(len(labels), MAX_RULE_LABELS), 0, -1)
    for count in longest_first:
        if ".".join(labels[-count:]) in exceptions:
            return count - 1
    for count in longest_first:
        if ".".join(labels[-count:]) in suffixes or (count > 1 and ".".join(labels[-count + 1:]) in wildcards):
            return count
    return 1


def registered_name(base: str) -> str:
    # Takes base_domain()'s result: chose.com gives chose, but mail.chose.com would give mail
    return base.split(".")[0]


# What browsers drop from a link before reading it (the WHATWG URL standard)
C0_OR_SPACE = "".join(chr(i) for i in range(0x21))  # control characters and the space
TAB_OR_NEWLINE = str.maketrans("", "", "\t\n\r")


def browser_url(url: str) -> str:
    # Rewritten so urlsplit finds the host a browser goes to. Browsers bend the URL rules in
    # ways phishers use, and all of these go to evil.com:
    #   http://evil.com\@paypal.com      \ counts as /
    #   http:\\evil.com, http:/evil.com  any slashes work
    #   \\evil.com, /\evil.com           takes the page's https, like //evil.com
    #   http://x[@evil.com               the login part is skipped (Python refuses the [)
    #   h<tab>ttp://evil.com             tabs and line breaks are dropped
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
    # Read the way a browser reads it: percent-decoded, with fullwidth letters and other dots
    # made plain (http://ｅｖｉｌ。com), and no trailing dot
    try:
        name = urlsplit(browser_url(url)).hostname
    except ValueError:
        return None
    if not name:
        return None
    host = normalize_unicode(unquote(name)).rstrip(".")
    return browser_ipv4(host) or host or None


def browser_ipv4(host: str) -> str | None:
    # Browsers read a host ending in a number as IPv4, in forms ipaddress refuses:
    # http://3627734532/, http://0xd83ad604/ and http://0330.072.0326.04/ all go to
    # 216.58.214.4. The last part fills the bytes left (WHATWG URL standard).
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
    # The xn-- form DNS, proxy logs and blocklists use. One the encoder refuses is kept as is.
    try:
        return domain.encode("idna").decode("ascii")
    except UnicodeError:
        return domain


# A URL written in text, which mail clients make clickable. Punctuation at the end belongs to
# the sentence.
TEXT_URL = re.compile(r"(?<![\w.])(?:https?://|www\.)[^\s<>\"'`]+", re.I)


def urls_in_text(text: str) -> list[str]:
    return [m.group().rstrip(".,;:!?)]}*") for m in TEXT_URL.finditer(text)]


def domains_in_text(text: str) -> list[str]:
    # Any letters count, so Cyrillic text that looks like paypal.com is found. The ending has
    # to be a real TLD, or look like one (corn for com), so invoice.pdf and Thanks.Regards
    # aren't domains.
    found = re.finditer(r"(?<![\w.-])(?:[\w-]+\.)+([^\W\d_]{2,}|xn--[a-z0-9-]+)(?![\w-])", normalize_unicode(text))
    return [m.group(0) for m in found if _passes_for_tld(decode_idn(m.group(1)))]


def _passes_for_tld(label: str) -> bool:
    return any(form in TLDS for form in (label, unmask_lookalikes(label, pairs=False), unmask_lookalikes(label)))


def normalize_unicode(text: str) -> str:
    # Invisible formatting characters (zero-width space, soft hyphen) are dropped, as browsers
    # do in a host. Phishers hide them in names to get past filters.
    text = "".join(ch for ch in text if unicodedata.category(ch) != "Cf")
    # Fullwidth and styled letters become plain, and IDNA's other dots become "."
    return unicodedata.normalize("NFKC", text).replace("\u3002", ".").lower()


def decode_idn(domain: str) -> str:
    # xn--pypal-4ve.com -> pаypal.com, to compare with paypal.com. A broken label is kept as is.
    labels = []
    for label in domain.split("."):
        if label.startswith("xn--"):
            try:
                label = label.encode("ascii").decode("idna")
            except UnicodeError:
                pass
        labels.append(label)
    return ".".join(labels)


# Characters that pass for Latin letters: digit swaps, and the lowercase Cyrillic and Greek
# letters Unicode's confusables list maps to one. Escapes, since they look identical on screen.
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

# Capitals that look like a lowercase letter: I, Cyrillic І and Greek Ι look like l, and Ь
# like b. Kept apart, since LOOKALIKE_CHARS runs after lowercasing.
CAPITAL_LOOKALIKES = str.maketrans({"I": "l", "\u0406": "l", "\u0399": "l", "\u042c": "b"})


# Letter pairs that pass for one letter, kept out of LOOKALIKE_CHARS since str.maketrans
# only takes single characters
LOOKALIKE_PAIRS = {"rn": "m", "nn": "m", "vv": "w", "cl": "d"}


def unmask_lookalikes(text: str, pairs: bool = True) -> str:
    # paypa1.com -> paypal.com, rnicrosoft.com -> microsoft.com. Characters go before pairs, so
    # c1ocusign.com still becomes docusign.com.
    text = normalize_unicode(text).translate(LOOKALIKE_CHARS)
    if pairs:
        for pair, letter in LOOKALIKE_PAIRS.items():
            text = text.replace(pair, letter)
    return text


def lookalike_forms(text: str) -> set[str]:
    # Every reading with lookalikes swapped back, since one can hide another: with and without
    # pairs (nn turns amazonnow into amazomow), and with capitals as written and as the letter
    # they look like (PayPaI with a capital I, but IAN WRIGHT isn't lan wrlght).
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
