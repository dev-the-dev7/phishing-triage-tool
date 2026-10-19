"""Pull IOCs out of an email or pasted alert text, plus the refang/defang helpers."""

import ipaddress
import re
from urllib.parse import unquote, urlsplit, urlunsplit

from .domains import TEXT_URL, ascii_domain, browser_url, domains_in_text, is_ip, url_host, urls_in_text
from .link_wrappers import destinations
from .models import Indicators, Origin, ParsedEmail

EMAIL = re.compile(r"(?<![\w.+%-])[\w.+%-]+@[\w-]+(?:\.[\w-]+)+")
IPV4 = re.compile(r"(?<![0-9.])[0-9]{1,3}(?:\.[0-9]{1,3}){3}(?!\.?[0-9])")
# A reverse DNS name, like those in DNS logs: 5.0.168.192.in-addr.arpa asks for the name of
# 192.168.0.5
REVERSE_DNS = re.compile(r"(?<![\w.-])([0-9]{1,3}(?:\.[0-9]{1,3}){3})\.in-addr\.arpa(?![\w-])", re.I)
# Any .arpa name. Its numbers are written backwards, so they aren't an IP (an IPv6 reverse
# name can start 4.3.2.1.b.a...).
ARPA_NAME = re.compile(r"(?<![\w.-])[\w.-]+\.arpa(?![\w-])", re.I)
HASH = re.compile(r"(?<![0-9a-z])(?:[0-9a-f]{64}|[0-9a-f]{40}|[0-9a-f]{32})(?![0-9a-z])", re.I)

# Defanged forms: evil[.]com, evil (dot) com, x[@]evil.com, https[:]//, hxxp and h**p. Spaces
# in front are only taken from the start of a run, since trying each one would take minutes.
BRACKETED = re.compile(r"(?<![ \t])[ \t]*[\[({]\s*(\.|dot|@|at|:|://|/)\s*[\])}][ \t]*", re.I)
BROKEN_SCHEME = re.compile(r"(?<![a-z])h[x*]{2}p(?=s?:)", re.I)


def refang(text: str) -> str:
    # evil\.com, the way a regex writes it, counts as defanged too
    text = BRACKETED.sub(lambda m: {"dot": ".", "at": "@"}.get(m.group(1).lower(), m.group(1)), text)
    return BROKEN_SCHEME.sub("http", text).replace("\\.", ".")


def defang(indicator: str) -> str:
    # So a chat app, ticket system or mail client doesn't turn it into a live link
    indicator = re.sub(r"(?<![a-z])http(?=s?:)", "hxxp", indicator, flags=re.I)
    return indicator.replace(".", "[.]").replace("@", "[@]")


def defang_text(text: str) -> str:
    # Every link, domain and address in a sentence, without touching the sentence's own full
    # stops, which aren't between two letters
    text = re.sub(r"(?<![a-z])http(?=s?:)", "hxxp", text, flags=re.I)
    text = re.sub(r"(?<=[\w-])\.(?=[\w-])", "[.]", text)
    # Anything an address can have before its @, like the = that ends encoded text
    return re.sub(r"(?<=[\w.!#$%&'*+/=?^`{|}~-])@(?=[\w-])", "[@]", text)


def from_email(parsed: ParsedEmail, origin: Origin | None) -> Indicators:
    # What the email links to, loads and came from. Domains only mentioned in the text aren't
    # listed, since phishing names the real brand to look genuine, and neither is a link's text.
    urls, hosts, emails = [], [], []
    # The email's own addresses first, so a long list of link domains can't push them down
    for address in [*parsed.from_addrs, *parsed.sender, *parsed.reply_to, *parsed.return_path]:
        emails.append(address.email)
        hosts.append(address.domain)
    if origin and origin.ip:
        hosts.append(origin.ip)
    for href in [link.href for link in parsed.links] + parsed.other_urls:
        host = url_host(href)
        if host:
            urls.append(_requested_url(href, host))
            hosts.append(host)
        elif re.match("mailto:", href, re.I):
            emails += EMAIL.findall(unquote(href))
    return _indicators(urls, hosts, emails, [attachment.sha256 for attachment in parsed.attachments])


def from_text(text: str) -> Indicators:
    # Bare domains, IPs and hashes count, since alerts list them that way. URLs and addresses
    # are taken out first, so a file name in a URL's path isn't read as a domain.
    text = refang(text)
    urls, hosts = [], []
    for url in urls_in_text(text):
        # A www. link with no scheme opens as http, and a wrapped one is read as where it goes,
        # since users often report the Safe Links URL they clicked
        for href in destinations("http://" + url if url.lower().startswith("www.") else url):
            host = url_host(href)
            urls.append(_requested_url(href, host) if host else href)
            hosts.append(host)
    text = TEXT_URL.sub(" ", text)
    emails = EMAIL.findall(text)
    hosts += [email.rpartition("@")[2] for email in emails]
    text = EMAIL.sub(" ", text)
    # Paths are dropped too, since .sh and .py are real TLDs: evil.com/run.sh gives evil.com
    hosts += domains_in_text(re.sub(r"(?<=[\w:-])[/\\]\S*", " ", text)) + _ips_in(text)
    return _indicators(urls, hosts, emails, [found.lower() for found in HASH.findall(text)])


def _requested_url(href: str, host: str) -> str:
    # The URL the browser asks for, with the host as DNS writes it, so http://3627734532/ is
    # http://216.58.214.4/ and a Cyrillic pаypal.com doesn't look like the real one
    url = browser_url(href)
    try:
        parts = urlsplit(url)
        port = f":{parts.port}" if parts.port is not None else ""
    except ValueError:
        return url
    netloc = f"[{host}]" if ":" in host else ascii_domain(host)
    return urlunsplit(parts._replace(netloc=netloc + port))


def _ips_in(text: str) -> list[str]:
    # IPv4 by its shape, and IPv6 from runs of hex digits, colons and dots with at least two
    # colons. ipaddress decides which are real, so 999.1.1.1 and a time like 10:30:00 aren't.
    # A reverse DNS name is swapped for its IP written forwards, with spaces so it can't join
    # the next number, and other .arpa names are taken out.
    text = REVERSE_DNS.sub(lambda name: " " + ".".join(reversed(name.group(1).split("."))) + " ", text)
    text = ARPA_NAME.sub(" ", text)
    candidates = IPV4.findall(text)
    for token in re.findall(r"[0-9a-f:.]+", text, re.I):
        if token.count(":") >= 2:
            # A label in front, like ip:2001:db8::1, leaves one colon at the start
            token = token.rstrip(".")
            token = token[1:] if re.match(":[^:]", token) else token
            # At least two groups, since code like [Convert]::FromBase64String leaves ::F, a
            # valid IPv6 address
            if len([group for group in token.split(":") if group]) >= 2:
                candidates.append(token)
    return [ip for ip in candidates if is_ip(ip)]


def _indicators(urls, hosts, emails, hashes) -> Indicators:
    # A dot at the end (evil.com.) is the same domain in DNS
    hosts = [host.lower().rstrip(".") for host in hosts if host]
    return Indicators(
        urls=_unique(urls),
        domains=_unique(ascii_domain(host) for host in hosts if host and not is_ip(host)),
        # Written one way, so 2001:DB8:0::1 and 2001:db8::1 are one IP
        ips=_unique(str(ipaddress.ip_address(host)) for host in hosts if is_ip(host)),
        # Mail providers ignore case, so Billing@PayPa1.com and billing@paypa1.com are one address
        emails=_unique(email.lower() for email in emails),
        hashes=_unique(hashes),
    )


def _unique(items) -> list[str]:
    return list(dict.fromkeys(items))
