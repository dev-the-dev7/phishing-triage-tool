"""Pull IOCs out of an email or pasted alert text, plus the refang/defang helpers."""

import ipaddress
import re
from urllib.parse import unquote, urlsplit, urlunsplit

from .domains import TEXT_URL, ascii_domain, browser_url, domains_in_text, is_ip, url_host, urls_in_text
from .models import Indicators, Origin, ParsedEmail

EMAIL = re.compile(r"(?<![\w.+%-])[\w.+%-]+@[\w-]+(?:\.[\w-]+)+")
IPV4 = re.compile(r"(?<![0-9.])[0-9]{1,3}(?:\.[0-9]{1,3}){3}(?!\.?[0-9])")
HASH = re.compile(r"(?<![0-9a-z])(?:[0-9a-f]{64}|[0-9a-f]{40}|[0-9a-f]{32})(?![0-9a-z])", re.I)

# The ways people write an indicator so it can't be clicked: evil[.]com, evil (dot) com,
# x[@]evil.com, https[:]//, and hxxp or h**p for http. Spaces in front are only taken from the
# start of a run, since trying every space in a long run would take minutes.
BRACKETED = re.compile(r"(?<![ \t])[ \t]*[\[({]\s*(\.|dot|@|at|:|://|/)\s*[\])}][ \t]*", re.I)
BROKEN_SCHEME = re.compile(r"(?<![a-z])h[x*]{2}p(?=s?:)", re.I)


def refang(text: str) -> str:
    # Turns defanged indicators back into real ones, so they can be found. evil\.com, the way
    # a regex writes it, is read as evil.com too.
    text = BRACKETED.sub(lambda m: {"dot": ".", "at": "@"}.get(m.group(1).lower(), m.group(1)), text)
    return BROKEN_SCHEME.sub("http", text).replace("\\.", ".")


def defang(indicator: str) -> str:
    # hxxp, [.] and [@] stop a chat app, ticket system or mail client turning the indicator into
    # a live link that someone could click. refang() turns it back.
    indicator = re.sub(r"^http(?=s?:)", "hxxp", indicator, flags=re.I)
    return indicator.replace(".", "[.]").replace("@", "[@]")


def from_email(parsed: ParsedEmail, origin: Origin | None) -> Indicators:
    # What the email links to, loads, and came from: its links (including URLs written in the
    # plain text part) and other URLs, the sender addresses, the origin server and the
    # attachment hashes. A domain only mentioned in the text isn't listed, since phishing names
    # the real brand's domain to look genuine, and blocking that would be a mistake. Neither is
    # a URL written as an HTML link's text, since that's only what the link shows, not where
    # it goes.
    urls, hosts, emails = [], [], []
    for href in [link.href for link in parsed.links] + parsed.other_urls:
        host = url_host(href)
        if host:
            urls.append(_requested_url(href, host))
            hosts.append(host)
        elif re.match("mailto:", href, re.I):
            emails += EMAIL.findall(unquote(href))
    for address in [parsed.from_addr, *parsed.reply_to, parsed.return_path]:
        if address:
            emails.append(address.email)
            hosts.append(address.domain)
    if origin and origin.ip:
        hosts.append(origin.ip)
    return _indicators(urls, hosts, emails, [attachment.sha256 for attachment in parsed.attachments])


def from_text(text: str) -> Indicators:
    # Alert text pasted by an analyst or exported from a tool. Defanged indicators are turned
    # back first, and bare domains, IPs and hashes count, since alerts list them that way.
    # URLs and addresses are taken out before the rest is searched, so a file name in a URL's
    # path (/files/report.zip) isn't read as a domain.
    text = refang(text)
    urls, hosts = [], []
    for url in urls_in_text(text):
        # A www. link with no scheme opens as http
        href = "http://" + url if url.lower().startswith("www.") else url
        host = url_host(href)
        urls.append(_requested_url(href, host) if host else href)
        hosts.append(host)
    text = TEXT_URL.sub(" ", text)
    emails = EMAIL.findall(text)
    hosts += [email.rpartition("@")[2] for email in emails]
    text = EMAIL.sub(" ", text)
    # Paths aren't read for domains either, only what's in front of them: evil.com/files/run.sh
    # gives evil.com, and C:\Tools\setup.py gives nothing. .sh and .py are real TLDs, so the
    # file names would be listed as domains.
    hosts += domains_in_text(re.sub(r"(?<=[\w:-])[/\\]\S*", " ", text)) + _ips_in(text)
    return _indicators(urls, hosts, emails, [found.lower() for found in HASH.findall(text)])


def _requested_url(href: str, host: str) -> str:
    # The URL the browser asks for: the link read the way a browser reads it, with the host
    # written the way DNS writes it, as in the domain list. http://%70aypa1.com/ is
    # http://paypa1.com/, http://3627734532/ is http://216.58.214.4/, and a Cyrillic pаypal.com
    # is xn--pypal-4ve.com, so it doesn't look like the real one.
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
    candidates = IPV4.findall(text)
    for token in re.findall(r"[0-9a-f:.]+", text, re.I):
        if token.count(":") >= 2:
            # A label in front, like ip:2001:db8::1, leaves one colon at the start
            token = token.rstrip(".")
            token = token[1:] if re.match(":[^:]", token) else token
            # Two groups of digits at least, since PowerShell's [Convert]::FromBase64String
            # and std::string leave ::F and d::, which are valid IPv6 addresses
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
