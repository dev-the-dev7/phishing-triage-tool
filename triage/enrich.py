"""Reputation lookups with VirusTotal and AbuseIPDB. Nothing gets uploaded."""

import base64
import hashlib
import ipaddress
import json
import math
import os
import sys
import time
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from functools import partial
from pathlib import Path
from urllib.parse import quote, unquote

import requests

from .domains import TLDS, ascii_domain, base_domain, decode_idn, hosting_service, is_ip, url_host
from .iocs import EMAIL
from .lists import BRANDS, FREE_EMAIL_DOMAINS, OWN_DOMAINS
from .models import Attachment, Check, Indicators, LookupStatus, Origin, Reputation, Result, Strength, join_first_five
from .received import MICROSOFT_SERVER_DOMAINS

# A file is looked up by its hash and never uploaded, since an upload is shared with every
# VirusTotal customer. Scanning a URL would take a POST, so a URL VirusTotal hasn't seen
# comes back as not found.
VT_API = "https://www.virustotal.com/api/v3"
VT_COLLECTIONS = {"file": "files", "domain": "domains", "ip": "ip_addresses", "url": "urls"}
ABUSEIPDB_CHECK = "https://api.abuseipdb.com/api/v2/check"

# The free VirusTotal key allows 4 lookups a minute and 500 a day. 8 keeps a run to about a
# minute, and leaves room for 60 runs a day.
MAX_VT_LOOKUPS = 8
VT_PER_MINUTE = 4
# A limit's minute is counted as 61 seconds, since the service counts when a lookup arrives,
# not when it was sent
LIMIT_MINUTE = 61
# The free AbuseIPDB key allows 1,000 lookups a day
MAX_ABUSEIPDB_LOOKUPS = 10
# Only reports from the last 90 days count, since an IP abused long ago may have a new owner
ABUSEIPDB_DAYS = 90
# A domain registered this recently is flagged, a common cut-off for newly registered
# domains in mail and web filters
NEW_DOMAIN_DAYS = 30
# The owners AbuseIPDB can list Microsoft's IPs under. It names whoever holds the IP block,
# and an attacker can't get a block listed under one of these.
MICROSOFT_IP_OWNERS = {"microsoft.com"} | MICROSOFT_SERVER_DOMAINS

# Seconds to wait for a server to connect, or to send more, before giving up
TIMEOUT = 20
# A report is a few hundred KB at most. This stops an answer far bigger from filling memory.
MAX_ANSWER_BYTES = 5 * 1024 * 1024

# Found results are kept a day, so another run on the same campaign doesn't use up the free
# limits. Not found and reports no engine has checked aren't kept, since either can change
# within the hour.
CACHE_HOURS = 24
# Raised when what's kept for a result changes, so an older file is read as empty
CACHE_VERSION = 5

# What's kept from each answer, and its type. Cached entries are checked against it too.
FACTS = {
    "VirusTotal": {"malicious": int, "suspicious": int, "undetected": int, "harmless": int, "checked": str,
                   "registered": str},
    "AbuseIPDB": {"confidence": int, "reports": int, "users": int, "trusted": bool, "isp": str, "country": str,
                  "domain": str},
}

# Domains whose reputation is already known, so they're looked up last
KNOWN_DOMAINS = {domain for domains in BRANDS.values() for domain in domains} | FREE_EMAIL_DOMAINS

PICTURE_ENDINGS = (".png", ".jpg", ".jpeg", ".gif", ".bmp")


def _cache_file() -> Path:
    # The user's cache folder, outside the repository
    folder = os.environ.get("LOCALAPPDATA") or os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache"
    return Path(folder) / "phishing-triage" / "lookups.json"


CACHE_FILE = _cache_file()


@dataclass
class _Service:
    name: str
    key_variable: str  # the environment variable the key is read from
    most: int  # lookups sent in one run, at most
    per_minute: int = 0  # 0 when there's no limit a minute
    # Kept out of repr, so the key can't show up in a test failure
    key: str = field(init=False, repr=False)
    sent: list[float] = field(default_factory=list)  # when each lookup was sent (time.monotonic)
    stopped: str = ""  # why nothing more is sent to it this run

    def __post_init__(self):
        # Spaces or a line break pasted with the key are dropped
        self.key = os.environ.get(self.key_variable, "").strip()
        # A zero-width space or curly quote copied with the key would crash the request
        if not (self.key.isascii() and self.key.isprintable()):
            self.stopped = f"the key in {self.key_variable} has a character a key can't have"


class _NoAnswer(Exception):
    # stop means the service's other lookups would fail the same way, so they aren't sent
    def __init__(self, reason: str, stop: bool = False):
        super().__init__(reason)
        self.stop = stop


def look_up(found: Indicators, attachments: list[Attachment] | None = None, flagged: list[str] | None = None,
            origin: Origin | None = None) -> dict[str, list[Reputation]]:
    # Each indicator's results, by its value. Email addresses aren't looked up, but their
    # domains are. The attachments are only used to tell pictures from other files, and
    # flagged are the domains the lookalike and brand-joined checks flagged. The origin's
    # hops taken as Microsoft's get AbuseIPDB lookups too, for their owners.
    virustotal = _Service("VirusTotal", "VT_API_KEY", MAX_VT_LOOKUPS, VT_PER_MINUTE)
    abuseipdb = _Service("AbuseIPDB", "ABUSEIPDB_API_KEY", MAX_ABUSEIPDB_LOOKUPS)
    # AbuseIPDB first: it has no limit a minute, so its lookups are done before any wait for
    # VirusTotal that Ctrl+C might cut short
    order = _virustotal_order(found, attachments or [], flagged or [])
    lookups = ([(abuseipdb, "ip", ip) for ip in _abuseipdb_order(found, origin)]
               + [(virustotal, kind, value) for kind, value in order])
    cache = _read_cache()
    before = dict(cache)
    results = {}
    # Saved even if the run stops partway, since the lookups made count against the day's limit
    try:
        for service, kind, value in lookups:
            try:
                result = _look_up_one(service, kind, value, cache)
            except KeyboardInterrupt:
                # The first Ctrl+C skips the lookups left, so the indicators still print. A
                # second one stops the tool.
                virustotal.stopped = abuseipdb.stopped = "stopped with Ctrl+C"
                result = _look_up_one(service, kind, value, cache)
            results.setdefault(value, []).append(result)
    finally:
        if cache != before:
            _write_cache(cache)
    return results


def check_domain_age(found: Indicators, results: dict[str, list[Reputation]]) -> Check:
    # Most phishing domains are used within days of being registered, and an old one makes a
    # lookalike likelier to be a real business. The brands' domains, webmail, your own, and
    # names that aren't sent aren't in question.
    name, strength = "Newly registered domain", Strength.MEDIUM
    today = datetime.fromtimestamp(time.time(), timezone.utc).date()
    new, old, unknown = [], [], []
    for domain in found.domains:
        if _not_sent_because("domain", domain) or _well_known(("domain", domain)):
            continue
        service = hosting_service(domain)
        registered = _registered(domain, results)
        if service:
            unknown.append(f"{domain} (only {service} has one)")
        elif registered is None or registered > today:
            unknown.append(domain)
        elif registered == today:
            new.append(f"{domain} was registered {registered}, today")
        elif (today - registered).days < NEW_DOMAIN_DAYS:
            new.append(f"{domain} was registered {registered}, {_count((today - registered).days, 'day')} ago")
        else:
            old.append(f"{domain} {registered}")
    if new:
        return Check(name, Result.FLAG, strength, join_first_five(new))
    if unknown:
        return Check(name, Result.INCONCLUSIVE, strength, f"No registration date for {join_first_five(unknown)}")
    if old:
        return Check(name, Result.PASS, strength, f"Every domain was registered at least {NEW_DOMAIN_DAYS} days ago: "
                                                  f"{join_first_five(old)}")
    return Check(name, Result.PASS, strength, "No sender or link domain besides well-known ones and your own")


def check_microsoft_hops(origin: Origin | None, results: dict[str, list[Reputation]]) -> Check:
    # A sender can name itself as a Microsoft server and be skipped as one, but Microsoft's
    # server wrote down its IP, and the IP's owner can't be faked
    name, strength = "Faked Microsoft hop", Strength.STRONG
    hops = origin.microsoft_hops if origin else []
    faked, faked_ips, unknown, unknown_above = [], [], [], []
    for position, server, ip in hops:
        result = next((r for r in results.get(ip, []) if r.service == "AbuseIPDB"), None)
        owner = result.facts.get("domain") if result else None
        if owner in MICROSOFT_IP_OWNERS:
            continue
        if owner:
            if not faked:
                unknown_above = list(unknown)
            faked.append(f"Received header {position} calls itself {server}, but AbuseIPDB lists {ip} under "
                         f"{owner}: {result.text}")
            faked_ips.append(ip)
        elif result is None:
            unknown.append(f"Received header {position} ({ip}): not looked up")
        elif result.status == LookupStatus.FOUND:
            unknown.append(f"Received header {position} ({ip}): AbuseIPDB doesn't list an owner")
        else:
            unknown.append(f"Received header {position} ({ip}): {result.text}")
    if faked:
        # Each header was written by the server the header above it came from, so the first faked
        # one is the real handoff only when every hop above it is Microsoft's
        if unknown_above:
            return Check(name, Result.FLAG, strength, f"{join_first_five(faked)}. The Origin line may be wrong",
                         [f"Who owns these isn't known, so Microsoft may have got the email from one of them "
                          f"instead: {join_first_five(unknown_above)}"], ips=faked_ips)
        return Check(name, Result.FLAG, strength, f"{join_first_five(faked)}. The first is the server Microsoft "
                                                  "really got the email from, so the Origin line may be wrong",
                     ips=faked_ips)
    if unknown:
        return Check(name, Result.INCONCLUSIVE, strength, f"Who owns these isn't known: {join_first_five(unknown)}")
    if hops:
        headers = "header" if len(hops) == 1 else "headers"
        numbers = ", ".join(str(position) for position, _, _ in hops)
        return Check(name, Result.PASS, strength, f"Every hop named as a Microsoft server has a Microsoft IP, in "
                                                  f"Received {headers} {numbers}")
    return Check(name, Result.PASS, strength, "No hop was taken as Microsoft's on its name alone")


def _registered(domain: str, results: dict[str, list[Reputation]]) -> date | None:
    # From the domain's VirusTotal result. A cached one could have been edited, so a date that
    # doesn't read counts as none.
    for result in results.get(domain, []):
        if result.service == "VirusTotal" and result.facts.get("registered"):
            try:
                return date.fromisoformat(result.facts["registered"])
            except ValueError:
                return None
    return None


def _abuseipdb_order(found: Indicators, origin: Origin | None) -> list[str]:
    # Hops go top down, so fake ones added below can't push the sender's real one past the limit
    first = [origin.ip] if origin and origin.ip else []
    hops = [ip for _, _, ip in origin.microsoft_hops] if origin else []
    return list(dict.fromkeys(first + hops + found.ips))


def _virustotal_order(found: Indicators, attachments: list[Attachment], flagged: list[str]) -> list[tuple[str, str]]:
    # Only MAX_VT_LOOKUPS are sent, so what's most likely to matter goes first: attachments,
    # flagged lookalikes (their age is the best evidence for or against them), sender domains
    # (only one to three), link domains, links (often made for each reader, so rarely known),
    # pictures (mostly signature logos), then IPs, which AbuseIPDB covers too.
    flagged = {ascii_domain(domain.lower().rstrip(".")) for domain in flagged}
    link_domains = {ascii_domain(host.lower()) for host in map(url_host, found.urls) if host} - flagged
    # A hash counts as a picture only when no other kind of file has it
    files = {attachment.sha256 for attachment in attachments if not _is_picture(attachment)}
    pictures = {attachment.sha256 for attachment in attachments} - files
    lookups = ([("file", sha) for sha in found.hashes if sha not in pictures]
               + [("domain", domain) for domain in found.domains if domain in flagged]
               + [("domain", domain) for domain in found.domains if domain not in flagged | link_domains]
               + [("domain", domain) for domain in found.domains if domain in link_domains]
               + [("url", url) for url in found.urls]
               + [("file", sha) for sha in found.hashes if sha in pictures]
               + [("ip", ip) for ip in found.ips])
    # Brand domains, free webmail and links to them last. sorted() is stable, so the rest
    # keep their order.
    return sorted(lookups, key=_well_known)


def _is_picture(attachment: Attachment) -> bool:
    # The type and the name both have to say picture: Windows opens a file by its name, and a
    # mail client can go by its type. SVG doesn't count, since it can hold scripts.
    return (attachment.content_type.startswith("image/") and attachment.content_type != "image/svg+xml"
            and attachment.filename.lower().endswith(PICTURE_ENDINGS))


def _well_known(lookup: tuple[str, str]) -> bool:
    kind, value = lookup
    host = url_host(value) if kind == "url" else value
    return kind in ("domain", "url") and base_domain(host or "") in KNOWN_DOMAINS


def _look_up_one(service: _Service, kind: str, value: str, cache: dict) -> Reputation:
    reason = _not_sent_because(kind, value)
    if reason:
        return Reputation(service.name, LookupStatus.SKIPPED, f"skipped, {reason}")
    cache_key = _cache_key(service.name, kind, value)
    if cache_key in cache and _valid(service.name, cache[cache_key]["facts"]):
        return _found(service.name, cache[cache_key]["facts"])
    if not service.key:
        return Reputation(service.name, LookupStatus.UNAVAILABLE, f"unavailable, {service.key_variable} isn't set",
                          for_the_run=True)
    if service.stopped:
        return Reputation(service.name, LookupStatus.UNAVAILABLE, f"unavailable, {service.stopped}", for_the_run=True)
    if len(service.sent) >= service.most:
        return Reputation(service.name, LookupStatus.SKIPPED,
                          f"skipped, over the limit of {service.most} lookups a run", for_the_run=True)
    try:
        facts = _ask(service, kind, value)
    except _NoAnswer as e:
        if e.stop:
            service.stopped = str(e)
        return Reputation(service.name, LookupStatus.UNAVAILABLE, f"unavailable, {e}", for_the_run=e.stop)
    if facts is None:
        return Reputation(service.name, LookupStatus.NOT_FOUND, "not found (unknown, not clean)")
    if service.name != "VirusTotal" or _engines(facts):
        cache[cache_key] = {"saved": time.time(), "facts": facts}
    return _found(service.name, facts)


def _not_sent_because(kind: str, value: str) -> str:
    # Why an indicator isn't sent, or "" when it can be. Private IPs, internal names and your
    # own domains would only tell the service about your network.
    if kind == "file":
        return ""
    if kind == "url":
        host = url_host(value) or ""
    else:
        host = value
    if is_ip(host):
        if not ipaddress.ip_address(host).is_global:
            return "private or reserved address"
    # .arpa names are DNS's own, like reverse lookups, and never a website
    elif not _ends_in_tld(host) or host.rpartition(".")[2] == "arpa":
        return "not a public domain name"
    elif base_domain(host) in {base_domain(domain) for domain in OWN_DOMAINS}:
        return "one of your own domains"
    # Phishing links often carry the reader's address. It has to end in a real TLD, so
    # logo@2x.png doesn't count.
    if kind == "url" and any(map(_ends_in_tld, EMAIL.findall(_decodings(_without_fragment(value))))):
        return "it has an email address in it"
    return ""


def _ends_in_tld(name: str) -> bool:
    return decode_idn(name.rpartition(".")[2].lower()) in TLDS


def _decodings(url: str) -> str:
    # The URL as written and decoded up to three times, since a link inside a link is encoded
    # again (%2540 for @). Each form is kept, since decoding can also hide an address by
    # adding to its TLD (%2541 is A).
    forms = [url]
    for _ in range(3):
        forms.append(unquote(forms[-1]))
    return " ".join(forms)


def _without_fragment(url: str) -> str:
    # The part after # never leaves the browser, and phishing kits put the reader's address there
    return url.partition("#")[0]


def _ask(service: _Service, kind: str, value: str) -> dict | None:
    # The facts from the service's answer, or None when it has never seen the indicator
    if service.name == "VirusTotal":
        status, answer = _get(service, f"{VT_API}/{_virustotal_path(kind, value)}", {"x-apikey": service.key})
        read = partial(_virustotal_facts, dated=kind == "domain" and not hosting_service(value))
    else:
        status, answer = _get(service, ABUSEIPDB_CHECK, {"Key": service.key, "Accept": "application/json"},
                              {"ipAddress": value, "maxAgeInDays": ABUSEIPDB_DAYS})
        read = _abuseipdb_facts
    if status == 404 and service.name == "VirusTotal":
        return None
    if status in (401, 403):
        raise _NoAnswer(f"the key in {service.key_variable} was refused", stop=True)
    # VirusTotal's minute was already waited out in _get, and AbuseIPDB's limit is daily
    if status == 429:
        raise _NoAnswer("its daily limit was reached", stop=True)
    if status != 200:
        raise _NoAnswer(f"it answered with error {status}")
    # Anything in the answer can be missing or the wrong type
    try:
        facts = read(answer)
    except (AttributeError, KeyError, TypeError, ValueError, OverflowError, OSError):
        facts = None
    if not _valid(service.name, facts):
        raise _NoAnswer("its answer couldn't be read")
    return facts


def _virustotal_path(kind: str, value: str) -> str:
    if kind == "url":
        # A URL's id is its base64 form without the = padding
        return "urls/" + base64.urlsafe_b64encode(_without_fragment(value).encode()).decode().rstrip("=")
    # Encoded, so a / or ? from the email can't change which report is asked for
    return f"{VT_COLLECTIONS[kind]}/{quote(value, safe=':')}"


def _get(service: _Service, url: str, headers: dict, params: dict | None = None) -> tuple[int, object]:
    status, data = _send(service, url, headers, params)
    if status == 429 and service.per_minute:
        # A run only counts its own lookups, so an earlier run may have used up this minute.
        # Tried once more a minute later. Refused again means the day's limit was reached.
        print(f"{service.name}'s limit was reached, maybe by an earlier run in the last minute. "
              f"Waiting {LIMIT_MINUTE} seconds to try once more (Ctrl+C skips the rest of the lookups)",
              file=sys.stderr)
        time.sleep(LIMIT_MINUTE)
        status, data = _send(service, url, headers, params)
    # Neither API redirects, so this is a proxy or sign-in page, and every lookup would get it
    if 300 <= status < 400:
        raise _NoAnswer(f"it answered with a redirect ({status})", stop=True)
    # Both APIs answer in JSON, errors too, so anything else is a proxy or sign-in page, and
    # its status isn't the service's. RecursionError is JSON nested too deep to parse.
    try:
        return status, json.loads(data)
    except (ValueError, RecursionError):
        raise _NoAnswer(f"its answer couldn't be read (status {status})", stop=True) from None


def _send(service: _Service, url: str, headers: dict, params: dict | None) -> tuple[int, bytearray]:
    _wait_for_turn(service)
    service.sent.append(time.monotonic())
    # Redirects aren't followed, since requests would send the key header on to another site.
    # It only drops Authorization.
    try:
        with requests.get(url, headers=headers, params=params, timeout=TIMEOUT, stream=True,
                          allow_redirects=False) as response:
            data = bytearray()
            for chunk in response.iter_content(64 * 1024):
                data += chunk
                if len(data) > MAX_ANSWER_BYTES:
                    raise _NoAnswer("its answer was too big to be a report", stop=True)
            status = response.status_code
    except requests.RequestException as e:
        # Just the error's type, since requests' messages are long
        raise _NoAnswer(f"it couldn't be reached ({type(e).__name__})", stop=True) from None
    return status, data


def _wait_for_turn(service: _Service) -> None:
    # No more than per_minute lookups in any minute
    if service.per_minute and len(service.sent) >= service.per_minute:
        wait = service.sent[-service.per_minute] + LIMIT_MINUTE - time.monotonic()
        if wait > 0:
            print(f"Waiting {_count(math.ceil(wait), 'second')} for {service.name}'s limit of "
                  f"{service.per_minute} lookups a minute (Ctrl+C skips the rest of the lookups)", file=sys.stderr)
            time.sleep(wait)


def _virustotal_facts(answer, dated: bool) -> dict:
    # Only engines that gave a verdict count, not ones that timed out or can't scan the type
    attributes = answer["data"]["attributes"]
    stats = attributes.get("last_analysis_stats") or {}
    facts = {name: stats.get(name, 0) for name in ("malicious", "suspicious", "undetected", "harmless")}
    facts["checked"] = _date(attributes.get("last_analysis_date"))
    # A domain's registration date. A file's report has the same field for when it was built,
    # and a name a service handed out gets the service's date.
    facts["registered"] = _registration_date(attributes) if dated else ""
    return facts


def _registration_date(attributes: dict) -> str:
    # Read from whois records, which are often messy, so a date that doesn't read is left out
    # rather than the whole answer
    try:
        return _date(attributes.get("creation_date"))
    except (TypeError, ValueError, OverflowError, OSError):
        return ""


def _date(seconds) -> str:
    # Seconds since 1970, in UTC, as a date, or "" when there's none
    return "" if seconds is None else datetime.fromtimestamp(seconds, timezone.utc).date().isoformat()


def _abuseipdb_facts(answer) -> dict:
    # The network, country and owner can be missing (null), and only a real true counts as trusted
    data = answer["data"]
    return {"confidence": data["abuseConfidenceScore"], "reports": data["totalReports"],
            "users": data["numDistinctUsers"], "trusted": data.get("isWhitelisted") is True,
            "isp": (data.get("isp") or "").strip(), "country": (data.get("countryCode") or "").strip(),
            "domain": (data.get("domain") or "").strip().lower()}


def _valid(service: str, facts) -> bool:
    # Every fact there, of the right type, and counts from 0 to under a billion, since huge
    # ones can add up to a number too long to print. type(), since isinstance() would let
    # True pass as 1.
    types = FACTS[service]
    return (isinstance(facts, dict) and facts.keys() == types.keys()
            and all(type(facts[name]) is kind and (kind is not int or 0 <= facts[name] < 10 ** 9)
                    for name, kind in types.items()))


def _found(service: str, facts: dict) -> Reputation:
    if service == "VirusTotal":
        text = _describe_virustotal(facts)
    else:
        text = _describe_abuseipdb(facts)
    return Reputation(service, LookupStatus.FOUND, text, facts)


def _engines(facts: dict) -> int:
    # The engines that gave a verdict
    return facts["malicious"] + facts["suspicious"] + facts["undetected"] + facts["harmless"]


def _describe_virustotal(facts: dict) -> str:
    if not _engines(facts):
        text = "in VirusTotal, but no engine has checked it (unknown, not clean)"
    else:
        text = f"{facts['malicious']} of {_engines(facts)} engines flagged it malicious"
        if facts["suspicious"]:
            text += f", {facts['suspicious']} suspicious"
        # A result is only as new as VirusTotal's last check, and a site can turn malicious after it
        if facts["checked"]:
            text += f", last checked {facts['checked']}"
    if facts["registered"]:
        text += f", registered {facts['registered']}"
    return text


def _describe_abuseipdb(facts: dict) -> str:
    if not facts["reports"]:
        text = f"no reports in the last {ABUSEIPDB_DAYS} days"
    else:
        text = (f"reported {_count(facts['reports'], 'time')} by {_count(facts['users'], 'user')} in the last "
                f"{ABUSEIPDB_DAYS} days, abuse confidence {facts['confidence']}%")
    # Its trusted list is why Google's DNS server has hundreds of reports and 0% confidence
    if facts["trusted"]:
        text += " (on its trusted list)"
    where = network(facts)
    return f"{text}, {where}" if where else text


def network(facts: dict) -> str:
    # Context, not a check: where the IP is, by AbuseIPDB's records, not where the sender is
    return (facts["isp"] + (f" in {facts['country']}" if facts["country"] else "")).strip()


def _count(number: int, word: str) -> str:
    return f"{number:,} {word}" if number == 1 else f"{number:,} {word}s"


def _cache_key(service: str, kind: str, value: str) -> str:
    # Hashed, so the file isn't a readable list of what was looked up. A URL is keyed without
    # the part after #, like what's sent, so a campaign's per-reader links share one entry.
    if kind == "url":
        value = _without_fragment(value)
    return hashlib.sha256(f"{service}\n{kind}\n{value}".encode()).hexdigest()


def _read_cache() -> dict:
    # A missing, damaged or older file reads as empty
    try:
        saved = json.loads(CACHE_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError, RecursionError):
        return {}
    if not isinstance(saved, dict) or saved.get("version") != CACHE_VERSION or not isinstance(saved.get("lookups"), dict):
        return {}
    # Saved in the last CACHE_HOURS, and not in the future. Compared, not subtracted, since
    # subtracting a huge number from a time raises OverflowError.
    now = time.time()
    return {key: entry for key, entry in saved["lookups"].items()
            if isinstance(entry, dict) and type(entry.get("saved")) in (int, float)
            and now - CACHE_HOURS * 3600 < entry["saved"] <= now and "facts" in entry}


def _write_cache(cache: dict) -> None:
    # Written next to the old file and swapped in, so a failed write can't leave half a file
    try:
        CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
        written = CACHE_FILE.with_name(CACHE_FILE.name + ".new")
        written.write_text(json.dumps({"version": CACHE_VERSION, "lookups": cache}), encoding="utf-8")
        written.replace(CACHE_FILE)
    except OSError as e:
        print(f"Note: the lookups couldn't be saved for next time ({e})", file=sys.stderr)
