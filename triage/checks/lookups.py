"""The checks that need the lookups, so they only run with --enrich."""

import time
from datetime import date, datetime, timezone

from ..domains import hosting_service
from ..enrich import not_sent_because, well_known
from ..models import Check, Indicators, LookupStatus, Origin, Reputation, Result, Strength, join_first_five, pluralize
from ..reading.origin import MICROSOFT_SERVER_DOMAINS

# A domain registered this recently is flagged, a common cut-off for newly registered
# domains in mail and web filters
NEW_DOMAIN_DAYS = 30
# The owners AbuseIPDB can list Microsoft's IPs under. It names whoever holds the IP block,
# and an attacker can't get a block listed under one of these.
MICROSOFT_IP_OWNERS = {"microsoft.com"} | MICROSOFT_SERVER_DOMAINS


def check_domain_age(found: Indicators, results: dict[str, list[Reputation]]) -> Check:
    # Most phishing domains are used within days of being registered, and an old one makes a
    # lookalike likelier to be a real business. The brands' domains, webmail, your own, and
    # names that aren't sent aren't in question.
    name, strength = "Newly registered domain", Strength.MEDIUM
    today = datetime.fromtimestamp(time.time(), timezone.utc).date()
    new, old, unknown = [], [], []
    for domain in found.domains:
        if not_sent_because("domain", domain) or well_known(("domain", domain)):
            continue
        service = hosting_service(domain)
        registered = _registered_on(domain, results)
        if service:
            unknown.append(f"{domain} (only {service} has one)")
        elif registered is None or registered > today:
            unknown.append(domain)
        elif registered == today:
            new.append(f"{domain} was registered {registered}, today")
        elif (today - registered).days < NEW_DOMAIN_DAYS:
            new.append(f"{domain} was registered {registered}, {pluralize((today - registered).days, 'day')} ago")
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
    name, strength = "Faked Microsoft hop", Strength.VERY_STRONG
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
                         ["Who owns these isn't known, so Microsoft may have got the email from one of them "
                          f"instead: {join_first_five(unknown_above)}"], ips=faked_ips)
        return Check(name, Result.FLAG, strength, f"{join_first_five(faked)}. The first is the server Microsoft "
                                                  "really got the email from, so the Origin line may be wrong",
                     ips=faked_ips)
    if unknown:
        return Check(name, Result.INCONCLUSIVE, strength, f"Who owns these isn't known: {join_first_five(unknown)}")
    if hops:
        headers = "header" if len(hops) == 1 else "headers"
        numbers = join_first_five([str(position) for position, _, _ in hops], ", ")
        return Check(name, Result.PASS, strength, "Every hop named as a Microsoft server has a Microsoft IP, in "
                                                  f"Received {headers} {numbers}")
    return Check(name, Result.PASS, strength, "No hop was taken as Microsoft's on its name alone")


def _registered_on(domain: str, results: dict[str, list[Reputation]]) -> date | None:
    # From the domain's VirusTotal result. A cached one could have been edited, so a date that
    # doesn't read counts as none.
    for result in results.get(domain, []):
        if result.service == "VirusTotal" and result.facts.get("registered"):
            try:
                return date.fromisoformat(result.facts["registered"])
            except ValueError:
                return None
    return None
