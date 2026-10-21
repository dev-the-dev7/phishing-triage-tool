"""Known combinations of findings that mean more together than apart, each named with why it
matters. They never change a check's result, and finding none says nothing about the email."""

from dataclasses import dataclass

from ..domains import decode_idn, url_host
from ..models import Check, ParsedEmail, Result


@dataclass
class Pattern:
    name: str
    found: list[str]  # the checks it's made from
    why: str


def find_patterns(parsed: ParsedEmail, checks: list[Check]) -> list[Pattern]:
    # Each is made from findings about different facts. One lookalike domain tripping three
    # checks is one fact, so it isn't a pattern.
    flagged = {check.name: check for check in checks if check.result == Result.FLAG}
    # Both only pass for the From's own domain, so the email really came from it
    authenticated = [name for name in ("DMARC", "DKIM")
                     if any(check.name == name and check.result == Result.PASS for check in checks)]
    if "DMARC" in flagged:
        # DMARC couldn't authenticate the From, so a DKIM pass read here can be text the sender added
        authenticated = []
    lookalikes = set(flagged["Lookalike domain"].domains) if "Lookalike domain" in flagged else set()
    from_lookalike = any(decode_idn(a.domain) in lookalikes for a in parsed.from_addrs if a.domain)
    patterns = []

    if authenticated and from_lookalike:
        patterns.append(Pattern("Lookalike that passes authentication", [*authenticated, "Lookalike domain"],
                                "The attacker owns the lookalike domain, so passing only shows the email came "
                                "from it."))

    # Only a lookalike link counts, since ordinary mail trips the other link checks: click
    # tracking the text check, and a template's javascript:void(0) the link type check
    link_hosts = {decode_idn(host) for host in (url_host(link.href) for link in parsed.links) if host}
    # Free webmail is left out, since anyone can make an account to send from
    if authenticated and link_hosts & lookalikes and not from_lookalike and "Free webmail sender" not in flagged:
        patterns.append(Pattern("Authenticated sender with a lookalike link", [*authenticated, "Lookalike domain"],
                                "The email really came from its From domain, so the account may be hacked or "
                                "a real service misused. If so, tell the sender's organization instead of "
                                "blocking its domain."))
    return patterns
