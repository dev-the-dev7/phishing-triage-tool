"""The follow-ups the note suggests if the email is confirmed malicious, picked from what was
found. They're suggestions for the analyst, never steps the tool took."""

from dataclasses import dataclass, field

from .patterns import Pattern
from ..checks.headers import is_free_webmail
from ..domains import ascii_domain
from ..models import Address, Check, Indicators, ParsedEmail, Result

# Flags for domains the attacker likely registered. Blocking a spoofed or shared one would cut off real senders.
BLOCK_CHECKS = ("Lookalike domain", "Newly registered domain")


@dataclass
class FollowUp:
    text: str
    values: dict[str, list[str]] = field(default_factory=dict)  # values from the email shown under it, by label


def suggest_follow_ups(parsed: ParsedEmail, checks: list[Check], patterns: list[Pattern],
                       found: Indicators) -> list[FollowUp]:
    flagged = {check.name: check for check in checks if check.result == Result.FLAG}
    message_id = {"Message-ID": [parsed.message_id]} if parsed.message_id else {}
    follow_ups = [FollowUp("Find other recipients of the same message (search by its Message-ID or sender)",
                           message_id | _addresses("From", parsed.from_addrs) | _addresses("Sender", parsed.sender))]

    if "Reply-To" in parsed.unread_address_headers and not parsed.reply_to:
        follow_ups.append(FollowUp("Check whether anyone replied. The tool couldn't read the Reply-To, so find where "
                                   "replies go by hand"))
    else:
        # Replies go to the Reply-To when there is one
        replies_to = _addresses("Reply-To", parsed.reply_to) or _addresses("From", parsed.from_addrs)
        follow_ups.append(FollowUp("Check whether anyone replied (search sent mail for the address replies go to)",
                                   replies_to))
    if found.urls:
        follow_ups.append(FollowUp("Check whether anyone clicked a link (proxy or DNS logs for the indicator domains). "
                                   "If anyone entered a password, reset it and end their sessions"))
    if parsed.attachments:
        follow_ups.append(FollowUp("Search EDR for the attachments' SHA-256, to find computers that saved or opened "
                                   "them"))

    # As the indicators write them: in the xn-- form blocklists use, which can't pass for the
    # brand's own domain, and without a dot at the end, which is the same domain in DNS
    domains = list(dict.fromkeys(ascii_domain(domain.rstrip(".")) for name in BLOCK_CHECKS if name in flagged
                                 for domain in flagged[name].domains))
    block = [FollowUp("Block the lookalike or newly registered domains", {"Domains": domains})] if domains else []
    if "Free webmail sender" in flagged:
        # Only the webmail ones, since another From can be someone's real address the attacker put there
        webmail = [a.email for a in parsed.from_addrs if is_free_webmail(a.domain)]
        block.append(FollowUp("Block the sender's webmail address, not the whole webmail domain", {"From": webmail}))
    follow_ups += block or [FollowUp("Block the attacker's own sender address and domains, not spoofed or shared "
                                     "ones like a webmail or link-shortening service")]
    if "Display name mismatch" in flagged:
        follow_ups.append(FollowUp("Tell whoever the display name pretends to be, like an executive or a brand's "
                                   "phishing team"))
    if any(pattern.name == "Authenticated sender with a lookalike link" for pattern in patterns):
        follow_ups.append(FollowUp("Tell the sender's organization its account or service may be misused, instead "
                                   "of blocking its domain"))
    return follow_ups


def _addresses(label: str, addresses: list[Address]) -> dict[str, list[str]]:
    return {label: [a.email for a in addresses]} if addresses else {}
