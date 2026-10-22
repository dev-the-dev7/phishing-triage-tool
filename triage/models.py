"""Dataclasses passed between the pipeline stages, and how a check's evidence is written."""

from dataclasses import dataclass, field
from enum import StrEnum


@dataclass
class Address:
    display_name: str
    email: str
    domain: str  # lowercased, "" if there's no @
    # What some mail clients show when the address has encoded text, which isn't allowed in one
    decoded: str = ""


@dataclass
class Link:
    href: str  # where the link actually goes
    text: str  # what the reader sees
    full_text: str = ""  # every bit of text in the link, with the parts a browser hides
    # Domains in the text with a tag in the middle (pay<b>pal</b>.com), where CSS the tool
    # doesn't read could change what the reader sees
    split_domains: list[str] = field(default_factory=list)
    through_google: bool = False  # it went through Google's redirect page to get to href


@dataclass
class Attachment:
    filename: str
    content_type: str  # what the sender declared, not verified
    size: int
    sha256: str


class Result(StrEnum):
    FLAG = "flag"
    PASS = "pass"
    INCONCLUSIVE = "inconclusive"


class Strength(StrEnum):
    VERY_STRONG = "very strong"  # no known legitimate sender does it
    STRONG = "strong"
    MEDIUM = "medium"
    WEAK = "weak"


@dataclass
class Check:
    name: str
    result: Result
    strength: Strength
    evidence: str
    # What the result doesn't cover, for the analyst to look at whatever it says. A caveat is
    # never why the check got its result: when it can't tell, it's inconclusive.
    caveats: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)  # the domains a flag is about, looked up first
    ips: list[str] = field(default_factory=list)  # IPs a flag is about that the email didn't list

    def __post_init__(self):
        # Turns "flag" into Result.FLAG, and raises ValueError on a typo like "fail"
        self.result = Result(self.result)
        self.strength = Strength(self.strength)


def join_first_five(items: list[str], separator: str = "; ") -> str:
    # Evidence lists stop at five, so one email with dozens of links can't bury the note
    extra = f" (and {len(items) - 5} more)" if len(items) > 5 else ""
    return separator.join(items[:5]) + extra


def pluralize(number: int, word: str) -> str:
    return f"{number:,} {word}" if number == 1 else f"{number:,} {word}s"


def describe_encoded_addresses(addresses: list[Address], header: str = "") -> str:
    # One sentence for any number of them, so a thousand can't bury the report
    if len(addresses) == 1:
        named = f"{header} address {addresses[0].email}" if header else addresses[0].email
        return (f"{named} has encoded text in it, which isn't allowed in an address. Some mail clients decode it "
                f"and show {addresses[0].decoded}")
    named = f"{len(addresses)} {header} addresses" if header else f"{len(addresses)} addresses"
    shown = join_first_five([f"{address.decoded} for {address.email}" for address in addresses])
    return (f"{named} have encoded text in them, which isn't allowed in an address. Some mail clients decode "
            f"them and show {shown}")


@dataclass
class Origin:
    # ip and name are None when every hop is inside the provider (like Gmail to Gmail)
    ip: str | None
    # The reverse DNS name the receiver looked up, or "unknown". Microsoft only gives the
    # sender's own name.
    name: str | None
    # The provider server that took the handoff, or that delivered it when there's no outside server
    received_by: str
    earliest_claim: str | None = None  # IP from a lower hop, which could be forged
    # Hops taken as Microsoft's by their names, as (header number, name, IP)
    microsoft_hops: list[tuple[int, str, str]] = field(default_factory=list)


@dataclass
class ParsedEmail:
    from_addrs: list[Address] = field(default_factory=list)  # from every From header, in order
    from_headers: int = 0
    sender: list[Address] = field(default_factory=list)  # Outlook shows it as "Sender on behalf of From"
    reply_to: list[Address] = field(default_factory=list)
    reply_to_headers: int = 0
    return_path: list[Address] = field(default_factory=list)  # from every Return-Path header, in order
    return_path_headers: int = 0
    to: list[Address] = field(default_factory=list)
    unread_address_headers: list[str] = field(default_factory=list)  # with an address the tool couldn't read
    subject: str = ""
    date: str = ""
    message_id: str = ""
    received: list[str] = field(default_factory=list)  # newest hop first
    auth_results: list[str] = field(default_factory=list)  # topmost first
    dkim_signatures: list[str] = field(default_factory=list)  # topmost first
    text_body: str = ""
    html_body: str = ""
    html_text: str = ""  # what the HTML shows, one line per block, without the hidden parts
    hidden_in_words: list[str] = field(default_factory=list)  # hidden text found inside a shown word
    css_added_text: list[str] = field(default_factory=list)  # text <style> blocks add (content: ".")
    html_images: int = 0  # images the HTML shows
    links: list[Link] = field(default_factory=list)  # in the HTML, then URLs written in the plain text
    other_urls: list[str] = field(default_factory=list)  # what the HTML loads or sends a form to
    base_tags: int = 0  # different <base> tags the links were read against, the most in one HTML part
    attachments: list[Attachment] = field(default_factory=list)
    parse_warnings: list[str] = field(default_factory=list)


@dataclass
class Indicators:
    # Each list in the order found, without repeats
    urls: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)  # in the xn-- form DNS uses
    ips: list[str] = field(default_factory=list)
    emails: list[str] = field(default_factory=list)
    hashes: list[str] = field(default_factory=list)  # MD5, SHA-1 or SHA-256, told apart by length


class LookupStatus(StrEnum):
    FOUND = "found"
    NOT_FOUND = "not found"  # the service has never seen it, which isn't the same as clean
    UNAVAILABLE = "unavailable"  # no usable key, an error, the service's limit was reached, or Ctrl+C
    SKIPPED = "skipped"  # not sent: past the run's limit, or something that shouldn't leave your network


@dataclass
class Reputation:
    service: str  # VirusTotal or AbuseIPDB
    status: LookupStatus
    text: str  # what was found, or why nothing was, in plain words
    facts: dict = field(default_factory=dict)  # what a found result is written from
    # True when it's about the run, not the indicator (over the limit, no key, the service
    # stopped), so the report says it once
    for_the_run: bool = False
