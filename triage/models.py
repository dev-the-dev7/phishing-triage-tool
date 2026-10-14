"""Dataclasses passed between the pipeline stages, and how a check's evidence is written."""

from dataclasses import dataclass, field
from enum import StrEnum


@dataclass
class Address:
    display_name: str
    email: str
    domain: str  # lowercased, "" if there's no @


@dataclass
class Link:
    href: str  # where the link actually goes
    text: str  # what the reader sees
    full_text: str = ""  # every bit of text in the link, with the parts a browser hides
    # Domains in the text with a tag in the middle (pay<b>pal</b>.com), where CSS the tool
    # doesn't read could change what shows
    split_domains: list[str] = field(default_factory=list)


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
    STRONG = "strong"
    MEDIUM = "medium"
    WEAK = "weak"


@dataclass
class Check:
    name: str
    result: Result
    strength: Strength
    evidence: str
    # What the result doesn't cover: something close to this check that it couldn't check, for
    # the analyst to look at whatever the result says, or a pointer to a related check. Evidence
    # is why the check got its result, and a caveat never is. When the check can't tell, the
    # result is inconclusive, not a pass with a caveat.
    caveats: list[str] = field(default_factory=list)

    def __post_init__(self):
        # Turns "flag" into Result.FLAG, and raises ValueError on a typo like "fail"
        self.result = Result(self.result)
        self.strength = Strength(self.strength)


def join_first_five(items: list[str]) -> str:
    # Evidence lists stop at five, so one email with dozens of links can't bury the note
    extra = f" (and {len(items) - 5} more)" if len(items) > 5 else ""
    return "; ".join(items[:5]) + extra


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


@dataclass
class ParsedEmail:
    from_addr: Address | None = None
    reply_to: list[Address] = field(default_factory=list)
    return_path: Address | None = None
    to: list[Address] = field(default_factory=list)
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
