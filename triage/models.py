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
    links: list[Link] = field(default_factory=list)
    attachments: list[Attachment] = field(default_factory=list)
    parse_warnings: list[str] = field(default_factory=list)
