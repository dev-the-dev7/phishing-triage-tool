"""Dataclasses passed between the pipeline stages."""

from dataclasses import dataclass, field


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
    text_body: str = ""
    html_body: str = ""
    links: list[Link] = field(default_factory=list)
    attachments: list[Attachment] = field(default_factory=list)
    parse_warnings: list[str] = field(default_factory=list)
