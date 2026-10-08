"""Parse a .eml file into a ParsedEmail."""

import email
import email.policy
import hashlib
from email.utils import getaddresses
from html.parser import HTMLParser

from .models import Address, Attachment, Link, ParsedEmail


def parse_file(path) -> ParsedEmail:
    # Binary mode so the email library handles charsets instead of us guessing
    with open(path, "rb") as f:
        return parse_bytes(f.read())


def parse_bytes(raw: bytes) -> ParsedEmail:
    msg = email.message_from_bytes(raw, policy=email.policy.default)

    # The parser accepts any file without complaint, so check it actually looks like an email
    if not any(name in msg for name in ("From", "To", "Subject", "Date", "Received")):
        raise ValueError("no email headers found, is this an .eml file?")

    warnings = []
    # With several From headers, mail clients and DMARC checks don't always pick the same one
    from_count = sum(1 for key in msg.keys() if key.lower() == "from")
    if from_count > 1:
        warnings.append(f"{from_count} From headers found, using the first")

    from_list = _addresses(msg, "From", warnings)
    return_path = _addresses(msg, "Return-Path", warnings)
    html_body = _body_text(msg, "html", warnings)

    return ParsedEmail(
        from_addr=from_list[0] if from_list else None,
        reply_to=_addresses(msg, "Reply-To", warnings),
        return_path=return_path[0] if return_path else None,
        to=_addresses(msg, "To", warnings),
        subject=_header(msg, "Subject", warnings),
        date=_header(msg, "Date", warnings),
        message_id=_header(msg, "Message-ID", warnings),
        received=_all_headers(msg, "Received", warnings),
        auth_results=_all_headers(msg, "Authentication-Results", warnings),
        text_body=_body_text(msg, "plain", warnings),
        html_body=html_body,
        links=_extract_links(html_body, warnings),
        attachments=_attachments(msg),
        parse_warnings=warnings,
    )


# Spam headers are often broken. Record unreadable ones as warnings instead of crashing.

def _unreadable(warnings, name, error) -> None:
    warnings.append(f"{name} header couldn't be parsed ({type(error).__name__})")


def _header(msg, name, warnings) -> str:
    try:
        value = msg[name]
    except Exception as e:
        _unreadable(warnings, name, e)
        return ""
    return "" if value is None else _collapse(str(value))


def _all_headers(msg, name, warnings) -> list[str]:
    try:
        values = msg.get_all(name) or []
    except Exception as e:
        _unreadable(warnings, name, e)
        return []
    return [_collapse(str(v)) for v in values]


def _addresses(msg, name, warnings) -> list[Address]:
    try:
        header = msg[name]
        if header is None:
            return []
        # From/To/Reply-To come back as address headers. Return-Path doesn't, so parse it by hand
        if hasattr(header, "addresses"):
            pairs = [(a.display_name, a.addr_spec) for a in header.addresses]
        else:
            pairs = getaddresses([str(header)])
    except Exception as e:
        _unreadable(warnings, name, e)
        return []

    result = []
    for display_name, addr in pairs:
        if not addr:
            continue
        domain = addr.rpartition("@")[2].lower() if "@" in addr else ""
        result.append(Address(display_name, addr, domain))
    return result


def _collapse(value: str) -> str:
    # Long headers are folded across lines. Join them back into one
    return " ".join(value.split())


def _body_text(msg, subtype, warnings) -> str:
    part = msg.get_body(preferencelist=(subtype,))
    if part is None:
        return ""
    try:
        return part.get_content()
    except LookupError:
        warnings.append(f"{subtype} body has an unknown charset, decoded as UTF-8")
        return (part.get_payload(decode=True) or b"").decode("utf-8", errors="replace")


class _LinkCollector(HTMLParser):
    """Collects (href, visible text) for every <a> tag. Only reads the HTML as text."""

    def __init__(self):
        super().__init__()
        self.links = []
        self._href = None
        self._text = []

    def handle_starttag(self, tag, attrs):
        if tag != "a":
            return
        # If the previous <a> was never closed, end it before starting this one
        self._finish()
        href = dict(attrs).get("href")
        if href:
            self._href = href.strip()
            self._text = []

    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag):
        if tag == "a":
            self._finish()

    def close(self):
        super().close()
        self._finish()  # catches an <a> that was never closed

    def _finish(self):
        if self._href is not None:
            self.links.append(Link(self._href, _collapse("".join(self._text))))
        self._href = None


def _extract_links(html: str, warnings) -> list[Link]:
    if not html:
        return []
    collector = _LinkCollector()
    try:
        collector.feed(html)
        collector.close()
    except Exception as e:
        # catch any exceptions from HTMLParser due to malformed <![...]> markup. Record what was found before that.
        collector._finish()
        warnings.append(f"HTML body couldn't be fully parsed ({type(e).__name__}), links after that point may be missing")
    return collector.links


def _attachments(msg) -> list[Attachment]:
    found = []
    # walk() instead of iter_attachments() so files nested inside other
    # multipart sections (like a forwarded email) are found too.
    for part in msg.walk():
        if part.is_multipart() or not (part.is_attachment() or part.get_filename()):
            continue
        # Hashed in memory only. The bytes are never written to disk.
        data = part.get_payload(decode=True) or b""
        found.append(Attachment(
            filename=part.get_filename() or "",
            content_type=part.get_content_type(),
            size=len(data),
            sha256=hashlib.sha256(data).hexdigest(),
        ))
    return found
