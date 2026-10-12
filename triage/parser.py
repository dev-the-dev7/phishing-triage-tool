"""Parse a .eml file into a ParsedEmail."""

import email
import email.policy
import hashlib
from email.utils import getaddresses
from html.parser import HTMLParser
from urllib.parse import urljoin

from .domains import url_host
from .models import Address, Attachment, Link, ParsedEmail

# Microsoft 365's largest allowed message. A bigger file isn't a real email, and the
# email library needs several times the file's size in memory.
MAX_EMAIL_BYTES = 150 * 1024 * 1024

# Real headers are well under this, even with a long non-English file name. Python's email
# library gets very slow on longer ones (a 160 KB Content-Type took 90 seconds): its parser
# is quadratic in places, and it parses a header again every time it's read.
MAX_HEADER_LENGTH = 4 * 1024


class _HeaderLengthPolicy(email.policy.EmailPolicy):
    # The default policy, but the library won't parse a header over MAX_HEADER_LENGTH.
    # Cutting a Content-Type short could change how the email splits into parts and hide one,
    # so the email is refused. A long Date or Message-ID only gets a warning (_header catches it).
    def header_fetch_parse(self, name, value):
        if len(value) > MAX_HEADER_LENGTH:
            raise ValueError(f"the {name} header is {len(value):,} characters long, too long to be "
                             "a real header. Check this email by hand.")
        return super().header_fetch_parse(name, value)


def parse_file(path) -> ParsedEmail:
    # Binary mode so the email library handles charsets instead of us guessing.
    # One byte past the limit is enough to know it's too big, without reading all of it.
    with open(path, "rb") as f:
        raw = f.read(MAX_EMAIL_BYTES + 1)
    if len(raw) > MAX_EMAIL_BYTES:
        raise ValueError(f"file is over {MAX_EMAIL_BYTES // (1024 * 1024)} MB, too big to be an email")
    return parse_bytes(raw)


def parse_bytes(raw: bytes) -> ParsedEmail:
    try:
        return _parse_message(raw)
    except RecursionError:
        # Parts nested thousands deep, or (comments) nested hundreds deep in a header like
        # Content-Type, run Python's email library out of stack
        raise ValueError("the email has parts or header comments nested too deeply to read") from None


def _parse_message(raw: bytes) -> ParsedEmail:
    msg = email.message_from_bytes(raw, policy=_HeaderLengthPolicy())

    # The parser accepts any file without complaint
    if not any(name in msg for name in ("From", "To", "Subject", "Date", "Received")):
        raise ValueError("no email headers found, is this an .eml file?")

    warnings = []
    # With several From headers or addresses, mail clients and DMARC checks don't always
    # pick the same one
    from_count = _count_headers(msg, "From")
    if from_count > 1:
        warnings.append(f"{from_count} From headers found, using the first")
    from_list = _addresses(msg, "From", warnings)
    if len(from_list) > 1:
        warnings.append(f"From has {len(from_list)} addresses, using the first")
    # Email allows one Reply-To header (RFC 5322). With more, it isn't defined which one a
    # mail client replies to. The addresses in all of them are checked.
    reply_to_count = _count_headers(msg, "Reply-To")
    if reply_to_count > 1:
        warnings.append(f"{reply_to_count} Reply-To headers found, checking the addresses in all of them")
    # Reported phish often arrive forwarded as an attachment. The checks only read this
    # email's own headers and body, so they'd be checking the employee's forward.
    for name in _attached_emails(msg):
        warnings.append(f"{name} is an email attached to this one. If this is a forwarded report, "
                        "the checks ran on the wrapper. Save the attachment and run the tool on it.")

    return_path = _addresses(msg, "Return-Path", warnings)
    html_parts = _shown_texts(msg, "html", warnings)

    return ParsedEmail(
        from_addr=from_list[0] if from_list else None,
        reply_to=_addresses(msg, "Reply-To", warnings, every_header=True),
        return_path=return_path[0] if return_path else None,
        to=_addresses(msg, "To", warnings),
        subject=_text_header(msg, "Subject", warnings),
        date=_header(msg, "Date", warnings),
        message_id=_header(msg, "Message-ID", warnings),
        received=_raw_headers(msg, "Received"),
        auth_results=_raw_headers(msg, "Authentication-Results"),
        dkim_signatures=_raw_headers(msg, "DKIM-Signature"),
        text_body="\n".join(_shown_texts(msg, "plain", warnings)),
        html_body="\n".join(html_parts),
        links=[link for html in html_parts for link in _extract_links(html, warnings)],
        attachments=_attachments(msg),
        parse_warnings=warnings,
    )


# Spam headers are often broken. Record unreadable ones as warnings instead of crashing.

def _warn_unreadable(warnings, name, error) -> None:
    warnings.append(f"{name} header couldn't be parsed ({type(error).__name__})")


def _header(msg, name, warnings) -> str:
    try:
        value = msg[name]
    except Exception as e:
        _warn_unreadable(warnings, name, e)
        return ""
    return "" if value is None else _collapse_whitespace(str(value))


def _text_header(msg, name, warnings) -> str:
    # A plain text header like the Subject. It's decoded here, not by the library, because the
    # library would refuse a very long one and _decode_words decodes its start instead.
    raw = _raw_headers(msg, name)[:1]
    return _collapse_whitespace(_decode_words(raw[0], name, warnings)) if raw else ""


def _raw_headers(msg, name) -> list[str]:
    # The header read as written. The email library decodes =?utf-8?q?...?= encoded
    # words anywhere in a header, but they're only allowed in plain text like the Subject and
    # display names. Anywhere else, decoding turns text the sender chose into something new:
    # the valid envelope address =?utf-8?q?x=3Bdkim=3Dpass?=@evil.com, copied into
    # Authentication-Results by the provider, would be decoded into x;dkim=pass@evil.com.
    values = []
    for key, value in msg.raw_items():
        if key.lower() == name.lower():
            # The library keeps bytes that aren't ASCII as placeholder characters (surrogates).
            # They're decoded as UTF-8 here, like the rest of the email.
            text = str(value).encode("utf-8", "surrogateescape").decode("utf-8", errors="replace")
            values.append(_collapse_whitespace(text))
    return values


def _addresses(msg, name, warnings, every_header=False) -> list[Address]:
    # Read from the header as written, since the email library decodes encoded words even
    # inside an address: service@=?utf-8?q?paypal=2Ecom?= would come out as service@paypal.com.
    raw = _raw_headers(msg, name) if every_header else _raw_headers(msg, name)[:1]
    try:
        # getaddresses' strict mode drops what it can't read instead of guessing, sometimes just
        # one address out of several (x@[1.2.3.4]). The lenient parser runs only to notice that.
        pairs = getaddresses(raw)
        lenient = getaddresses(raw, strict=False)
    except Exception as e:
        _warn_unreadable(warnings, name, e)
        return []

    result = []
    for display_name, addr in pairs:
        if not addr:
            continue
        # Encoded text isn't allowed in an address, but mail clients hit by the Mailsploit bugs
        # decoded it anyway and showed an address that isn't the real one
        shown = _decode_words(addr, name, warnings)
        if shown != addr:
            warnings.append(f"{name} address {addr} has encoded text in it, which isn't allowed in an "
                            f"address. Some mail clients decode it and show {shown}")
        domain = addr.rpartition("@")[2].lower() if "@" in addr else ""
        result.append(Address(_decode_words(display_name, name, warnings), addr, domain))
    dropped = {addr for _, addr in lenient if addr} - {addr for _, addr in pairs}
    if (any("@" in value for value in raw) and not result) or dropped:
        warnings.append(f"{name} has an address the tool couldn't read safely. Check the header by hand.")
    return result


def _count_headers(msg, name) -> int:
    return sum(1 for key in msg.keys() if key.lower() == name.lower())


def _decode_words(text: str, name: str, warnings) -> str:
    # Decodes =?utf-8?q?...?= encoded words, the way the email library does in a plain text header.
    # Only the start is decoded, since the decoder is slow on long text. That's the part a mail
    # client shows, and padding a display name can't push a brand name out of it.
    start, rest = text[:MAX_HEADER_LENGTH], text[MAX_HEADER_LENGTH:]
    if rest:
        warning = f"{name} has text over {MAX_HEADER_LENGTH:,} characters long, only the start was decoded"
        if warning not in warnings:
            warnings.append(warning)
    return str(email.policy.default.header_factory("Decoded", start)) + rest


def _collapse_whitespace(value: str) -> str:
    return " ".join(value.split())


def _shown_texts(msg, subtype, warnings) -> list[str]:
    # Every text/plain or text/html part a mail client could show. In multipart/alternative,
    # clients show the last version they can, and some show every inline part. A phishing
    # link can be in the second HTML part, not the first.
    texts = []
    for part in _own_parts(msg):
        if part.get_content_type() != f"text/{subtype}" or part.is_attachment():
            continue
        try:
            texts.append(part.get_content())
        except LookupError:
            warnings.append(f"{subtype} body has an unknown charset, decoded as UTF-8")
            texts.append((part.get_payload(decode=True) or b"").decode("utf-8", errors="replace"))
    return texts


def _own_parts(msg) -> list:
    # Every part of this email in order, without going inside attached emails, which are
    # a separate message. A stack, not recursion, because deep nesting would overflow it.
    parts, stack = [], [msg]
    while stack:
        part = stack.pop()
        parts.append(part)
        if part.is_multipart() and part.get_content_maintype() != "message":
            stack.extend(reversed(list(part.iter_parts())))
    return parts


class _LinkCollector(HTMLParser):
    """Collects (href, visible text) for every <a> tag. Only reads the HTML as text."""

    def __init__(self):
        super().__init__()
        self.links = []
        self.base = None  # the first <base href>, which sets where relative links go
        self._href = None
        self._text = []

    def handle_starttag(self, tag, attrs):
        # Browsers use the first href when a tag has two. dict(attrs) would keep the last.
        href = next((value for name, value in attrs if name == "href"), None)
        if tag == "base" and href and self.base is None:
            self.base = href.strip()
        if tag != "a":
            return
        # If the previous <a> was never closed, end it before starting this one
        self._finish()
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
            self.links.append(Link(self._href, _collapse_whitespace("".join(self._text))))
        self._href = None


def _extract_links(html: str, warnings) -> list[Link]:
    if not html:
        return []
    collector = _LinkCollector()
    try:
        collector.feed(html)
        collector.close()
    except Exception as e:
        # HTMLParser can raise on broken markup like <![...]>. Keep the links found before that point.
        collector._finish()
        warnings.append(f"HTML body couldn't be fully parsed ({type(e).__name__}), links after that point may be missing")

    links = []
    for link in collector.links:
        if collector.base and not url_host(link.href):
            # <base href="https://evil.com/"> makes <a href="/login"> go to evil.com. This is
            # the baseStriker trick. Links with a host of their own keep it.
            try:
                link = Link(urljoin(collector.base, link.href), link.text)
            except ValueError:
                pass  # a broken <base> leaves the link as written
        links.append(link)
    return links


def _attached_emails(msg) -> list[str]:
    # message/rfc822 is an attached email, and message/global is the same with UTF-8 headers.
    # Outlook's .msg is its own format, found by name.
    names = []
    for part in msg.walk():
        filename = part.get_filename() or ""
        is_email_type = part.get_content_type() in ("message/rfc822", "message/global")
        if is_email_type or filename.lower().endswith((".eml", ".msg")):
            names.append(f'"{filename}"' if filename else "An unnamed part")
    return names


def _attachments(msg) -> list[Attachment]:
    found = []
    # walk() instead of iter_attachments(), to find files nested inside other multipart
    # sections (like a forwarded email).
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
