"""Parse a .eml file into a ParsedEmail."""

import email
import email.policy
import hashlib
import re
from dataclasses import replace
from email.utils import getaddresses
from html.parser import HTMLParser
from itertools import groupby
from urllib.parse import urljoin

from .domains import (C0_OR_SPACE, TAB_OR_NEWLINE, browser_url, domains_in_text, normalize_unicode, url_host,
                      urls_in_text)
from .models import Address, Attachment, Link, ParsedEmail

# Microsoft 365's largest allowed message. A bigger file isn't a real email, and the
# email library needs several times the file's size in memory.
MAX_EMAIL_BYTES = 150 * 1024 * 1024

# Real headers are well under this, even with a long non-English file name. Python's email
# library gets very slow on longer ones (a 160 KB Content-Type took 90 seconds): its parser
# is quadratic in places, and it parses a header again every time it's read.
MAX_HEADER_LENGTH = 4 * 1024

# Real emails have one <base> tag at most. Every link is read against each base (see
# _read_html), so without a limit, thousands of both would take minutes.
MAX_BASES = 10

# Python's parser hands over what's inside these as text, but a browser doesn't show it:
# scripts, CSS, the page title, and what's shown instead of a frame or plugin
UNSHOWN_ELEMENTS = {"script", "style", "title", "iframe", "noembed", "noframes"}

# Attributes that make a mail client load a URL (an image, a frame) or send a form to it.
# Links and <base> are read on their own.
URL_ATTRIBUTES = {"src", "action", "formaction", "background", "poster"}

# Elements with no content and no end tag
VOID_ELEMENTS = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param",
                 "source", "track", "wbr"}

# Elements that start on a new line or in a new cell, so text on either side of one isn't the same word
BLOCK_ELEMENTS = {"address", "article", "aside", "blockquote", "br", "caption", "center", "dd", "details",
                  "dialog", "div", "dl", "dt", "fieldset", "figcaption", "figure", "footer", "form", "h1",
                  "h2", "h3", "h4", "h5", "h6", "header", "hr", "li", "main", "menu", "nav", "ol", "p",
                  "pre", "section", "summary", "table", "td", "th", "tr", "ul"}

# Browsers end some elements without an end tag, and the tool has to as well, or it would
# think a hidden element was still open. A new <p>, <div> or other block ends an open <p>
# (unless a table cell or button is open inside it). The others are below.
ENDS_P = {"address", "article", "aside", "blockquote", "center", "details", "dialog", "dd", "div", "dl", "dt",
          "fieldset", "figcaption", "figure", "footer", "form", "h1", "h2", "h3", "h4", "h5", "h6", "header",
          "hr", "li", "main", "menu", "nav", "ol", "p", "pre", "section", "summary", "table", "ul"}
P_LIMITS = {"button", "td", "th", "table", "template"}
HEADINGS = {"h1", "h2", "h3", "h4", "h5", "h6"}
# Each start tag, the elements it ends, and the ones it doesn't look past: a new <li> ends the
# last <li>, but not one outside the list it's in
IMPLIED_ENDS = {
    "li": ({"li"}, {"ol", "ul", "table", "template"}),
    "dt": ({"dt", "dd"}, {"dl", "table", "template"}),
    "dd": ({"dt", "dd"}, {"dl", "table", "template"}),
    "tr": ({"tr"}, {"table", "template"}),
    "td": ({"td", "th"}, {"tr", "table", "template"}),
    "th": ({"td", "th"}, {"tr", "table", "template"}),
    "option": ({"option"}, {"select", "template"}),
    "a": ({"a"}, {"td", "th", "table", "template"}),
}

# The markers around the parts only Outlook for Windows shows, <!--[if mso]> ... <![endif]-->,
# and around the parts every other client shows, <!--[if !mso]><!--> ... <!--<![endif]-->.
# Those second ones have to go whole: a <!-- left behind would start a comment that hides the
# rest of the email.
OUTLOOK_MARKERS = re.compile(r"<!--\[if[^\]]{0,100}\]>(?:<!--\s{0,10}-->|<!-->)?"
                             r"|(?:<!--\s{0,10})?<!\[endif\]-->", re.I)

# Marks where a tag sits in a link's text (see _split_by_tags). The text itself can't hold it,
# since it's taken out of the text first.
TAG_MARK = "\x00"
LONE_SEPARATOR = re.compile(r"(?<=\x00)[^\w\x00]+(?=\x00)")
# Tags that aren't marked: <a> ends the link, the UNSHOWN_ELEMENTS aren't part of the page,
# and <wbr> only marks where a long word can wrap. CSS can't make a <wbr> show anything (Edge
# won't draw one as a block or give it ::before text), and long URLs in a link's text often
# have one after each dot or slash.
UNMARKED = UNSHOWN_ELEMENTS | {"a", "wbr"}

# Text or a tag put straight into a table, outside any cell, is moved in front of the table by
# browsers, so a hidden table doesn't hide it. These are the parts of a table where that
# happens, and the tags that do belong there.
TABLE_PARTS = {"table", "thead", "tbody", "tfoot", "tr"}
TABLE_CONTENT = TABLE_PARTS | {"caption", "colgroup", "col", "td", "th", "form", "input", "script", "style",
                               "template"}


class _HeaderLengthPolicy(email.policy.EmailPolicy):
    # The default policy, but the library won't parse a header over MAX_HEADER_LENGTH.
    # Cutting a Content-Type short could change how the email splits into parts and hide one,
    # so the email is refused. A long Date only gets a warning (_header catches it).
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
    text_body = "\n".join(_shown_texts(msg, "plain", warnings))
    html_parts = _shown_texts(msg, "html", warnings)
    collected = [_read_html(html, warnings) for html in html_parts]

    return ParsedEmail(
        from_addr=from_list[0] if from_list else None,
        reply_to=_addresses(msg, "Reply-To", warnings, every_header=True),
        return_path=return_path[0] if return_path else None,
        to=_addresses(msg, "To", warnings),
        subject=_text_header(msg, "Subject", warnings),
        date=_header(msg, "Date", warnings),
        # Read as written, since a search of the mail logs needs it exactly. The library would
        # decode =?utf-8?q?<x=40evil.com>?= into <x@evil.com>.
        message_id=next(iter(_raw_headers(msg, "Message-ID")), ""),
        received=_raw_headers(msg, "Received"),
        auth_results=_raw_headers(msg, "Authentication-Results"),
        dkim_signatures=_raw_headers(msg, "DKIM-Signature"),
        text_body=text_body,
        html_body="\n".join(html_parts),
        html_text="\n".join(part.text for part in collected if part.text),
        hidden_in_words=[found for part in collected for found in part.hidden_in_words],
        css_added_text=list(dict.fromkeys(text for part in collected for text in part.css_added_text)),
        html_images=sum(part.images for part in collected),
        links=[link for part in collected for link in part.links] + _text_links(text_body),
        other_urls=[url for part in collected for url in part.other_urls],
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


class _HTMLCollector(HTMLParser):
    """Collects the links, the other URLs, and the text with what a browser would hide.
    Only reads the HTML as text."""

    def __init__(self):
        super().__init__()
        self.links = []
        self.other_urls = []
        self.bases = []  # every <base href>, which sets where relative links go
        self.pieces = []  # (text, hidden) in order, with a "\n" piece where a block starts or ends
        self.images = 0  # <img> tags a browser would show
        self.css = []  # the text of every <style> block
        self._unshown = None  # the one of the UNSHOWN_ELEMENTS this is inside
        # Each open element as (tag, gone, invisible, zero font size, outside), each one worked
        # out from its parent's and its own, so the last one says whether text here is hidden.
        # For a table part, outside is what text put straight into it gets instead (see TABLE_PARTS).
        self._open = []
        self._positions = {}  # where each tag is open in _open, so finding one doesn't need a search
        self._href = None
        self._text = []
        self._full_text = []
        self._marked = []  # the link's text with TAG_MARK where each tag inside it is

    def handle_starttag(self, tag, attrs):
        if self._href is not None and tag not in UNMARKED:
            self._marked.append(TAG_MARK)
        self._close_implied(tag)
        gone, invisible, zero_font = _hiding(tag, attrs, self._context(moved=tag not in TABLE_CONTENT))
        if tag in BLOCK_ELEMENTS:
            self._break(tag, gone)
        if tag in UNSHOWN_ELEMENTS:
            self._unshown = tag
        elif tag not in VOID_ELEMENTS:
            self._positions.setdefault(tag, []).append(len(self._open))
            self._open.append((tag, gone, invisible, zero_font, self._context(moved=True)))
        # Font size doesn't shrink an image, so a row of images in a font-size:0 cell still shows
        if tag == "img" and not (gone or invisible) and any(name == "src" and value for name, value in attrs):
            self.images += 1
        # Browsers use the first href when a tag has two. dict(attrs) would keep the last. An
        # href with no value (<a href>) is an empty link to a browser. Python's parser gives None.
        href = next((value or "" for name, value in attrs if name == "href"), None)
        if href is None and tag != "base":
            # SVG links and images can give their address in xlink:href instead
            href = next((value or "" for name, value in attrs if name == "xlink:href"), None)
        # Trimmed the way browsers trim a link. Python's strip() would also drop a no-break
        # space, which browsers keep: to them "\xa0https://x.com/" is a relative link, not x.com.
        if href is not None:
            href = href.strip(C0_OR_SPACE)
        self.other_urls += [value.strip(C0_OR_SPACE) for name, value in attrs
                            if name in URL_ATTRIBUTES and value and value.strip(C0_OR_SPACE)]
        if tag == "a":
            # If the previous <a> was never closed, end it before starting this one
            self._finish()
            # An empty href is still a link, to the page or its <base>
            if href is not None:
                self._href = href
                self._text = []
                self._full_text = []
                self._marked = []
        elif (tag == "area" or tag.startswith("v:")) and href is not None:
            # A clickable part of an image, or a shape Outlook draws as a button
            # (<v:roundrect href>). Neither has text of its own.
            self.links.append(Link(href, ""))
        elif tag == "base" and href:
            self.bases.append(href)
        elif tag not in ("area", "base") and href:
            self.other_urls.append(href)  # a stylesheet's <link href>, or an SVG image

    def handle_data(self, data):
        # Text inside <style> or the others in UNSHOWN_ELEMENTS isn't part of the page at all,
        # so <a>paypal<style> </style>.com</a> reads as paypal.com
        if self._unshown == "style":
            self.css.append(data)
        if self._unshown:
            return
        # Spaces stay in a table, and other text is moved in front of it (see TABLE_PARTS)
        hidden = any(self._context(moved=bool(data.strip())))
        self.pieces.append((re.sub(r"\s+", " ", data), hidden))
        if self._href is not None:
            self._full_text.append(data)
            self._marked.append(data.replace(TAG_MARK, ""))
            if not hidden:
                self._text.append(data)

    def handle_startendtag(self, tag, attrs):
        # Browsers ignore the / in <span hidden/> and leave the element open, so the text after
        # it is hidden. Inside <svg> or <math>, <g/> is closed.
        self.handle_starttag(tag, attrs)
        if self._last_open({"svg", "math"}) >= 0:
            self.handle_endtag(tag)

    def handle_endtag(self, tag):
        # Only its own end tag ends a <title> or <style>, the way a browser reads it
        if tag == self._unshown:
            self._unshown = None
        if tag == "a":
            self._finish()
        elif self._href is not None and tag not in UNMARKED:
            self._marked.append(TAG_MARK)
        # An end tag closes its element and any left open inside it. One with nothing to close is skipped.
        gone = bool(self._open) and self._open[-1][1]
        if self._positions.get(tag):
            index = self._positions[tag][-1]
            gone = self._open[index][1]
            self._close_from(index)
        if tag in BLOCK_ELEMENTS:
            self._break(tag, gone)

    def close(self):
        super().close()
        self._finish()  # catches an <a> that was never closed

    def _break(self, tag, gone):
        # A block starts or ends here, or a <br>: a new line in the text, and a space in a
        # link's text, so example.com<br>Sign in isn't read as example.comSign. A block that's
        # invisible or has font size 0 still takes up its lines. One that's gone doesn't, so
        # it only gets the space in the link's text read with the hidden parts.
        if not gone:
            self.pieces.append(("\n", False))
        if self._href is not None:
            self._full_text.append(" ")
            if not gone:
                self._text.append(" ")
            if tag == "br":
                # Read like a tag holding a space: CSS can hide a <br> (display:none) and join
                # paypal<br>.com into paypal.com, as hiding a space would
                self._marked.append(" " + TAG_MARK)

    def _finish(self):
        if self._href is not None:
            self.links.append(Link(self._href, _collapse_whitespace("".join(self._text)),
                                   _collapse_whitespace("".join(self._full_text)),
                                   _split_by_tags("".join(self._marked))))
        self._href = None

    def _context(self, moved: bool) -> tuple[bool, bool, bool]:
        # What new text or a new element inherits: (gone, invisible, zero font size). Moved
        # means it isn't table content, so in a table part it goes in front of the table.
        if not self._open:
            return False, False, False
        tag, gone, invisible, zero_font, outside = self._open[-1]
        return outside if moved and tag in TABLE_PARTS else (gone, invisible, zero_font)

    def _close_implied(self, tag):
        if tag in ENDS_P:
            self._close_last({"p"}, P_LIMITS)
        if tag in IMPLIED_ENDS:
            self._close_last(*IMPLIED_ENDS[tag])
        # A heading can't hold another, so <h1>x<h2> ends the <h1>
        if tag in HEADINGS and self._open and self._open[-1][0] in HEADINGS:
            self._close_from(len(self._open) - 1)

    def _close_last(self, tags, limits):
        # Closes the last open element in tags, unless one in limits was opened inside it
        index = self._last_open(tags)
        if index > self._last_open(limits):
            self._close_from(index)

    def _last_open(self, tags) -> int:
        return max((self._positions[tag][-1] for tag in tags if self._positions.get(tag)), default=-1)

    def _close_from(self, index):
        for tag, *_ in self._open[index:]:
            self._positions[tag].pop()
        del self._open[index:]


def _hiding(tag, attrs, parent) -> tuple[bool, bool, bool]:
    # (gone, invisible, zero font size) for an element. Gone means a browser draws nothing of
    # it: display:none, the hidden attribute, opacity 0, or a <template>, and nothing inside
    # can undo that. Visibility and font size pass down too, but a child can set them back,
    # as email templates do with font-size:0 on a row to close the gaps between its images.
    style = _style(attrs)
    gone, invisible, zero_font = parent
    # The hidden attribute works through display, so display:inline shows the element again
    display = style.get("display", "none" if any(name == "hidden" for name, _ in attrs) else "")
    if tag == "template" or display == "none" or _is_zero(style.get("opacity", "")):
        gone = True
    invisible = {"hidden": True, "collapse": True, "visible": False}.get(style.get("visibility"), invisible)
    size = style.get("font-size")
    if size is not None and _is_zero(size):
        zero_font = True
    elif size is not None and not re.fullmatch(r"[\d.]+(?:em|%)|inherit|unset|smaller|larger", size):
        # em, % and the words scale the parent's size, so a zero stays zero
        zero_font = False
    return gone, invisible, zero_font


def _style(attrs) -> dict[str, str]:
    # The style attribute as {property: value}, lowercased, without comments. As in CSS, the
    # last value for a property wins, unless an earlier one is marked !important.
    style = next((value or "" for name, value in attrs if name == "style"), "")
    style = re.sub(r"/\*.*?(?:\*/|\Z)", "", style, flags=re.S).lower()
    declarations, important = {}, set()
    for declaration in style.split(";"):
        name, _, value = declaration.partition(":")
        name, is_important, value = name.strip(), "!" in value, value.split("!")[0].strip()
        if value and (is_important or name not in important):
            declarations[name] = value
            if is_important:
                important.add(name)
    return declarations


def _is_zero(value: str) -> bool:
    # 0, 0px, 0.0em or 0%
    return "0" in value and re.fullmatch(r"[0.]+(?:[a-z]+|%)?", value) is not None


def _read_html(html: str, warnings) -> _HTMLCollector:
    # One HTML part's links, other URLs and text, with relative links read against its <base>
    collector = _collect(html, warnings)
    # Outlook for Windows shows what's inside <!--[if mso]> ... <![endif]-->, and every other
    # client reads it as a comment, so a link can be there for Outlook users only. A link can
    # start in one of these parts and end in another, with its text between them, so the HTML
    # is read again with the markers taken out, the way Outlook reads it, and the links only
    # that reading finds are added. Its text isn't, since other clients don't show it.
    if re.search(r"<!--\[if", html, re.I):
        outlook_html = OUTLOOK_MARKERS.sub("", html)
        outlook_warnings = []
        outlook = _collect(outlook_html, outlook_warnings)
        warnings += [warning for warning in outlook_warnings if warning not in warnings]
        seen = {(link.href, link.text, link.full_text) for link in collector.links}
        collector.links += [link for link in outlook.links if (link.href, link.text, link.full_text) not in seen]
        known = set(collector.other_urls)
        collector.other_urls += [url for url in outlook.other_urls if url not in known]
    return collector


def _collect(html: str, warnings) -> _HTMLCollector:
    collector = _HTMLCollector()
    try:
        collector.feed(html)
        collector.close()
    except Exception as e:
        # Python's HTMLParser no longer raises on broken markup like <![...]>, as older versions
        # did, but a bug in _HTMLCollector still could. Keep what was found before that point.
        collector._finish()
        warnings.append(f"HTML body couldn't be fully parsed ({type(e).__name__}), links after that point may be missing")

    # <base href="https://evil.com/"> makes <a href="/login"> go to evil.com. This is the
    # baseStriker trick. Browsers use the first <base>, but skip one inside <template> or <svg>,
    # and Python's parser can't tell where a tag sits. So links are read against every base,
    # and a decoy in front can't hide the real one. A base is read like a link, so one a
    # browser accepts (https:\\evil.com\) works here too.
    bases = list(dict.fromkeys(browser_url(base) for base in collector.bases))
    if len(bases) > MAX_BASES:
        warnings.append(f"The HTML has {len(bases)} different <base> tags, which set where links go. "
                        f"Links were read against the first {MAX_BASES}. Check the rest by hand.")
    elif len(bases) > 1:
        warnings.append(f"The HTML has {len(bases)} different <base> tags. Browsers use one, "
                        "so links were read against each.")
    collector.links = [replace(link, href=href) for link in collector.links
                       for href in _read_against_bases(link.href, bases)]
    collector.other_urls = [href for url in collector.other_urls for href in _read_against_bases(url, bases)]
    shown = "".join(text for text, hidden in collector.pieces if not hidden)
    collector.text = "\n".join(_collapse_whitespace(line) for line in shown.split("\n") if line.strip())
    collector.hidden_in_words = _hidden_in_words(collector.pieces)
    collector.css_added_text = _css_added_text("".join(collector.css))
    return collector


def _split_by_tags(marked: str) -> list[str]:
    # Domains in a link's text with a tag in the middle of them: pay<b>pal</b>.com, or
    # paypal<span class="x"> </span>.com. A tag is where CSS could hide part of the text or
    # add to it, so what the reader sees there can't be known. The text is also read without
    # the tags that hold only spaces or punctuation, since hiding one of those is how a domain
    # gets split. A domain inside one tag's text isn't counted.
    if TAG_MARK not in marked:
        return []
    whole = set(domains_in_text(marked.replace(TAG_MARK, " ")))
    joined = marked.replace(TAG_MARK, "")
    without_separators = LONE_SEPARATOR.sub("", marked).replace(TAG_MARK, "")
    found = domains_in_text(joined) + domains_in_text(without_separators)
    return [domain for domain in dict.fromkeys(found) if domain not in whole]


def _css_added_text(css: str) -> list[str]:
    # Text a <style> block adds to the page, like .x::before { content: "." }, which the reader
    # sees and the tool doesn't. Escapes are decoded (\2e is a dot). Only text with a letter,
    # digit, dot or @ counts, and text taken from an attribute (attr(title)), since icon fonts
    # (content: "\f101", a symbol) and layout tricks (content: "") add nothing that reads. An
    # image (content: url("...")) isn't text either: email trackers load one that way.
    css = re.sub(r"/\*.*?(?:\*/|\Z)", "", css, flags=re.S)
    found = []
    for value in re.findall(r"content\s*:([^;}]*)", css, re.I):
        value = re.sub(r"url\([^)]*\)", "", value, flags=re.I)
        quoted = "".join(re.findall(r"[\"']([^\"']*)[\"']", value))
        text = re.sub(r"\\([0-9a-f]{1,6})\s?", _css_unescape, quoted, flags=re.I)
        if "attr(" in value.lower() or re.search(r"[^\W_]|[.@]", text):
            found.append(text or value.strip())
    return found


def _css_unescape(match) -> str:
    # \2e is the character with that hex number, a dot. Past the last character there is, it's
    # the replacement character, as in CSS.
    number = int(match.group(1), 16)
    return chr(number) if number <= 0x10FFFF else "\ufffd"


def _hidden_in_words(pieces) -> list[str]:
    # Hidden text with a shown letter or digit right before and after it. The reader of
    # Mic<span style="font-size:0">xyz</span>rosoft sees Microsoft, and a filter reads
    # Micxyzrosoft (the ZeroFont trick). Hidden spaces and invisible characters (&zwnj;) alone
    # are left out, since templates hide the gaps between images that way, and a filter that
    # drops invisible characters reads the word right.
    runs = [(hidden, "".join(text for text, _ in group)) for hidden, group in groupby(pieces, key=lambda p: p[1])]
    found = []
    for i in range(1, len(runs) - 1):
        hidden, text = runs[i]
        before, after = runs[i - 1][1], runs[i + 1][1]
        if hidden and normalize_unicode(text).strip() and before[-1:].isalnum() and after[:1].isalnum():
            start, end = before.split()[-1], after.split()[0]
            found.append(f"{start}[{_collapse_whitespace(text)}]{end} shows as {start}{end}")
    return found


def _text_links(text: str) -> list[Link]:
    # URLs written out in a plain text part. Mail clients make them clickable, and open a www.
    # link with no scheme as http.
    return [Link("http://" + url if url.lower().startswith("www.") else url, url) for url in urls_in_text(text)]


def _read_against_bases(href: str, bases: list[str]) -> list[str]:
    # Where the link goes with each <base>, without repeats
    if not bases or not _uses_base(href):
        return [href]
    readings = []
    for base in bases[:MAX_BASES]:
        try:
            readings.append(urljoin(base, href))
        except ValueError:
            readings.append(href)  # a broken <base> leaves the link as written
    return list(dict.fromkeys(readings))


def _uses_base(href: str) -> bool:
    # A link with no host of its own is read against the base. Links with a host keep it,
    # except one with a scheme but not two slashes: on an https base, browsers read
    # https:paypal.com as a page on the base's site. urljoin does the same, and leaves the
    # link as written when its scheme isn't the base's: http:paypal.com still goes to paypal.com.
    if not url_host(href):
        return True
    return re.match(r"[a-z][a-z\d+.-]*:(?![/\\]{2})", href.translate(TAB_OR_NEWLINE), re.I) is not None


def _attached_emails(msg) -> list[str]:
    # message/rfc822 is an attached email, and message/global is the same with UTF-8 headers.
    # Outlook's .msg is its own format, found by name. Only this email's own parts are
    # searched: an email inside an attached one gets checked when that one is run on its own.
    names = []
    for part in _own_parts(msg):
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
