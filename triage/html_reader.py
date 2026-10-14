"""Read an HTML body the way a mail client shows it: the links, the other URLs it loads, the
text the reader sees, and text hidden inside words or added by CSS."""

import re
from dataclasses import dataclass, replace
from html.parser import HTMLParser
from itertools import groupby
from urllib.parse import urljoin

from .domains import C0_OR_SPACE, TAB_OR_NEWLINE, browser_url, domains_in_text, normalize_unicode, url_host
from .models import Link

# Real emails have one <base> tag at most. Every link is read against each base (see
# _collect), so without a limit, thousands of both would take minutes.
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


@dataclass
class ParsedHTML:
    # What read_html finds in one HTML part, for the parser to add to the ParsedEmail
    text: str  # what the reader sees, one line per block
    hidden_in_words: list[str]  # hidden text found inside a shown word
    css_added_text: list[str]  # text <style> blocks add
    images: int  # images a browser would show
    links: list[Link]
    other_urls: list[str]  # what the HTML loads or sends a form to


def read_html(html: str, warnings) -> ParsedHTML:
    # One HTML part's links, other URLs and text, with relative links read against its <base>
    parsed = _collect(html, warnings)
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
        seen = {(link.href, link.text, link.full_text) for link in parsed.links}
        parsed.links += [link for link in outlook.links if (link.href, link.text, link.full_text) not in seen]
        known = set(parsed.other_urls)
        parsed.other_urls += [url for url in outlook.other_urls if url not in known]
    return parsed


def _collect(html: str, warnings) -> ParsedHTML:
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
    shown = "".join(text for text, hidden in collector.pieces if not hidden)
    return ParsedHTML(
        text="\n".join(_collapse_whitespace(line) for line in shown.split("\n") if line.strip()),
        hidden_in_words=_hidden_in_words(collector.pieces),
        css_added_text=_css_added_text("".join(collector.css)),
        images=collector.images,
        links=[replace(link, href=href) for link in collector.links
               for href in _read_against_bases(link.href, bases)],
        other_urls=[href for url in collector.other_urls for href in _read_against_bases(url, bases)],
    )


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
    # (content: "\f101", a symbol) and layout tricks (content: "") add no readable text. An
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


def _collapse_whitespace(value: str) -> str:
    return " ".join(value.split())
