"""Checks on what the body shows: text hidden inside words, an email that's only an image, and
text added by CSS the tool doesn't read.

These only report what they find. An email without hidden text isn't safer for it, so a pass
would read like reassurance the check can't give."""

import re

from .models import Check, ParsedEmail, Result, Strength, join_first_five


def check_hidden_text(parsed: ParsedEmail) -> list[Check]:
    if not parsed.hidden_in_words:
        return []
    return [Check("Hidden text", Result.FLAG, Strength.MEDIUM,
                  "Text is hidden inside words, so filters read something other than what the reader sees: "
                  + join_first_five(parsed.hidden_in_words))]


def check_css_added_text(parsed: ParsedEmail) -> list[Check]:
    # The reader sees text a <style> block adds to the page (.x::before { content: "." }), but
    # the tool doesn't read CSS, so it can't check that text. Weak, since templates add small
    # decorations this way too. The text is shown so the analyst can judge it.
    if not parsed.css_added_text:
        return []
    shown = [f'"{text}"' if len(text) <= 40 else f'"{text[:40]}..."' for text in parsed.css_added_text]
    return [Check("Text added by CSS", Result.FLAG, Strength.WEAK,
                  f"CSS adds {join_first_five(shown)} to what the email shows, and the tool doesn't read CSS. "
                  "Check what the email looks like in a mail client.")]


def check_image_only(parsed: ParsedEmail) -> list[Check]:
    # Text in a picture can't be read by filters or by this tool, which is why phishing sends
    # QR codes and screenshots of text. It's only flagged when the email shows no text at all,
    # since a logo or a photo next to some text is normal.
    shown = parsed.html_text if parsed.html_body else parsed.text_body
    images = parsed.html_images + sum(1 for a in parsed.attachments if a.content_type.startswith("image/"))
    if not images or re.search(r"[^\W_]", shown):
        return []
    # No count in the evidence: an image in the HTML is often also an attachment (cid:), and
    # counting both would double it
    return [Check("Image only", Result.FLAG, Strength.MEDIUM,
                  "The email shows images and no text. Any text or QR code in them can't be checked, "
                  "so look at them by hand, and don't scan a QR code to see where it goes.")]
