"""Tests for triage/parser.py: refusing what isn't safe to parse, reading addresses and
encoded text, and the warnings an analyst needs to see."""

import hashlib

import pytest

from triage import parser
from triage.impersonation import check_display_name
from triage.models import ParsedEmail, Result
from triage.parser import parse_bytes, parse_file

UNREADABLE = "has an address the tool couldn't read safely"
ATTACHED_EMAIL = "is an email attached to this one"


def parse(*header_lines: str, body: str = "Hello") -> ParsedEmail:
    raw = "\r\n".join(["To: someone@example.net", *header_lines, "", body])
    return parse_bytes(raw.encode())


def multipart(*parts: str) -> tuple[str, str]:
    # The Content-Type header and body of a multipart/mixed email holding these parts, each
    # written as its own headers, a blank line, and its content
    body = "".join(f"--B\r\n{part}\r\n" for part in parts) + "--B--"
    return 'Content-Type: multipart/mixed; boundary="B"', body


TEXT_PART = "Content-Type: text/plain\r\n\r\nSee attached"
PDF_PART = ('Content-Type: application/pdf\r\nContent-Disposition: attachment; filename="invoice.pdf"\r\n'
            "Content-Transfer-Encoding: base64\r\n\r\naGVsbG8=")


def test_not_an_email_is_refused():
    with pytest.raises(ValueError, match="no email headers found"):
        parse_bytes(b"just some text\r\nwith no headers")


@pytest.mark.parametrize("header", ["From: a@example.org", "To: b@example.org", "Subject: s",
                                    "Date: Tue, 06 Oct 2026 10:00:00 +0000", "Received: from x by y"])
def test_one_common_header_is_enough(header):
    assert parse_bytes(f"{header}\r\n\r\nHello".encode()).text_body == "Hello"


def test_file_size_limit(tmp_path, monkeypatch):
    email_start = b"Subject: s\r\n\r\n"
    monkeypatch.setattr(parser, "MAX_EMAIL_BYTES", 100)
    at_limit, over_limit = tmp_path / "at.eml", tmp_path / "over.eml"
    at_limit.write_bytes(email_start.ljust(100, b"x"))
    over_limit.write_bytes(email_start.ljust(101, b"x"))
    assert parse_file(at_limit).subject == "s"
    with pytest.raises(ValueError, match="too big to be an email"):
        parse_file(over_limit)


# Python's email library is very slow on some long headers it parses itself (a 160 KB
# Content-Type took 90 seconds), so over MAX_HEADER_LENGTH they're refused

@pytest.mark.parametrize("name", ["Content-Type", "Content-Disposition", "Content-Transfer-Encoding"])
def test_long_library_parsed_header_refuses_the_email(name):
    # Refused, not cut short: a cut Content-Type could change how the email splits into parts
    if name == "Content-Type":
        header_lines, body = ["Content-Type: text/plain; name=" + "a" * 160_000], "Hello"
    elif name == "Content-Disposition":
        content_type, body = multipart(TEXT_PART, "Content-Type: application/pdf\r\n"
                                       "Content-Disposition: attachment; " + ";" * 16_000 + "\r\n\r\nx")
        header_lines = [content_type]
    else:
        header_lines, body = ["Content-Transfer-Encoding: " + "a" * 5_000], "Hello"
    with pytest.raises(ValueError, match=rf"the {name} header is [\d,]+ characters long"):
        parse("From: a@example.org", *header_lines, body=body)


def test_header_length_limit():
    at_limit = "text/plain; name=".ljust(parser.MAX_HEADER_LENGTH, "a")
    assert parse("From: a@example.org", f"Content-Type: {at_limit}").text_body == "Hello"
    with pytest.raises(ValueError, match="the Content-Type header is 4,097 characters long"):
        parse("From: a@example.org", f"Content-Type: {at_limit}a")


def test_long_date_only_warns():
    parsed = parse("From: a@example.org", "Date: <" + "a" * 5_000 + "@example.org>")
    assert parsed.parse_warnings == ["Date header couldn't be parsed (ValueError)"]
    assert parsed.date == ""
    assert parsed.from_addr.email == "a@example.org"


@pytest.mark.parametrize("message_id", [
    # Searching the mail logs needs it exactly, so encoded text isn't decoded
    "=?utf-8?q?<x=40evil.com>?=",
    # The library doesn't parse it, so its length and nested comments don't matter
    "<" + "a" * 5_000 + "@example.org>",
    "(a" * 1_000,
])
def test_message_id_is_read_as_written(message_id):
    parsed = parse("From: a@example.org", f"Message-ID: {message_id}")
    assert parsed.message_id == message_id
    assert parsed.parse_warnings == []


def test_long_file_name_in_a_real_email_parses():
    # 120 Japanese characters, percent-encoded as RFC 2231 allows, come to about 1,100
    name = "\N{HIRAGANA LETTER A}" * 120
    encoded = "".join(f"%{byte:02X}" for byte in name.encode())
    content_type, body = multipart(TEXT_PART, "Content-Type: application/pdf\r\n"
                                   f"Content-Disposition: attachment; filename*=utf-8''{encoded}\r\n\r\nx")
    assert parse("From: a@example.org", content_type, body=body).attachments[0].filename == name


def test_long_encoded_subject_decodes_only_the_start():
    encoded = "=?utf-8?q?PayPal?= " + "=?utf-8?q?a?=" * 20_000
    parsed = parse("From: a@example.org", f"Subject: {encoded}")
    assert parsed.subject.startswith("PayPal")
    # The rest is kept as written
    assert parsed.subject.endswith("=?utf-8?q?a?=")
    assert "Subject has text over 4,096 characters long, only the start was decoded" in parsed.parse_warnings


def test_padding_a_display_name_doesnt_hide_the_brand():
    # _ is a space in Q encoding. Without it, the encoded words would join into PayPalaaa...
    encoded = "=?utf-8?q?PayPal_?=" + "=?utf-8?q?a?=" * 20_000
    parsed = parse(f'From: "{encoded}" <service@evil.com>')
    assert check_display_name(parsed).result == Result.FLAG


def test_long_text_warning_is_given_once_per_header():
    padding = "a " * 3_000
    parsed = parse("From: a@example.org", f'Reply-To: "{padding}" <a@example.org>, "{padding}" <b@example.org>')
    long_text = [w for w in parsed.parse_warnings if "only the start was decoded" in w]
    assert long_text == ["Reply-To has text over 4,096 characters long, only the start was decoded"]


def nested(depth: int, content_type: str) -> str:
    inner = "Content-Type: text/plain\r\n\r\nHello"
    for i in range(depth):
        if content_type == "multipart/mixed":
            inner = f'Content-Type: multipart/mixed; boundary="b{i}"\r\n\r\n--b{i}\r\n{inner}\r\n--b{i}--'
        else:
            inner = f"Content-Type: {content_type}\r\n\r\n{inner}"
    return inner


@pytest.mark.parametrize("content_type", ["multipart/mixed", "message/rfc822"])
def test_deeply_nested_parts_are_refused(content_type):
    # Python's email library runs out of stack. A clean error, not a crash with a traceback.
    raw = "To: someone@example.net\r\nSubject: s\r\n" + nested(3_000, content_type)
    with pytest.raises(ValueError, match="nested too deeply"):
        parse_bytes(raw.encode())


def test_deeply_nested_comments_in_content_type_are_refused():
    with pytest.raises(ValueError, match="nested too deeply"):
        parse("From: a@example.org", "Content-Type: text/html; " + "(a" * 1_000)


@pytest.mark.parametrize("subject, expected", [
    ("=?utf-8?q?Your_invoice?=", "Your invoice"),
    ("=?utf-8?b?WW91ciBpbnZvaWNl?=", "Your invoice"),
    # Folded onto two lines, and the space between encoded words dropped
    ("=?utf-8?q?Your_?=\r\n =?utf-8?q?invoice?=", "Your invoice"),
    ("=?x-unknown?q?Your_invoice?=", "Your invoice"),
    ("Re: =?utf-8?q?caf=C3=A9?= menu", "Re: caf\N{LATIN SMALL LETTER E WITH ACUTE} menu"),
    # Sent as raw UTF-8 instead of encoded
    ("caf\N{LATIN SMALL LETTER E WITH ACUTE}", "caf\N{LATIN SMALL LETTER E WITH ACUTE}"),
    # Line breaks hidden in encoded text are collapsed like other whitespace
    ("=?utf-8?q?Your=0D=0A=0D=0Ainvoice?=", "Your invoice"),
])
def test_subject_decoding(subject, expected):
    assert parse("From: a@example.org", f"Subject: {subject}").subject == expected


# Encoded text isn't allowed in an address, but some mail clients decode it anyway (the
# Mailsploit bugs) and show an address that isn't the real one. It's read as written,
# with a warning showing what those clients display.

@pytest.mark.parametrize("from_value, domain, shown", [
    ("service@=?utf-8?q?paypal=2Ecom?=", "=?utf-8?q?paypal=2ecom?=", "service@paypal.com"),
    ("PayPal <service@=?utf-8?b?cGF5cGFsLmNvbQ==?=>", "=?utf-8?b?cgf5cgfslmnvbq==?=", "service@paypal.com"),
    ("=?utf-8?q?service=40paypal=2Ecom?=@evil.com", "evil.com", "service@paypal.com@evil.com"),
])
def test_encoded_text_in_an_address_is_read_as_written(from_value, domain, shown):
    parsed = parse(f"From: {from_value}")
    assert parsed.from_addr.domain == domain
    assert any(f"Some mail clients decode it and show {shown}" in w for w in parsed.parse_warnings)


def test_address_with_encoded_word_characters_has_no_warning():
    parsed = parse("From: a=?b@example.com")
    assert parsed.from_addr.email == "a=?b@example.com"
    assert parsed.parse_warnings == []


@pytest.mark.parametrize("from_value, display_name", [
    ("=?utf-8?b?UGF5UGFs?= <service@evil.com>", "PayPal"),
    ("=?x-unknown?q?PayPal?= <service@evil.com>", "PayPal"),
    ("\N{LATIN CAPITAL LETTER U WITH DIAERESIS}ber Team <service@evil.com>",
     "\N{LATIN CAPITAL LETTER U WITH DIAERESIS}ber Team"),
    # Many mail clients show a comment as the name
    ("service@evil.com (PayPal Billing)", "PayPal Billing"),
])
def test_display_name_decoding(from_value, display_name):
    assert parse(f"From: {from_value}").from_addr.display_name == display_name


@pytest.mark.parametrize("from_value", [
    # Python's strict address parser drops these instead of guessing, sometimes just one
    # address out of several
    "x@[1.2.3.4]",
    "x@[1.2.3.4], a@paypal.com",
    "a@example.org, x@[1.2.3.4]",
    "PayPal <service@paypa1.com> (Support",
    "alice@example.org)<bob@example.org>",
    # Neither parser finds an address here, but the @ shows one was meant
    "PayPal <service@>",
])
def test_dropped_address_warns(from_value):
    parsed = parse(f"From: {from_value}")
    assert f"From {UNREADABLE}. Check the header by hand." in parsed.parse_warnings


@pytest.mark.parametrize("from_value", [
    "<>",
    "undisclosed-recipients:;",
    "Team: a@example.org, b@example.org;",
    "a@example.org,,b@example.org",
    '"Smith, Alice" <a@example.org>',
    '"security@paypal.com" <x@evil.com>',
])
def test_unusual_but_readable_address_doesnt_warn(from_value):
    parsed = parse(f"From: {from_value}")
    assert not any(UNREADABLE in w for w in parsed.parse_warnings)


def test_address_parser_error_gives_a_warning(monkeypatch):
    # Python's address parser didn't raise on anything the damaged-email tests tried, so the
    # test makes it raise
    def fail(*args, **kwargs):
        raise ValueError("unreadable")

    monkeypatch.setattr(parser, "getaddresses", fail)
    parsed = parse("From: a@example.org")
    assert parsed.from_addr is None
    assert "From header couldn't be parsed (ValueError)" in parsed.parse_warnings


def test_two_from_headers_warn_and_use_the_first():
    # Mail clients and DMARC checks don't always pick the same one
    parsed = parse("From: service@paypal.com", "From: x@evil.com")
    # Not also "From has 2 addresses", since only the first header's addresses are read
    assert parsed.parse_warnings == ["2 From headers found, using the first"]
    assert parsed.from_addr.email == "service@paypal.com"


def test_two_addresses_in_from_warn_and_use_the_first():
    parsed = parse("From: service@paypal.com, x@evil.com")
    assert "From has 2 addresses, using the first" in parsed.parse_warnings
    assert parsed.from_addr.email == "service@paypal.com"


def test_two_reply_to_headers_warn():
    parsed = parse("From: a@example.org", "Reply-To: a@example.org", "Reply-To: x@evil.net")
    assert parsed.parse_warnings == ["2 Reply-To headers found, checking the addresses in all of them"]
    assert [a.email for a in parsed.reply_to] == ["a@example.org", "x@evil.net"]
    # One Reply-To gives no warning
    assert parse("From: a@example.org", "Reply-To: a@example.org").parse_warnings == []


def test_to_date_and_message_id():
    parsed = parse("From: a@example.org", "Date: Tue, 06 Oct 2026 10:00:00 +0000", "Message-ID: <abc@example.org>")
    assert [a.email for a in parsed.to] == ["someone@example.net"]
    assert (parsed.date, parsed.message_id) == ("Tue, 06 Oct 2026 10:00:00 +0000", "<abc@example.org>")


def test_missing_headers_are_empty():
    parsed = parse("From: a@example.org")
    assert (parsed.subject, parsed.date, parsed.message_id) == ("", "", "")


INNER_EMAIL = ("From: x@evil.com\r\nSubject: Your account\r\nContent-Type: text/html\r\n\r\n"
               '<a href="https://evil.com/">paypal.com</a>')


@pytest.mark.parametrize("attachment_headers", [
    "Content-Type: message/rfc822",
    # The same with UTF-8 headers
    "Content-Type: message/global",
    # Found by name when sent as a plain file, including Outlook's .msg
    'Content-Type: application/octet-stream\r\nContent-Disposition: attachment; filename="report.eml"',
    'Content-Type: application/vnd.ms-outlook\r\nContent-Disposition: attachment; filename="Report.MSG"',
])
def test_attached_email_warns(attachment_headers):
    content_type, body = multipart(TEXT_PART, f"{attachment_headers}\r\n\r\n{INNER_EMAIL}")
    parsed = parse("From: employee@example.org", content_type, body=body)
    assert any(ATTACHED_EMAIL in w for w in parsed.parse_warnings)


def test_email_inside_an_attached_email_doesnt_warn():
    # old.eml is attached to the forwarded email, not to this one
    inner = ('From: x@evil.com\r\nSubject: Fwd\r\nContent-Type: multipart/mixed; boundary="C"\r\n\r\n'
             '--C\r\nContent-Type: text/plain\r\n\r\nHi\r\n--C\r\nContent-Type: application/octet-stream\r\n'
             'Content-Disposition: attachment; filename="old.eml"\r\n\r\nx\r\n--C--')
    content_type, body = multipart(TEXT_PART, f"Content-Type: message/rfc822\r\n\r\n{inner}")
    attached = [w for w in parse("From: employee@example.org", content_type, body=body).parse_warnings
                if ATTACHED_EMAIL in w]
    assert len(attached) == 1
    assert attached[0].startswith("An unnamed part")


def test_nested_attached_emails_warn_once():
    raw = "To: someone@example.net\r\nSubject: s\r\n" + nested(100, "message/rfc822")
    warnings = parse_bytes(raw.encode()).parse_warnings
    assert len([w for w in warnings if ATTACHED_EMAIL in w]) == 1


def test_attached_email_body_isnt_read_as_this_one():
    content_type, body = multipart(TEXT_PART, f"Content-Type: message/rfc822\r\n\r\n{INNER_EMAIL}")
    parsed = parse("From: employee@example.org", content_type, body=body)
    assert parsed.links == []
    assert parsed.html_body == ""


def test_attachment_inside_an_attached_email_is_listed():
    # A forwarded phish usually carries the file the analyst needs to hash
    inner = ('From: x@evil.com\r\nSubject: Invoice\r\nContent-Type: multipart/mixed; boundary="C"\r\n\r\n'
             f"--C\r\n{TEXT_PART}\r\n--C\r\n{PDF_PART}\r\n--C--")
    content_type, body = multipart(TEXT_PART, f"Content-Type: message/rfc822\r\n\r\n{inner}")
    attachments = parse("From: employee@example.org", content_type, body=body).attachments
    assert [a.filename for a in attachments] == ["invoice.pdf"]


def test_ordinary_attachment_doesnt_warn():
    content_type, body = multipart(TEXT_PART, PDF_PART)
    parsed = parse("From: a@example.org", content_type, body=body)
    assert parsed.parse_warnings == []


def test_attachment_is_hashed():
    content_type, body = multipart(TEXT_PART, PDF_PART)
    attachment, = parse("From: a@example.org", content_type, body=body).attachments
    assert attachment.filename == "invoice.pdf"
    assert attachment.content_type == "application/pdf"
    assert attachment.size == 5
    assert attachment.sha256 == hashlib.sha256(b"hello").hexdigest()


@pytest.mark.parametrize("headers, filename", [
    # Named only in Content-Type, with no Content-Disposition
    ('Content-Type: application/pdf; name="invoice.pdf"', "invoice.pdf"),
    # Marked as an attachment, with no name
    ("Content-Type: application/pdf\r\nContent-Disposition: attachment", ""),
])
def test_attachment_needs_only_a_name_or_the_attachment_mark(headers, filename):
    content_type, body = multipart(TEXT_PART, f"{headers}\r\n\r\nx")
    assert [a.filename for a in parse("From: a@example.org", content_type, body=body).attachments] == [filename]


def test_unknown_body_charset_is_decoded_as_utf8():
    parsed = parse("From: a@example.org", "Content-Type: text/plain; charset=x-unknown", body="Hello")
    assert parsed.text_body == "Hello"
    assert "plain body has an unknown charset, decoded as UTF-8" in parsed.parse_warnings
