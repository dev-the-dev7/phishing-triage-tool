"""Tests for triage/iocs.py: indicators from an email or from alert text, and refang/defang."""

import pytest

from triage.iocs import defang, from_email, from_text, refang
from triage.models import Address, Attachment, Indicators, Link, Origin, ParsedEmail

SHA256 = "043ea8960dc71f654cf0ac9ac501c16d09eed7b0e1528532fe25f122f1cc4f35"
SHA1 = "a9993e364706816aba3e25717850c26c9cd0d89d"
MD5 = "900150983cd24fb0d6963f7d28e17f72"


@pytest.mark.parametrize("defanged, real", [
    ("hxxps://evil[.]com/login", "https://evil.com/login"),
    ("hXXp://evil(.)com", "http://evil.com"),
    ("h**ps://evil{.}com", "https://evil.com"),
    ("evil[dot]com", "evil.com"),
    ("evil (DOT) com", "evil.com"),
    ("user[@]evil[.]com", "user@evil.com"),
    ("user [at] evil [dot] com", "user@evil.com"),
    ("https[:]//evil.com", "https://evil.com"),
    ("hxxps[://]evil.com", "https://evil.com"),
    ("203[.]0[.]113[.]5", "203.0.113.5"),
    # The way a regex writes it
    (r"evil\.com", "evil.com"),
    # Not defanged
    ("httpbin.org", "httpbin.org"),
    ("a hxxp b", "a hxxp b"),
])
def test_refang(defanged, real):
    assert refang(defanged) == real


@pytest.mark.parametrize("real, defanged", [
    ("https://evil.com/login.php", "hxxps://evil[.]com/login[.]php"),
    ("HTTP://evil.com/", "hxxp://evil[.]com/"),
    # Only a scheme is changed, not a domain that starts with http
    ("httpbin.org", "httpbin[.]org"),
    ("user@evil.com", "user[@]evil[.]com"),
    ("203.0.113.5", "203[.]0[.]113[.]5"),
    ("2001:db8::1", "2001:db8::1"),
    (SHA256, SHA256),
])
def test_defang(real, defanged):
    assert defang(real) == defanged
    assert refang(defanged) == real.replace("HTTP", "http")


ALERT = f"""
Alert: user clicked hxxps://login-paypa1[.]com/verify?id=1 from 10.0.0.5
Sender: billing[@]paypa1[.]com
C2: 198.51.100.7:443, ip:2001:DB8:0::1, http://3627734532/x
Seen in: evil[.]net, invoice.pdf, setup.exe
SHA256: {SHA256.upper()}
MD5: {MD5}, SHA-1 {SHA1}
"""


def test_alert_text():
    assert from_text(ALERT) == Indicators(
        urls=["https://login-paypa1.com/verify?id=1", "http://216.58.214.4/x"],
        domains=["login-paypa1.com", "paypa1.com", "evil.net"],
        ips=["216.58.214.4", "10.0.0.5", "198.51.100.7", "2001:db8::1"],
        emails=["billing@paypa1.com"],
        hashes=[SHA256, MD5, SHA1],
    )


@pytest.mark.parametrize("text, url, host", [
    # Punctuation at the end belongs to the sentence
    ("Go to https://evil.com/x.", "https://evil.com/x", "evil.com"),
    ("(see https://evil.com/x)", "https://evil.com/x", "evil.com"),
    ('<a href="https://evil.com/x">', "https://evil.com/x", "evil.com"),
    ("https://evil.com/x https://evil.com/x", "https://evil.com/x", "evil.com"),
    # Markdown around a URL from a chat app
    ("See `https://evil.com/x`", "https://evil.com/x", "evil.com"),
    ("See *https://evil.com/x*", "https://evil.com/x", "evil.com"),
    # A www. link with no scheme opens as http
    ("Go to www.evil.com/x, now", "http://www.evil.com/x", "www.evil.com"),
    # Written the way the browser asks for it, with the host as DNS writes it
    ("HTTP://%65vil.com/x", "http://evil.com/x", "evil.com"),
    ("https://user@evil.com:8443/x?y#z", "https://evil.com:8443/x?y#z", "evil.com"),
    ("https://p\N{CYRILLIC SMALL LETTER A}ypal.com/x", "https://xn--pypal-4ve.com/x", "xn--pypal-4ve.com"),
])
def test_urls_in_text(text, url, host):
    found = from_text(text)
    assert (found.urls, found.domains) == ([url], [host])


def test_url_with_an_ip_host():
    found = from_text("http://0xd83ad604/x and http://[2001:DB8::1]:8080/y")
    assert (found.urls, found.ips) == (["http://216.58.214.4/x", "http://[2001:db8::1]:8080/y"],
                                       ["216.58.214.4", "2001:db8::1"])


def test_text_in_a_url_isnt_read_on_its_own():
    # A file name or hash in a URL's path isn't a domain or a hash of its own
    found = from_text(f"https://evil.com/files/report.zip?h={MD5}")
    assert (found.domains, found.hashes) == (["evil.com"], [])


@pytest.mark.parametrize("text, domains", [
    # Without a scheme, a path is still a path. .py and .sh are real TLDs.
    ("evil[.]com/wp-admin/login.php", ["evil.com"]),
    (r"Process C:\Users\bob\AppData\run.py read C:\Users\bob\.ssh\id_rsa", []),
    ("Ran /usr/bin/update.sh on evil.com", ["evil.com"]),
    (r"Ran C:\setup.py and D:/tools/run.sh", []),
])
def test_file_names_in_a_path_arent_domains(text, domains):
    assert from_text(text).domains == domains


@pytest.mark.parametrize("text", [
    "version 10.0.19041.1", "at 10:30:00", "MAC 00:1a:2b:3c:4d:5e", "999.1.1.1", "01.2.3.4", "1.2.3.4.5",
    # Code in alerts, which leaves ::F, d:: and ::B, all valid IPv6 addresses on their own
    "[Convert]::FromBase64String($x)", "std::string", "Foo::Bar",
])
def test_numbers_that_arent_ips(text):
    assert from_text(text).ips == []


@pytest.mark.parametrize("text", [MD5 + "0", "g" + MD5[1:], MD5[1:]])
def test_hex_that_isnt_a_hash(text):
    assert from_text(text).hashes == []


def test_addresses_ignore_case():
    assert from_text("Billing@PayPa1.com wrote to billing@paypa1.com").emails == ["billing@paypa1.com"]


def test_nothing_found():
    assert from_text("No indicators here, see you at 10:30.") == Indicators()


@pytest.mark.parametrize("text", ["Thanks.Regards", "invoice.pdf", "srv01.corp.local"])
def test_endings_that_arent_tlds_arent_domains(text):
    assert from_text(text).domains == []


def email(**fields) -> ParsedEmail:
    return ParsedEmail(from_addr=Address("PayPal", "service@paypa1.com", "paypa1.com"), **fields)


def test_email_indicators():
    parsed = email(
        reply_to=[Address("", "x@evil.org", "evil.org")],
        return_path=Address("", "bounce@mailer.example", "mailer.example"),
        links=[Link("https://evil.com/a", "paypal.com"), Link("mailto:help@evil.org?subject=Hi", "Help"),
               Link(r"https:\\evil.com\@paypal.com", "Sign in"),
               # URLs written in the plain text part, as the parser reads them
               Link("https://evil.com/a", "https://evil.com/a"), Link("http://www.evil.net/b", "www.evil.net/b")],
        other_urls=["http://3627734532/p.gif"],
        attachments=[Attachment("invoice.pdf", "application/pdf", 5, SHA256)],
    )
    assert from_email(parsed, Origin("203.0.113.5", "mail.paypa1.com", "mx.example.net")) == Indicators(
        # Links are written the way the browser reads them
        urls=["https://evil.com/a", "https://evil.com/@paypal.com", "http://www.evil.net/b", "http://216.58.214.4/p.gif"],
        domains=["evil.com", "www.evil.net", "paypa1.com", "evil.org", "mailer.example"],
        ips=["216.58.214.4", "203.0.113.5"],
        emails=["help@evil.org", "service@paypa1.com", "x@evil.org", "bounce@mailer.example"],
        hashes=[SHA256],
    )


@pytest.mark.parametrize("fields", [
    # Phishing names the real brand to look genuine, and the link check covers what a link shows
    {"text_body": "Log in to paypal.com from 198.51.100.7, or email help@paypal.com"},
    {"links": [Link("https://paypa1.com/", "https://www.paypal.com/")]},
    # Links without a web host
    {"links": [Link("javascript:alert(1)", "x"), Link("/login", "x"), Link("", "x")]},
])
def test_what_an_email_only_mentions_isnt_listed(fields):
    found = from_email(email(**fields), None)
    assert "paypal.com" not in found.domains and "evil.com" not in found.domains
    assert found.ips == []
    assert found.emails == ["service@paypa1.com"]


def test_domains_are_in_the_form_dns_uses():
    parsed = email(links=[Link("https://p\N{CYRILLIC SMALL LETTER A}ypal.com/", "")])
    assert from_email(parsed, None).domains == ["xn--pypal-4ve.com", "paypa1.com"]
    # A dot at the end is the same domain
    parsed = ParsedEmail(from_addr=Address("", "a@evil.com.", "evil.com."), links=[Link("https://evil.com/", "")])
    assert from_email(parsed, None).domains == ["evil.com"]


def test_origin_inside_the_provider_has_no_ip():
    assert from_email(email(), Origin(None, None, "mx.google.com")).ips == []


def test_sender_without_a_domain():
    parsed = ParsedEmail(from_addr=Address("", "undisclosed", ""))
    assert from_email(parsed, None) == Indicators(emails=["undisclosed"])
