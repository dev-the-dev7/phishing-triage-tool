"""Tests for triage/received.py: reading Received headers and finding the server that handed
the email to your provider."""

import pytest

from triage.models import Origin, ParsedEmail
from triage.parser import parse_bytes
from triage.received import _read_hop, find_origin, received_warnings

DATE = "Tue, 6 Oct 2026 10:00:00 +0000"


def origin(*received: str) -> Origin | None:
    # Received headers newest first, the order they're in the email
    return find_origin(ParsedEmail(received=list(received)))


# One hop in each format, as (header, IP, name, receiving server). The IP is always the
# one the receiving server saw, never the HELO name the sender gave, which can be an IP too.
HOP_FORMATS = [
    # Gmail and Postfix: "helo (reverse DNS name [ip])"
    (f"from mail.evil.net (mail.evil.net. [203.0.113.5]) by mx.google.com with ESMTPS id x; {DATE}",
     "203.0.113.5", "mail.evil.net", "mx.google.com"),
    (f"from helo.example (unknown [203.0.113.5]) by mx.example.org (Postfix) with ESMTP; {DATE}",
     "203.0.113.5", "unknown", "mx.example.org"),
    (f"from [8.8.8.8] (unknown [203.0.113.5]) by mx.example.org; {DATE}",
     "203.0.113.5", "unknown", "mx.example.org"),
    # Some servers leave the name out when the lookup fails. The HELO is never used instead.
    (f"from fake.helo ([203.0.113.5]) by mx.example.org; {DATE}",
     "203.0.113.5", "unknown", "mx.example.org"),
    # Microsoft: "name (ip)", where the name is the one the sender gave
    (f"from mail.evil.net (203.0.113.5) by X.mail.protection.outlook.com (10.1.2.3) with Microsoft SMTP Server; {DATE}",
     "203.0.113.5", "mail.evil.net", "X.mail.protection.outlook.com"),
    (f"from [8.8.8.8] (203.0.113.5) by X.mail.protection.outlook.com (10.1.2.3); {DATE}",
     "203.0.113.5", "8.8.8.8", "X.mail.protection.outlook.com"),
    (f"from DM6PR02.prod.outlook.com (2603:10b6:5:1d3::10) by SN6PR02.prod.outlook.com with HTTPS; {DATE}",
     "2603:10b6:5:1d3::10", "DM6PR02.prod.outlook.com", "SN6PR02.prod.outlook.com"),
    # Exim: "rdns ([ip]:port helo=...)", or "[ip] (helo=...)" when the lookup failed
    (f"from mail.evil.net ([203.0.113.5]:41234 helo=fake.helo) by mx.example.org with esmtps; {DATE}",
     "203.0.113.5", "mail.evil.net", "mx.example.org"),
    (f"from [203.0.113.5] (helo=fake.helo) by mx.example.org with esmtp; {DATE}",
     "203.0.113.5", "unknown", "mx.example.org"),
    (f"from [203.0.113.5] (helo=[8.8.8.8]) by mx.example.org with esmtp; {DATE}",
     "203.0.113.5", "unknown", "mx.example.org"),
    (f"from [2001:db8::5] (helo=fake.helo) by mx.example.org with esmtp; {DATE}",
     "2001:db8::5", "unknown", "mx.example.org"),
    # qmail: "unknown (HELO ...) (ip)", where (HELO [ip]) is the sender's
    (f"from unknown (HELO fake.helo) (203.0.113.5) by mx.example.org with SMTP; {DATE}",
     "203.0.113.5", "unknown", "mx.example.org"),
    (f"from unknown (HELO [8.8.8.8]) (203.0.113.5) by mx.example.org with SMTP; {DATE}",
     "203.0.113.5", "unknown", "mx.example.org"),
    # The sender picks the HELO, and one starting with "by" isn't the receiver
    (f"from unknown (HELO bydesign.example) (203.0.113.5) by mx.example.org with SMTP; {DATE}",
     "203.0.113.5", "unknown", "mx.example.org"),
    # Text after the receiver can say "by" too, like a quoted recipient address
    (f'from mail.evil.net (mail.evil.net. [203.0.113.5]) by mx.example.org for <"x by y"@example.org>; {DATE}',
     "203.0.113.5", "mail.evil.net", "mx.example.org"),
    # RFC 5321 spells the keywords FROM and BY, and its grammar ignores case
    (f"FROM mail.evil.net (mail.evil.net. [203.0.113.5]) BY mx.example.org; {DATE}",
     "203.0.113.5", "mail.evil.net", "mx.example.org"),
    # IPv4 written as IPv6 becomes plain IPv4, which lookups need
    (f"from helo (rdns.example [IPv6:::ffff:203.0.113.5]) by mx.example.org; {DATE}",
     "203.0.113.5", "rdns.example", "mx.example.org"),
    (f"from  mail.evil.net  (mail.evil.net. [203.0.113.5])  by  mx.google.com; {DATE}",
     "203.0.113.5", "mail.evil.net", "mx.google.com"),
]


@pytest.mark.parametrize("header, ip, name, by", HOP_FORMATS)
def test_hop_formats(header, ip, name, by):
    assert _read_hop(header) == {"ip": ip, "name": name, "by": by}


@pytest.mark.parametrize("header", [
    f"from x (fake.google.com [8.8.8.8]) (unknown [203.0.113.5]) by mx.example.org; {DATE}",
    f"from (8.8.8.8) (203.0.113.5) by X.mail.protection.outlook.com (10.1.2.3); {DATE}",
])
def test_helo_shaped_like_the_receiver_part_is_skipped(header):
    # The receiver writes its part after the HELO, so the last match is the real one
    assert _read_hop(header)["ip"] == "203.0.113.5"


@pytest.mark.parametrize("header, warns", [
    # Gmail's API submissions and local delivery have no IP, which is normal
    (f"from 776393159873 named unknown by gmailapi.google.com with HTTPREST; {DATE}", False),
    (f"by mx.google.com with SMTP id abc; {DATE}", False),
    # An IP in a format the tool doesn't read could be the handoff, so the analyst is told
    (f"from 203.0.113.5 by mta.example.org with HTTP; {DATE}", True),
    (f"from mail.example.org 203.0.113.5 by mta.example.org with HTTP; {DATE}", True),
])
def test_headers_without_a_readable_hop(header, warns):
    assert _read_hop(header) is None
    assert bool(received_warnings(ParsedEmail(received=[header]))) == warns


def test_warning_names_the_header():
    warnings = received_warnings(ParsedEmail(received=[HOP_FORMATS[0][0], f"from 203.0.113.5 by x; {DATE}"]))
    assert warnings == ["Received header 2 has an IP in a format the tool can't read, so the origin may be "
                        "wrong. Check that header by hand."]
    warnings = received_warnings(ParsedEmail(received=[f"from 203.0.113.{n} by x; {DATE}" for n in range(6)]))
    assert warnings == ["Received headers 1, 2, 3, 4, 5 (and 1 more) have an IP in a format the tool can't read, so "
                        "the origin may be wrong. Check those headers by hand."]


GOOGLE_RELAY = f"from mail-sor-f41.google.com (mail-sor-f41.google.com. [209.85.220.41]) by mx.google.com; {DATE}"


def test_relays_inside_the_provider_are_skipped():
    # The hop from a Google server to a Google server is internal, so the origin is the one below
    found = origin(GOOGLE_RELAY, f"from mail.evil.net (mail.evil.net. [203.0.113.5]) by mail-sor-f41.google.com; {DATE}")
    assert found == Origin("203.0.113.5", "mail.evil.net", "mail-sor-f41.google.com")


def test_microsoft_relays_are_skipped_by_name():
    found = origin(
        f"from SN6PR02.prod.outlook.com (2603:10b6:5:1d3::10) by SN6PR02MB.namprd02.prod.outlook.com with HTTPS; {DATE}",
        f"from mail.evil.net (203.0.113.5) by SN6PR02.mail.protection.outlook.com (10.1.2.3); {DATE}",
    )
    assert found == Origin("203.0.113.5", "mail.evil.net", "SN6PR02.mail.protection.outlook.com",
                           microsoft_hops=[(1, "SN6PR02.prod.outlook.com", "2603:10b6:5:1d3::10")])


def test_hops_taken_as_microsofts_by_name_are_listed():
    # Header 1 has no IP but still counts, so the numbers match the email's. Hops with internal
    # IPs or other providers' names, and hops below the handoff, aren't listed.
    found = origin(
        f"by SN6PR02MB.namprd02.prod.outlook.com with HTTPS; {DATE}",
        f"from SN6PR02.prod.outlook.com (2603:10b6:5:1d3::10) by SN6PR02MB.namprd02.prod.outlook.com with HTTPS; {DATE}",
        f"from DM6PR02.prod.outlook.com (10.1.2.4) by SN6PR02.prod.outlook.com; {DATE}",
        GOOGLE_RELAY,
        f"from x.mail.protection.outlook.com (203.0.113.9) by mail-sor-f41.google.com; {DATE}",
        f"from mail.evil.net (198.51.100.7) by x.mail.protection.outlook.com; {DATE}",
        f"from y.prod.outlook.com (192.0.2.1) by mail.evil.net; {DATE}",
    )
    assert found.microsoft_hops == [(2, "SN6PR02.prod.outlook.com", "2603:10b6:5:1d3::10"),
                                    (5, "x.mail.protection.outlook.com", "203.0.113.9")]
    # With no handoff, a sender calling itself Microsoft's would otherwise go unseen
    found = origin(f"from x.prod.outlook.com (203.0.113.9) by SN6PR02.prod.outlook.com; {DATE}")
    assert (found.ip, found.microsoft_hops) == (None, [(1, "x.prod.outlook.com", "203.0.113.9")])


def test_hops_below_the_handoff_are_claims():
    # The sender wrote everything below the handoff, so its IPs could be made up. The
    # earliest one is shown, since it claims to be where the email started.
    found = origin(f"from mail.evil.net (mail.evil.net. [203.0.113.5]) by mx.google.com; {DATE}",
                   f"from relay (unknown [198.51.100.7]) by mail.evil.net; {DATE}",
                   f"from laptop (unknown [192.0.2.9]) by relay; {DATE}")
    assert found == Origin("203.0.113.5", "mail.evil.net", "mx.google.com", earliest_claim="192.0.2.9")


def test_internal_ips_below_the_handoff_arent_claims():
    found = origin(f"from mail.evil.net (mail.evil.net. [203.0.113.5]) by mx.google.com; {DATE}",
                   f"from laptop (unknown [192.168.1.20]) by mail.evil.net; {DATE}")
    assert found.earliest_claim is None


def test_every_hop_inside_the_provider():
    # Gmail to Gmail: no outside server. The topmost server is named, since it delivered the email.
    found = origin(GOOGLE_RELAY, f"from laptop (unknown [192.168.1.20]) by mail-sor-f41.google.com; {DATE}")
    assert found == Origin(None, None, "mx.google.com")


@pytest.mark.parametrize("ip, internal", [
    ("10.0.0.5", True), ("172.16.0.5", True), ("192.168.1.5", True), ("127.0.0.1", True),
    ("169.254.1.5", True), ("::1", True), ("fd00::5", True), ("fe80::5", True),
    # Carrier-grade NAT, which Python's is_private misses
    ("100.64.0.5", True),
    ("203.0.113.5", False),
    # Reserved and never used, so a hop from one was made up and should stay visible.
    # Python's is_private counts it as private.
    ("240.0.0.1", False),
])
def test_internal_networks(ip, internal):
    found = origin(f"from helo (rdns.example [{ip}]) by mx.example.org; {DATE}")
    assert (found.ip is None) == internal


def test_no_received_headers():
    assert origin() is None
    assert origin(f"from 776393159873 named unknown by gmailapi.google.com with HTTPREST; {DATE}") is None


@pytest.mark.xfail(reason="README limitation: a sender that calls itself *.outlook.com is skipped as internal, "
                          "and only --enrich checks its IP's owner",
                   raises=AssertionError)
def test_sender_claiming_a_microsoft_name():
    found = origin(f"from x.mail.protection.outlook.com (203.0.113.9) by SN6PR02.mail.protection.outlook.com (10.1.2.3); {DATE}",
                   f"from mail.evil.net (198.51.100.7) by x.mail.protection.outlook.com; {DATE}")
    assert found.ip == "203.0.113.9"


def parse_received(*received: str) -> ParsedEmail:
    raw = "\r\n".join([*(f"Received: {r}" for r in received), "From: a@example.org", "Subject: s", "", "Hello"])
    return parse_bytes(raw.encode())


def test_folded_received_header():
    parsed = parse_received(f"from mail.evil.net (mail.evil.net. [203.0.113.5])\r\n\tby mx.google.com with ESMTPS id x;\r\n\t{DATE}")
    assert find_origin(parsed) == Origin("203.0.113.5", "mail.evil.net", "mx.google.com")


def test_encoded_helo_cant_change_the_origin():
    # Decoded, this HELO reads "x (mail-sor-f41.google.com [209.85.220.41])", a fake Google hop
    helo = "=?utf-8?q?x=20=28mail-sor-f41=2Egoogle=2Ecom=20=5B209=2E85=2E220=2E41=5D=29?="
    parsed = parse_received(f"from unknown (HELO {helo}) (203.0.113.5) by mx.example.org with SMTP; {DATE}")
    assert find_origin(parsed).ip == "203.0.113.5"
