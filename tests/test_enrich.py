"""Tests for the reputation lookups (triage/enrich.py). Every answer is made up here, and
nothing goes online: requests.get is replaced, and conftest.py makes any real connection fail."""

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest
import requests

from triage import enrich
from triage.enrich import check_domain_age, check_microsoft_hops, look_up
from triage.models import Attachment, Indicators, LookupStatus, Origin, Reputation, Result

VT = "https://www.virustotal.com/api/v3"
ABUSEIPDB = "https://api.abuseipdb.com/api/v2/check"
SHA = "a" * 64
# 2026-10-12 09:30 UTC
CHECKED = 1791797400
NOT_FOUND = (404, {"error": {"code": "NotFoundError", "message": "not found"}})


def vt_report(malicious=0, suspicious=0, undetected=0, harmless=0, checked=CHECKED, created=None):
    # Engines that timed out are in the stats too, and aren't counted
    stats = {"malicious": malicious, "suspicious": suspicious, "undetected": undetected, "harmless": harmless,
             "timeout": 3}
    attributes = {"last_analysis_stats": stats, "last_analysis_date": checked}
    if created is not None:
        attributes["creation_date"] = created
    return {"data": {"attributes": attributes}}


def abuseipdb_report(confidence=0, reports=0, users=0, **more):
    return {"data": {"ipAddress": "8.8.8.8", "abuseConfidenceScore": confidence, "totalReports": reports,
                     "numDistinctUsers": users, **more}}


def answer(status: int, body) -> MagicMock:
    # A response to use in a with block. Bytes are sent as they are, anything else as JSON.
    data = body if isinstance(body, bytes) else json.dumps(body).encode()
    response = MagicMock()
    response.__enter__.return_value = response
    response.status_code = status
    response.iter_content.return_value = [data[i:i + 100] for i in range(0, len(data), 100)]
    return response


class Server:
    # Stands in for requests.get. It answers by address (AbuseIPDB's with the IP after a ?),
    # gives VirusTotal's not found for anything else, and keeps every request. A list of
    # answers is given one per request. Each request takes delay seconds on the test clock.
    def __init__(self, clock):
        self.clock = clock
        self.delay = 0
        self.answers = {}
        self.requests = []

    def get(self, url, **kwargs):
        self.requests.append((url, kwargs))
        self.clock.now += self.delay
        params = kwargs["params"]
        found = self.answers.get(f"{url}?{params['ipAddress']}" if params else url, NOT_FOUND)
        if isinstance(found, list):
            found = found.pop(0)
        if isinstance(found, Exception):
            raise found
        return answer(*found)

    def asked(self) -> list[str]:
        return [f"{url}?{kwargs['params']['ipAddress']}" if kwargs["params"] else url for url, kwargs in self.requests]


@pytest.fixture
def server(monkeypatch, clock):
    fake = Server(clock)
    monkeypatch.setattr(enrich.requests, "get", fake.get)
    return fake


@pytest.fixture
def keys(monkeypatch):
    monkeypatch.setenv("VT_API_KEY", "vt-key")
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "abuseipdb-key")


def texts(results) -> dict[str, list[str]]:
    return {value: [f"{result.service}: {result.text}" for result in found] for value, found in results.items()}


def test_a_file_is_looked_up_by_its_hash(server, keys):
    server.answers[f"{VT}/files/{SHA}"] = (200, vt_report(malicious=5, suspicious=2, undetected=60))
    results = look_up(Indicators(hashes=[SHA]))
    assert texts(results) == {SHA: ["VirusTotal: 5 of 67 engines flagged it malicious, 2 suspicious, "
                                    "last checked 2026-10-12"]}
    assert results[SHA][0].status == LookupStatus.FOUND
    assert results[SHA][0].facts == {"malicious": 5, "suspicious": 2, "undetected": 60, "harmless": 0,
                                     "checked": "2026-10-12", "registered": ""}
    # A GET with the key in a header, never in the address, and no redirects the key could follow
    assert server.requests == [(f"{VT}/files/{SHA}", {"headers": {"x-apikey": "vt-key"}, "params": None,
                                                      "timeout": 20, "stream": True, "allow_redirects": False})]


@pytest.mark.parametrize("found, address", [
    (Indicators(domains=["evil.com"]), f"{VT}/domains/evil.com"),
    (Indicators(ips=["8.8.8.8"]), f"{VT}/ip_addresses/8.8.8.8"),
    (Indicators(ips=["2001:4860:4860::8888"]), f"{VT}/ip_addresses/2001:4860:4860::8888"),
    # base64 without the = padding
    (Indicators(urls=["https://evil.com/login"]), f"{VT}/urls/aHR0cHM6Ly9ldmlsLmNvbS9sb2dpbg"),
    # The part after # never reaches the site, so it isn't sent, even with an address in it
    (Indicators(urls=["https://evil.com/login#jordan.lee@example.com"]), f"{VT}/urls/aHR0cHM6Ly9ldmlsLmNvbS9sb2dpbg"),
    # An address ends in a real TLD, and .png isn't one
    (Indicators(urls=["https://cdn.evil.com/logo@2x.png"]), f"{VT}/urls/aHR0cHM6Ly9jZG4uZXZpbC5jb20vbG9nb0AyeC5wbmc"),
    # A / in a value can't change which report is asked for
    (Indicators(domains=["x/../evil.com"]), f"{VT}/domains/x%2F..%2Fevil.com"),
], ids=["domain", "IPv4", "IPv6", "URL", "URL fragment", "image for sharp screens", "encoded"])
def test_where_each_indicator_is_looked_up(server, keys, found, address):
    look_up(found)
    assert [asked for asked in server.asked() if asked.startswith(VT)] == [address]


def test_ips_are_looked_up_with_abuseipdb_too(server, keys):
    # AbuseIPDB first, since it has no limit a minute to wait for
    server.answers[f"{ABUSEIPDB}?8.8.8.8"] = (200, abuseipdb_report(confidence=87, reports=1234, users=5))
    results = look_up(Indicators(ips=["8.8.8.8"]))
    assert texts(results) == {"8.8.8.8": ["AbuseIPDB: reported 1,234 times by 5 users in the last 90 days, "
                                          "abuse confidence 87%",
                                          "VirusTotal: not found (unknown, not clean)"]}
    assert server.requests[0] == (ABUSEIPDB, {
        "headers": {"Key": "abuseipdb-key", "Accept": "application/json"},
        "params": {"ipAddress": "8.8.8.8", "maxAgeInDays": 90}, "timeout": 20, "stream": True,
        "allow_redirects": False})


@pytest.mark.parametrize("report, text", [
    (abuseipdb_report(confidence=25, reports=1, users=1), "reported 1 time by 1 user in the last 90 days, "
                                                          "abuse confidence 25%"),
    (abuseipdb_report(), "no reports in the last 90 days"),
    # Google's DNS server, which people's firewalls report and AbuseIPDB lists as trusted
    (abuseipdb_report(reports=239, users=94, isWhitelisted=True, isp="Google LLC", countryCode="US"),
     "reported 239 times by 94 users in the last 90 days, abuse confidence 0% (on its trusted list), "
     "Google LLC in US"),
    (abuseipdb_report(isp=None, countryCode="NL", isWhitelisted=None), "no reports in the last 90 days, in NL"),
    (abuseipdb_report(isp="DigitalOcean, LLC", countryCode=None), "no reports in the last 90 days, DigitalOcean, LLC"),
    (abuseipdb_report(isWhitelisted="yes"), "no reports in the last 90 days"),
    (abuseipdb_report(isp="  ", countryCode=" US "), "no reports in the last 90 days, in US"),
], ids=["one report", "no reports", "trusted", "country only", "network only", "trusted only when true", "spaces"])
def test_abuseipdb_results_in_plain_words(server, monkeypatch, report, text):
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "abuseipdb-key")
    server.answers[f"{ABUSEIPDB}?8.8.8.8"] = (200, report)
    assert texts(look_up(Indicators(ips=["8.8.8.8"])))["8.8.8.8"][0] == f"AbuseIPDB: {text}"


@pytest.mark.parametrize("report, text", [
    (vt_report(undetected=60, harmless=10, checked=None), "0 of 70 engines flagged it malicious"),
    # Known to VirusTotal, but nothing to go on
    (vt_report(checked=None), "in VirusTotal, but no engine has checked it (unknown, not clean)"),
    ({"data": {"attributes": {}}}, "in VirusTotal, but no engine has checked it (unknown, not clean)"),
], ids=["no date", "no engines", "no stats"])
def test_virustotal_results_in_plain_words(server, keys, report, text):
    server.answers[f"{VT}/domains/evil.com"] = (200, report)
    assert texts(look_up(Indicators(domains=["evil.com"]))) == {"evil.com": [f"VirusTotal: {text}"]}


# 2027-01-10 00:00 UTC, five days before the test clock's 2027-01-15
CREATED_LAST_WEEK = 1_799_539_200


def test_a_domains_registration_date_is_shown(server, keys):
    server.answers[f"{VT}/domains/evil.com"] = (200, vt_report(undetected=60, created=CREATED_LAST_WEEK))
    assert texts(look_up(Indicators(domains=["evil.com"]))) == {
        "evil.com": ["VirusTotal: 0 of 60 engines flagged it malicious, last checked 2026-10-12, registered 2027-01-10"]}


def test_a_files_creation_date_isnt_a_registration(server, keys):
    # It's when the program was built
    server.answers[f"{VT}/files/{SHA}"] = (200, vt_report(undetected=60, created=CREATED_LAST_WEEK))
    assert "registered" not in texts(look_up(Indicators(hashes=[SHA])))[SHA][0]


def test_a_hosted_names_date_isnt_shown(server, keys):
    # It's when github.io was registered, not when the site was made
    hosted = "paypal-login.github.io"
    server.answers[f"{VT}/domains/{hosted}"] = (200, vt_report(undetected=60, created=CREATED_LAST_WEEK))
    assert "registered" not in texts(look_up(Indicators(domains=[hosted])))[hosted][0]


@pytest.mark.parametrize("created", ["2004-03-01", 10 ** 20], ids=["as text", "too big"])
def test_a_registration_date_that_doesnt_read_is_left_out(server, keys, created):
    # It comes from whois records, so the engines' verdicts still count
    server.answers[f"{VT}/domains/evil.com"] = (200, vt_report(undetected=60, created=created))
    assert texts(look_up(Indicators(domains=["evil.com"]))) == {
        "evil.com": ["VirusTotal: 0 of 60 engines flagged it malicious, last checked 2026-10-12"]}


def registered(on: str) -> list[Reputation]:
    return [Reputation("VirusTotal", LookupStatus.FOUND, "", {"registered": on})]


@pytest.mark.parametrize("domains, results, result, evidence", [
    (["evil.com", "old.com"], {"evil.com": registered("2027-01-10"), "old.com": registered("2004-03-01")},
     Result.FLAG, "evil.com was registered 2027-01-10, 5 days ago"),
    (["evil.com"], {"evil.com": registered("2027-01-15")}, Result.FLAG, "evil.com was registered 2027-01-15, today"),
    (["evil.com"], {"evil.com": registered("2026-12-17")}, Result.FLAG,
     "evil.com was registered 2026-12-17, 29 days ago"),
    (["evil.com"], {"evil.com": registered("2026-12-16")}, Result.PASS,
     "Every domain was registered at least 30 days ago: evil.com 2026-12-16"),
    # A new one is flagged even when another has no date
    (["evil.com", "x.com"], {"evil.com": registered("2027-01-14")}, Result.FLAG,
     "evil.com was registered 2027-01-14, 1 day ago"),
    (["evil.com", "x.com"], {"evil.com": registered("2004-03-01")}, Result.INCONCLUSIVE,
     "No registration date for x.com"),
    (["x.com"], {"x.com": [Reputation("VirusTotal", LookupStatus.NOT_FOUND, "not found (unknown, not clean)")]},
     Result.INCONCLUSIVE, "No registration date for x.com"),
    # Even with a date from an older cache, it's the service's
    (["paypal-login.github.io"], {"paypal-login.github.io": registered("2013-02-08")}, Result.INCONCLUSIVE,
     "No registration date for paypal-login.github.io (only github.io has one)"),
    # From an edited cache, and in the future
    (["x.com"], {"x.com": registered("soon")}, Result.INCONCLUSIVE, "No registration date for x.com"),
    (["x.com"], {"x.com": registered("2030-01-01")}, Result.INCONCLUSIVE,
     "No registration date for x.com"),
    # Well-known and internal names aren't in question
    (["paypal.com", "gmail.com", "srv01.corp.local"], {}, Result.PASS,
     "No sender or link domain besides well-known ones and your own"),
], ids=["new", "today", "29 days", "30 days", "new and no date", "old and no date", "not found", "hosted",
        "date doesn't read", "date in the future", "nothing in question"])
def test_domain_age(domains, results, result, evidence):
    check = check_domain_age(Indicators(domains=domains), results)
    assert (check.result, check.evidence) == (result, evidence)


def test_your_own_domains_age_isnt_in_question(monkeypatch):
    monkeypatch.setattr(enrich, "OWN_DOMAINS", ["contoso.com"])
    assert check_domain_age(Indicators(domains=["mail.contoso.com"]), {}).result == Result.PASS


HOPS = [(2, "a.prod.outlook.com", "2603:10b6::1"), (3, "b.prod.outlook.com", "2603:10b6::2")]
SIX_HOPS = [(n + 2, f"h{n}.prod.outlook.com", f"2603:10b6::{n + 10}") for n in range(6)]


def test_hops_named_as_microsofts_go_after_the_origin(server, keys):
    # They're only asked about their owner, so VirusTotal doesn't get them
    origin = Origin("8.8.8.8", "mail.evil.net", "x.outlook.com", microsoft_hops=HOPS)
    look_up(Indicators(ips=["1.1.1.1", "8.8.8.8"]), origin=origin)
    assert server.asked() == [f"{ABUSEIPDB}?8.8.8.8", f"{ABUSEIPDB}?2603:10b6::1", f"{ABUSEIPDB}?2603:10b6::2",
                              f"{ABUSEIPDB}?1.1.1.1", f"{VT}/ip_addresses/1.1.1.1", f"{VT}/ip_addresses/8.8.8.8"]


def test_hops_are_looked_up_when_no_server_was_outside_microsoft(server, keys):
    # A sender calling itself Microsoft's that adds no headers below leaves no origin
    look_up(Indicators(), origin=Origin(None, None, "x.outlook.com", microsoft_hops=HOPS))
    assert server.asked() == [f"{ABUSEIPDB}?2603:10b6::1", f"{ABUSEIPDB}?2603:10b6::2"]


@pytest.mark.parametrize("domain, owner", [(" Microsoft.COM ", "microsoft.com"), (None, "")])
def test_the_ips_owner_is_kept(server, monkeypatch, domain, owner):
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "abuseipdb-key")
    server.answers[f"{ABUSEIPDB}?8.8.8.8"] = (200, abuseipdb_report(domain=domain))
    assert look_up(Indicators(ips=["8.8.8.8"]))["8.8.8.8"][0].facts["domain"] == owner


def owned_by(domain: str) -> list[Reputation]:
    return [Reputation("AbuseIPDB", LookupStatus.FOUND, "no reports in the last 90 days", {"domain": domain})]


SKIPPED = [Reputation("AbuseIPDB", LookupStatus.SKIPPED, "skipped, over the limit of 10 lookups a run")]


@pytest.mark.parametrize("hops, results, result, evidence", [
    (HOPS, {"2603:10b6::1": owned_by("microsoft.com"), "2603:10b6::2": owned_by("digitalocean.com")}, Result.FLAG,
     "Received header 3 calls itself b.prod.outlook.com, but AbuseIPDB lists 2603:10b6::2 under digitalocean.com: "
     "no reports in the last 90 days. The first is the server Microsoft really got the email from, so the Origin "
     "line may be wrong"),
    (HOPS, {"2603:10b6::1": owned_by("digitalocean.com"), "2603:10b6::2": owned_by("digitalocean.com")}, Result.FLAG,
     "Received header 2 calls itself a.prod.outlook.com, but AbuseIPDB lists 2603:10b6::1 under digitalocean.com: "
     "no reports in the last 90 days; Received header 3 calls itself b.prod.outlook.com, but AbuseIPDB lists "
     "2603:10b6::2 under digitalocean.com: no reports in the last 90 days. The first is the server Microsoft really "
     "got the email from, so the Origin line may be wrong"),
    # The sender wrote every header below the faked one, so their owners don't matter
    (HOPS, {"2603:10b6::1": owned_by("digitalocean.com"), "2603:10b6::2": SKIPPED}, Result.FLAG,
     "Received header 2 calls itself a.prod.outlook.com, but AbuseIPDB lists 2603:10b6::1 under digitalocean.com: "
     "no reports in the last 90 days. The first is the server Microsoft really got the email from, so the Origin "
     "line may be wrong"),
    (HOPS, {"2603:10b6::1": owned_by("microsoft.com"), "2603:10b6::2": owned_by("outlook.com")}, Result.PASS,
     "Every hop named as a Microsoft server has a Microsoft IP, in Received headers 2, 3"),
    (HOPS[:1], {"2603:10b6::1": owned_by("microsoft.com")}, Result.PASS,
     "Every hop named as a Microsoft server has a Microsoft IP, in Received header 2"),
    (SIX_HOPS, {ip: owned_by("microsoft.com") for _, _, ip in SIX_HOPS}, Result.PASS,
     "Every hop named as a Microsoft server has a Microsoft IP, in Received headers 2, 3, 4, 5, 6 (and 1 more)"),
    (HOPS, {"2603:10b6::1": owned_by(""), "2603:10b6::2": SKIPPED}, Result.INCONCLUSIVE,
     "Who owns these isn't known: Received header 2 (2603:10b6::1): AbuseIPDB doesn't list an owner; "
     "Received header 3 (2603:10b6::2): skipped, over the limit of 10 lookups a run"),
    (HOPS[:1], {}, Result.INCONCLUSIVE, "Who owns these isn't known: Received header 2 (2603:10b6::1): not looked up"),
    ([], {}, Result.PASS, "No hop was taken as Microsoft's on its name alone"),
], ids=["faked", "two faked", "faked above unknown", "all Microsoft's", "one", "six", "unknown", "not looked up",
        "none"])
def test_microsoft_hops(hops, results, result, evidence):
    check = check_microsoft_hops(Origin(None, None, "x.outlook.com", microsoft_hops=hops), results)
    assert (check.result, check.evidence, check.caveats) == (result, evidence, [])


def test_a_faked_hop_below_an_unknown_one_may_not_be_the_handoff():
    # The unknown one could be the sender's server, and the faked one a header it wrote
    check = check_microsoft_hops(Origin(None, None, "x.outlook.com", microsoft_hops=HOPS),
                                 {"2603:10b6::1": SKIPPED, "2603:10b6::2": owned_by("digitalocean.com")})
    assert check.result == Result.FLAG
    assert check.evidence == ("Received header 3 calls itself b.prod.outlook.com, but AbuseIPDB lists 2603:10b6::2 "
                              "under digitalocean.com: no reports in the last 90 days. The Origin line may be wrong")
    assert check.caveats == ["Who owns these isn't known, so Microsoft may have got the email from one of them "
                             "instead: Received header 2 (2603:10b6::1): skipped, over the limit of 10 lookups a run"]


def test_no_received_headers_means_no_microsoft_hops():
    assert check_microsoft_hops(None, {}).result == Result.PASS


def test_not_found_is_unknown_and_not_saved(server, keys):
    # A new phishing site can be reported within the hour, so it's asked about again
    found = Indicators(domains=["new-phish.com"])
    results = look_up(found)
    assert texts(results) == {"new-phish.com": ["VirusTotal: not found (unknown, not clean)"]}
    assert results["new-phish.com"][0].status == LookupStatus.NOT_FOUND
    look_up(found)
    assert len(server.requests) == 2


def test_a_report_no_engine_has_checked_isnt_saved(server, keys):
    # Like not found, it can change as soon as VirusTotal scans it
    server.answers[f"{VT}/domains/evil.com"] = (200, vt_report(checked=None))
    look_up(Indicators(domains=["evil.com"]))
    look_up(Indicators(domains=["evil.com"]))
    assert len(server.requests) == 2


@pytest.mark.parametrize("found, reason", [
    (Indicators(ips=["10.0.0.5"]), "private or reserved address"),
    # Reserved for documentation, never used on the internet
    (Indicators(ips=["198.51.100.7"]), "private or reserved address"),
    (Indicators(urls=["http://10.0.0.5/admin"]), "private or reserved address"),
    (Indicators(domains=["srv01.corp.local"]), "not a public domain name"),
    (Indicators(urls=["http://intranet/login"]), "not a public domain name"),
    (Indicators(urls=["http://"]), "not a public domain name"),
    # DNS's own names, from DNS logs: a lookup for the name of 192.168.0.5, and a home network
    (Indicators(domains=["5.0.168.192.in-addr.arpa"]), "not a public domain name"),
    (Indicators(domains=["nas.home.arpa"]), "not a public domain name"),
    # Phishing links often carry the reader's address
    (Indicators(urls=["https://evil.com/login?user=jordan.lee%40example.com"]), "it has an email address in it"),
    # A link carrying another link, with the address encoded twice (%2540)
    (Indicators(urls=["https://evil.com/r?next=https%3A%2F%2Fevil.com%2F%3Fe%3Djordan.lee%2540example.com"]),
     "it has an email address in it"),
    # Decoded, %2541 becomes A and joins the address's TLD, so each decoding is searched
    (Indicators(urls=["https://evil.com/?e=jordan.lee@example.com%2541"]), "it has an email address in it"),
], ids=["private IP", "reserved IP", "URL to a private IP", "internal name", "URL to an internal name",
        "URL without a host", "reverse DNS name", "home network name", "URL with an address",
        "URL with an address encoded twice", "URL with an address a decoding hides"])
def test_what_shouldnt_leave_your_network_isnt_sent(server, keys, found, reason):
    results = look_up(found)
    # IPs get a result from each service
    assert [(result.status, result.text) for listed in results.values() for result in listed] == [
        (LookupStatus.SKIPPED, f"skipped, {reason}")] * (2 if found.ips else 1)
    assert server.requests == []


def test_your_own_domains_arent_sent(server, keys, monkeypatch):
    # Alert text can name your machines, and VirusTotal has nothing new to say about your
    # domains. A domain is listed in OWN_DOMAINS by any name under it, as in the other checks.
    monkeypatch.setattr(enrich, "OWN_DOMAINS", ["mail.contoso.com"])
    values = ["https://intranet.contoso.com/hr", "wks-0231.corp.contoso.com", "contoso.com"]
    found = Indicators(urls=values[:1], domains=values[1:])
    assert texts(look_up(found)) == {value: ["VirusTotal: skipped, one of your own domains"] for value in values}
    assert server.requests == []


def test_without_keys_nothing_is_sent(server):
    results = look_up(Indicators(urls=["https://evil.com/"], domains=["evil.com"], ips=["8.8.8.8"], hashes=[SHA]))
    assert texts(results) == {
        "https://evil.com/": ["VirusTotal: unavailable, VT_API_KEY isn't set"],
        "evil.com": ["VirusTotal: unavailable, VT_API_KEY isn't set"],
        "8.8.8.8": ["AbuseIPDB: unavailable, ABUSEIPDB_API_KEY isn't set",
                    "VirusTotal: unavailable, VT_API_KEY isn't set"],
        SHA: ["VirusTotal: unavailable, VT_API_KEY isn't set"],
    }
    assert server.requests == []
    assert not enrich.CACHE_FILE.exists()


def test_the_key_isnt_shown_when_a_service_is_printed(keys):
    service = enrich._Service("VirusTotal", "VT_API_KEY", 8)
    assert service.key == "vt-key"
    assert "vt-key" not in repr(service)


@pytest.mark.parametrize("value, sent", [(" vt-key\n", True), ("  ", False)], ids=["pasted with spaces", "blank"])
def test_spaces_around_a_key_are_dropped(server, monkeypatch, value, sent):
    monkeypatch.setenv("VT_API_KEY", value)
    look_up(Indicators(domains=["evil.com"]))
    assert [kwargs["headers"] for _, kwargs in server.requests] == ([{"x-apikey": "vt-key"}] if sent else [])


@pytest.mark.parametrize("value", [
    "vt-key\N{ZERO WIDTH SPACE}",
    "\N{LEFT DOUBLE QUOTATION MARK}vt-key\N{RIGHT DOUBLE QUOTATION MARK}",
    "vt\nkey",
], ids=["zero-width space", "curly quotes", "line break inside"])
def test_a_key_with_a_character_a_header_cant_carry(server, monkeypatch, value):
    # Copying a key can pick these up, and the request would crash or be refused
    monkeypatch.setenv("VT_API_KEY", value)
    assert texts(look_up(Indicators(domains=["evil.com"]))) == {
        "evil.com": ["VirusTotal: unavailable, the key in VT_API_KEY has a character a key can't have"]}
    assert server.requests == []


def test_virustotal_order_and_limit(server, keys, capsys, clock):
    # Brand domains, free webmail and links to them go last. Past 8, nothing more is sent.
    found = Indicators(hashes=[SHA], urls=["https://login.evil.com/a", "https://www.paypal.com/b"],
                       domains=["login.evil.com", "www.paypal.com", "sender.net", "gmail.com", "outlook.com"],
                       ips=["8.8.8.8"])
    results = look_up(found)
    assert [address for address in server.asked() if address.startswith(VT)] == [
        f"{VT}/files/{SHA}",
        f"{VT}/domains/sender.net",
        f"{VT}/domains/login.evil.com",
        f"{VT}/urls/aHR0cHM6Ly9sb2dpbi5ldmlsLmNvbS9h",
        f"{VT}/ip_addresses/8.8.8.8",
        f"{VT}/domains/gmail.com",
        f"{VT}/domains/outlook.com",
        f"{VT}/domains/www.paypal.com",
    ]
    assert texts(results)["https://www.paypal.com/b"] == ["VirusTotal: skipped, over the limit of 8 lookups a run"]
    # 4 a minute: the 5th waits until a minute and a second after the 1st
    assert clock.slept == [61]
    assert capsys.readouterr().err == ("Waiting 61 seconds for VirusTotal's limit of 4 lookups a minute "
                                       "(Ctrl+C skips the rest of the lookups)\n")


LOGO = "b" * 64
SVG = "c" * 64


def test_pictures_go_after_the_links(server, keys):
    # An SVG can hold scripts, so it goes first with the other files
    attachments = [Attachment("image001.png", "image/png", 100, LOGO),
                   Attachment("invoice.svg", "image/svg+xml", 100, SVG),
                   Attachment("invoice.html", "text/html", 100, SHA)]
    found = Indicators(hashes=[LOGO, SVG, SHA], urls=["https://login.evil.com/a"], domains=["sender.net"],
                       ips=["8.8.8.8"])
    look_up(found, attachments)
    assert [address for address in server.asked() if address.startswith(VT)] == [
        f"{VT}/files/{SVG}",
        f"{VT}/files/{SHA}",
        f"{VT}/domains/sender.net",
        f"{VT}/urls/aHR0cHM6Ly9sb2dpbi5ldmlsLmNvbS9h",
        f"{VT}/files/{LOGO}",
        f"{VT}/ip_addresses/8.8.8.8",
    ]


@pytest.mark.parametrize("filename, content_type, picture", [
    ("image001.png", "image/png", True),
    ("Photo.JPG", "image/jpeg", True),
    ("invoice.svg", "image/svg+xml", False),
    # Named like a picture, but a mail client can go by the type and show it as SVG
    ("logo.png", "image/svg+xml", False),
    # Windows goes by the name, so these open as a program and a web page
    ("logo.png.exe", "image/png", False),
    ("logo.html", "image/png", False),
    ("image001.png", "application/octet-stream", False),
], ids=["png", "capital JPG", "SVG", "SVG named png", "program", "web page", "not declared a picture"])
def test_what_counts_as_a_picture(filename, content_type, picture):
    assert enrich._is_picture(Attachment(filename, content_type, 100, LOGO)) == picture


def test_a_hash_another_file_has_isnt_a_picture(server, keys):
    # The same bytes attached as invoice.html and logo.png can't move the web page back
    attachments = [Attachment("logo.png", "image/png", 100, SHA), Attachment("invoice.html", "text/html", 100, SHA)]
    look_up(Indicators(hashes=[SHA], domains=["sender.net"]), attachments)
    assert server.asked() == [f"{VT}/files/{SHA}", f"{VT}/domains/sender.net"]


def test_flagged_lookalikes_go_first(server, keys):
    # Their age is the best evidence for or against them, so a long email can't push them out.
    # The checks name a domain the way it displays.
    found = Indicators(domains=["sender.net", "xn--pypal-4ve.com", "paypa1.com"])
    look_up(found, flagged=["p\N{CYRILLIC SMALL LETTER A}ypal.com", "paypa1.com."])
    assert server.asked() == [f"{VT}/domains/xn--pypal-4ve.com", f"{VT}/domains/paypa1.com", f"{VT}/domains/sender.net"]


def test_waits_only_as_long_as_it_needs(server, keys, capsys, clock):
    # Each lookup takes 15 seconds, so the 5th is sent 60 seconds after the 1st
    server.delay = 15
    look_up(Indicators(domains=[f"site{n}.com" for n in range(5)]))
    assert clock.slept == [1]
    assert capsys.readouterr().err == ("Waiting 1 second for VirusTotal's limit of 4 lookups a minute "
                                       "(Ctrl+C skips the rest of the lookups)\n")


def test_abuseipdb_limit(server, monkeypatch):
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "abuseipdb-key")
    ips = [f"8.8.8.{n}" for n in range(12)]
    results = look_up(Indicators(ips=ips))
    assert len(server.requests) == 10
    assert [texts(results)[ip][0] for ip in ips[10:]] == ["AbuseIPDB: skipped, over the limit of 10 lookups a run"] * 2
    # Said once for the run in the report, not under each indicator
    assert all(results[ip][0].for_the_run for ip in ips[10:])


@pytest.mark.parametrize("failure, reason", [
    ((401, {"error": {"code": "WrongCredentialsError"}}), "the key in VT_API_KEY was refused"),
    ((403, {"error": {"code": "ForbiddenError"}}), "the key in VT_API_KEY was refused"),
    (requests.ConnectionError("vt-key"), "it couldn't be reached (ConnectionError)"),
    (requests.Timeout(), "it couldn't be reached (Timeout)"),
    # A proxy or sign-in page. The redirect isn't followed, so the key doesn't go with it.
    ((302, b""), "it answered with a redirect (302)"),
    ((200, b"<html>Sign in to the network</html>"), "its answer couldn't be read (status 200)"),
    # A page's status isn't the service's: its 403 isn't a refused key, and its 404 isn't not found
    ((403, b"<html>Blocked by your network</html>"), "its answer couldn't be read (status 403)"),
    ((404, b"<html>Page not found</html>"), "its answer couldn't be read (status 404)"),
    ((200, b"[" * 100_000), "its answer couldn't be read (status 200)"),
], ids=["401", "403", "can't connect", "timeout", "redirect", "not JSON", "block page", "page not found",
        "nested too deep"])
def test_a_failure_every_lookup_would_hit_stops_the_rest(server, keys, failure, reason):
    # Nothing more is sent: the next lookups would fail the same way
    server.answers[f"{VT}/domains/first.com"] = failure
    results = look_up(Indicators(domains=["first.com", "second.com"]))
    assert texts(results) == {"first.com": [f"VirusTotal: unavailable, {reason}"],
                              "second.com": [f"VirusTotal: unavailable, {reason}"]}
    assert results["first.com"][0].for_the_run and results["second.com"][0].for_the_run
    assert len(server.requests) == 1
    # The key isn't shown, even when the error had it
    assert "vt-key" not in str(texts(results))


TOO_MANY = (429, {"error": {"code": "QuotaExceededError"}})


def test_a_minute_used_up_by_an_earlier_run_is_waited_out(server, keys, capsys, clock):
    # Each run only counts its own lookups, so the run just before this one can have used up
    # VirusTotal's 4 for the minute
    server.answers[f"{VT}/domains/evil.com"] = [TOO_MANY, (200, vt_report(malicious=2, undetected=60))]
    assert texts(look_up(Indicators(domains=["evil.com"]))) == {
        "evil.com": ["VirusTotal: 2 of 62 engines flagged it malicious, last checked 2026-10-12"]}
    assert clock.slept == [61]
    assert capsys.readouterr().err == ("VirusTotal's limit was reached, maybe by an earlier run in the last "
                                       "minute. Waiting 61 seconds to try once more (Ctrl+C skips the rest of "
                                       "the lookups)\n")


def test_still_over_the_limit_a_minute_later(server, keys, clock):
    # Then the day's 500 are used up, and nothing more is sent
    server.answers[f"{VT}/domains/first.com"] = TOO_MANY
    results = look_up(Indicators(domains=["first.com", "second.com"]))
    assert texts(results) == {"first.com": ["VirusTotal: unavailable, its daily limit was reached"],
                              "second.com": ["VirusTotal: unavailable, its daily limit was reached"]}
    assert server.asked() == [f"{VT}/domains/first.com"] * 2
    assert clock.slept == [61]


def test_abuseipdb_failure_stops_only_abuseipdb(server, keys):
    # AbuseIPDB's limits are only daily, so it isn't asked again
    server.answers[f"{ABUSEIPDB}?8.8.8.8"] = (429, {"errors": [{"detail": "Daily rate limit of 1000 requests "
                                                                         "exceeded", "status": 429}]})
    results = look_up(Indicators(ips=["8.8.8.8", "8.8.4.4"]))
    assert texts(results)["8.8.4.4"] == ["AbuseIPDB: unavailable, its daily limit was reached",
                                         "VirusTotal: not found (unknown, not clean)"]
    assert server.asked() == [f"{ABUSEIPDB}?8.8.8.8", f"{VT}/ip_addresses/8.8.8.8", f"{VT}/ip_addresses/8.8.4.4"]


@pytest.mark.parametrize("failure, reason", [
    ((500, {"error": {"code": "InternalError"}}), "it answered with error 500"),
    # One indicator it can't read, which says nothing about the others
    ((400, {"error": {"code": "BadRequestError"}}), "it answered with error 400"),
    # JSON, so from the service, but without what a report has
    ((200, {"data": None}), "its answer couldn't be read"),
], ids=["server error", "bad request", "not a report"])
def test_other_failures_only_affect_that_lookup(server, keys, failure, reason):
    server.answers[f"{VT}/domains/first.com"] = failure
    server.answers[f"{VT}/domains/second.com"] = (200, vt_report(undetected=70))
    results = look_up(Indicators(domains=["first.com", "second.com"]))
    assert texts(results) == {"first.com": [f"VirusTotal: unavailable, {reason}"],
                              "second.com": ["VirusTotal: 0 of 70 engines flagged it malicious, last checked 2026-10-12"]}


def test_an_answer_too_big_to_be_a_report(server, keys, monkeypatch):
    # A proxy or sign-in page, so the rest would get the same
    monkeypatch.setattr(enrich, "MAX_ANSWER_BYTES", 50)
    server.answers[f"{VT}/domains/first.com"] = (200, vt_report())
    assert texts(look_up(Indicators(domains=["first.com", "second.com"]))) == {
        "first.com": ["VirusTotal: unavailable, its answer was too big to be a report"],
        "second.com": ["VirusTotal: unavailable, its answer was too big to be a report"]}
    assert len(server.requests) == 1


def broken_stats(**stats) -> dict:
    report = vt_report(undetected=70)
    report["data"]["attributes"]["last_analysis_stats"].update(stats)
    return report


@pytest.mark.parametrize("report", [
    [],
    {"data": None},
    {"data": {"attributes": []}},
    {"data": {"attributes": {"last_analysis_stats": [1, 2]}}},
    broken_stats(malicious="5"),
    broken_stats(malicious=-1),
    broken_stats(malicious=10 ** 9),
    # True would pass for 1 with isinstance()
    broken_stats(malicious=True),
    vt_report(undetected=70, checked="yesterday"),
    # Far past the years a date can hold
    vt_report(undetected=70, checked=10 ** 20),
], ids=["list", "no data", "attributes not an object", "stats not an object", "count as text", "negative count",
        "count too big", "true for a count", "date as text", "date too big"])
def test_virustotal_answers_that_cant_be_read(server, keys, report):
    server.answers[f"{VT}/domains/evil.com"] = (200, report)
    assert texts(look_up(Indicators(domains=["evil.com"]))) == {
        "evil.com": ["VirusTotal: unavailable, its answer couldn't be read"]}
    assert not enrich.CACHE_FILE.exists()


@pytest.mark.parametrize("report", [
    {"data": {"abuseConfidenceScore": 50}},
    abuseipdb_report(countryCode=840),
], ids=["counts missing", "country as a number"])
def test_abuseipdb_answer_that_cant_be_read(server, monkeypatch, report):
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "abuseipdb-key")
    server.answers[f"{ABUSEIPDB}?8.8.8.8"] = (200, report)
    assert texts(look_up(Indicators(ips=["8.8.8.8"])))["8.8.8.8"][0] == (
        "AbuseIPDB: unavailable, its answer couldn't be read")


def test_found_results_are_kept_for_a_day(server, keys, clock):
    server.answers[f"{VT}/domains/evil.com"] = (200, vt_report(malicious=3, undetected=60))
    found = Indicators(domains=["evil.com"])
    first = texts(look_up(found))
    clock.now += 24 * 3600 - 1
    assert texts(look_up(found)) == first
    assert len(server.requests) == 1
    clock.now += 1
    look_up(found)
    assert len(server.requests) == 2


def test_a_link_is_saved_by_what_was_sent(server, keys):
    # The same link with another reader's address after # is looked up once
    server.answers[f"{VT}/urls/aHR0cHM6Ly9ldmlsLmNvbS9sb2dpbg"] = (200, vt_report(malicious=4, undetected=60))
    look_up(Indicators(urls=["https://evil.com/login#jordan.lee@example.com"]))
    assert texts(look_up(Indicators(urls=["https://evil.com/login#sam.rivera@example.com"]))) == {
        "https://evil.com/login#sam.rivera@example.com": ["VirusTotal: 4 of 64 engines flagged it malicious, "
                                                         "last checked 2026-10-12"]}
    assert len(server.requests) == 1


def ctrl_c(*args):
    raise KeyboardInterrupt


FIVE_SITES = [f"site{n}.com" for n in range(5)]


def test_ctrl_c_skips_the_lookups_left(server, keys, monkeypatch, clock):
    # Pressed during the wait for VirusTotal's 5th lookup. AbuseIPDB's were made first, nothing
    # more is sent, and the results so far are shown and kept. What isn't sent for privacy
    # still says why.
    for site in FIVE_SITES:
        server.answers[f"{VT}/domains/{site}"] = (200, vt_report(undetected=60))
    server.answers[f"{ABUSEIPDB}?8.8.8.8"] = (200, abuseipdb_report())
    monkeypatch.setattr(clock, "sleep", ctrl_c)
    results = texts(look_up(Indicators(domains=FIVE_SITES, ips=["8.8.8.8", "10.0.0.5"])))
    assert results["site3.com"] == ["VirusTotal: 0 of 60 engines flagged it malicious, last checked 2026-10-12"]
    assert results["site4.com"] == ["VirusTotal: unavailable, stopped with Ctrl+C"]
    assert results["8.8.8.8"] == ["AbuseIPDB: no reports in the last 90 days",
                                  "VirusTotal: unavailable, stopped with Ctrl+C"]
    assert results["10.0.0.5"] == ["AbuseIPDB: skipped, private or reserved address",
                                   "VirusTotal: skipped, private or reserved address"]
    assert len(server.requests) == 5
    assert len(json.loads(enrich.CACHE_FILE.read_text(encoding="utf-8"))["lookups"]) == 5


def test_a_second_ctrl_c_stops_and_keeps_what_was_found(server, keys, monkeypatch, clock):
    # The second comes while the lookups left are being marked, and stops the tool. The first
    # 4 used up the limit, so they're still kept.
    for site in FIVE_SITES:
        server.answers[f"{VT}/domains/{site}"] = (200, vt_report(undetected=60))
    monkeypatch.setattr(clock, "sleep", ctrl_c)
    look_up_one = enrich._look_up_one

    def again_once_stopped(service, *args):
        if service.stopped:
            raise KeyboardInterrupt
        return look_up_one(service, *args)

    monkeypatch.setattr(enrich, "_look_up_one", again_once_stopped)
    with pytest.raises(KeyboardInterrupt):
        look_up(Indicators(domains=FIVE_SITES))
    assert len(json.loads(enrich.CACHE_FILE.read_text(encoding="utf-8"))["lookups"]) == 4


def test_the_cache_isnt_a_list_of_what_you_looked_up(server, keys):
    server.answers[f"{VT}/domains/evil.com"] = (200, vt_report(undetected=60))
    look_up(Indicators(domains=["evil.com"]))
    saved = enrich.CACHE_FILE.read_text(encoding="utf-8")
    assert "evil" not in saved
    assert json.loads(saved)["version"] == enrich.CACHE_VERSION


def saved_entry(**entry) -> str:
    key = enrich._cache_key("VirusTotal", "domain", "evil.com")
    facts = {"malicious": 0, "suspicious": 0, "undetected": 60, "harmless": 0, "checked": "", "registered": ""}
    entry = {"saved": 1_800_000_000.0, "facts": facts, **entry}
    return json.dumps({"version": enrich.CACHE_VERSION, "lookups": {key: entry}})


@pytest.mark.parametrize("contents", [
    "not JSON",
    "[" * 100_000,
    "[]",
    json.dumps({"version": enrich.CACHE_VERSION - 1, "lookups": {}}),
    json.dumps({"version": enrich.CACHE_VERSION, "lookups": []}),
    saved_entry(saved="today"),
    saved_entry(saved=1_800_000_000.0 + 60),
    saved_entry(saved=10 ** 400),
    saved_entry(facts={"malicious": "lots"}),
    # Each as long as Python will print, so the engines they add up to are one digit too long
    saved_entry(facts={**dict.fromkeys(["malicious", "suspicious", "undetected", "harmless"], int("9" * 4300)),
                       "checked": ""}),
], ids=["not JSON", "nested too deep", "a list", "older version", "lookups not an object", "time as text", "future time",
        "time too big", "facts of the wrong type", "counts too long to print"])
def test_a_damaged_cache_is_looked_up_again(server, keys, contents):
    enrich.CACHE_FILE.parent.mkdir(parents=True)
    enrich.CACHE_FILE.write_text(contents, encoding="utf-8")
    server.answers[f"{VT}/domains/evil.com"] = (200, vt_report(malicious=1, undetected=60))
    assert texts(look_up(Indicators(domains=["evil.com"]))) == {
        "evil.com": ["VirusTotal: 1 of 61 engines flagged it malicious, last checked 2026-10-12"]}
    assert len(server.requests) == 1
    # The new result is saved in its place
    saved = json.loads(enrich.CACHE_FILE.read_text(encoding="utf-8"))["lookups"]
    assert [entry["facts"]["malicious"] for entry in saved.values()] == [1]


def test_a_saved_entry_is_used(server, keys):
    enrich.CACHE_FILE.parent.mkdir(parents=True)
    enrich.CACHE_FILE.write_text(saved_entry(), encoding="utf-8")
    assert texts(look_up(Indicators(domains=["evil.com"]))) == {
        "evil.com": ["VirusTotal: 0 of 60 engines flagged it malicious"]}
    assert server.requests == []


def test_a_cache_that_cant_be_written(server, keys, capsys, monkeypatch, tmp_path):
    # A file where the cache folder should be. The results are still shown.
    (tmp_path / "blocked").write_text("")
    monkeypatch.setattr(enrich, "CACHE_FILE", tmp_path / "blocked" / "lookups.json")
    server.answers[f"{VT}/domains/evil.com"] = (200, vt_report(undetected=60))
    assert texts(look_up(Indicators(domains=["evil.com"]))) == {
        "evil.com": ["VirusTotal: 0 of 60 engines flagged it malicious, last checked 2026-10-12"]}
    assert capsys.readouterr().err.startswith("Note: the lookups couldn't be saved for next time (")


@pytest.mark.parametrize("env, folder", [
    ({"LOCALAPPDATA": "C:/Users/someone/AppData/Local"}, Path("C:/Users/someone/AppData/Local")),
    ({"XDG_CACHE_HOME": "/home/someone/.cache"}, Path("/home/someone/.cache")),
    ({}, Path.home() / ".cache"),
], ids=["Windows", "XDG", "neither"])
def test_the_cache_is_in_your_cache_folder(monkeypatch, env, folder):
    for name in ("LOCALAPPDATA", "XDG_CACHE_HOME"):
        monkeypatch.delenv(name, raising=False)
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    assert enrich._cache_file() == folder / "phishing-triage" / "lookups.json"


def test_without_a_home_folder_only_the_cache_is_skipped(server, keys, capsys, monkeypatch):
    # A stripped-down environment can have none, and the cache path is found when the tool starts
    def no_home():
        raise RuntimeError("Could not determine home directory.")

    for name in ("LOCALAPPDATA", "XDG_CACHE_HOME"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(Path, "home", no_home)
    assert enrich._cache_file() is None
    monkeypatch.setattr(enrich, "CACHE_FILE", None)
    server.answers[f"{VT}/domains/evil.com"] = (200, vt_report(undetected=60))
    assert texts(look_up(Indicators(domains=["evil.com"]))) == {
        "evil.com": ["VirusTotal: 0 of 60 engines flagged it malicious, last checked 2026-10-12"]}
    assert capsys.readouterr().err == ("Note: the lookups couldn't be saved for next time (there's no home folder, "
                                       "and XDG_CACHE_HOME isn't set)\n")
