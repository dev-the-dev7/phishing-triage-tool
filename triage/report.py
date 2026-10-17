"""Builds the report: everything the tool found about one email or one piece of alert text,
sorted, and written out for the terminal."""

import unicodedata
from dataclasses import dataclass, field

from .domains import base_domain
from .enrich import network
from .iocs import defang
from .models import (Address, Attachment, Check, Indicators, LookupStatus, Origin, ParsedEmail, Reputation, Result,
                     Strength, join_first_five)

# Text from an email can be any length (a Subject can be 260 KB), so what's shown is cut
MAX_VALUE_CHARS = 300
# Evidence, warnings and lookup results can hold several values, so they get more room
MAX_LONG_CHARS = 1_000

HASH_NAMES = {32: "MD5", 40: "SHA-1", 64: "SHA-256"}
RESULT_ORDER = [Result.FLAG, Result.INCONCLUSIVE, Result.PASS]
STRENGTH_ORDER = [Strength.STRONG, Strength.MEDIUM, Strength.WEAK]


@dataclass
class EmailFacts:
    from_addr: Address | None
    to: list[Address]
    reply_to: list[Address]
    return_path: Address | None
    subject: str
    date: str
    message_id: str
    links: int
    attachments: list[Attachment]


@dataclass
class IndicatorRow:
    kind: str  # URL, Domain, IP, Email, or the hash's name
    value: str
    results: list[Reputation] = field(default_factory=list)
    named_by: str = ""  # the check that named it, when the email didn't list it


@dataclass
class NotLookedUp:
    # Said once, with how many indicators it covered
    service: str
    text: str
    count: int


@dataclass
class Report:
    email: EmailFacts | None  # None for alert text
    origin: Origin | None
    origin_network: str  # the origin IP's network and country from AbuseIPDB, or ""
    findings: list[Check]  # flags strongest first, then inconclusive, then passes
    indicators: list[IndicatorRow]
    not_looked_up: list[NotLookedUp]
    warnings: list[str]  # about the tool's reading of the email, not the email itself

    @property
    def strongest_flag(self) -> Strength | None:
        flags = [check.strength for check in self.findings if check.result == Result.FLAG]
        return min(flags, key=STRENGTH_ORDER.index) if flags else None


def build_report(parsed: ParsedEmail, origin: Origin | None, checks: list[Check], found: Indicators,
                 results: dict[str, list[Reputation]], warnings: list[str]) -> Report:
    email = EmailFacts(parsed.from_addr, parsed.to, parsed.reply_to, parsed.return_path, parsed.subject, parsed.date,
                       parsed.message_id, len(parsed.links), parsed.attachments)
    # sorted() keeps the checks' own order within a result and strength
    findings = sorted(checks, key=lambda check: (RESULT_ORDER.index(check.result),
                                                 STRENGTH_ORDER.index(check.strength)))
    # IPs a flag names that the email didn't list, like a faked Microsoft hop's, are indicators too
    named = {ip: check.name for check in findings if check.result == Result.FLAG for ip in check.ips
             if ip not in found.ips}
    indicators, not_looked_up = _indicator_rows(found, results, named)
    origin_network = _network(results.get(origin.ip, [])) if origin and origin.ip else ""
    return Report(email, origin, origin_network, findings, indicators, not_looked_up, warnings)


def build_text_report(found: Indicators, results: dict[str, list[Reputation]]) -> Report:
    indicators, not_looked_up = _indicator_rows(found, results, {})
    return Report(None, None, "", [], indicators, not_looked_up, [])


def _indicator_rows(found: Indicators, results: dict[str, list[Reputation]],
                    named: dict[str, str]) -> tuple[list[IndicatorRow], list[NotLookedUp]]:
    rows = ([IndicatorRow("URL", url) for url in found.urls] + [IndicatorRow("Domain", d) for d in found.domains]
            + [IndicatorRow("IP", ip) for ip in found.ips]
            + [IndicatorRow("IP", ip, named_by=check) for ip, check in named.items()]
            + [IndicatorRow("Email", email) for email in found.emails]
            + [IndicatorRow(HASH_NAMES[len(sha)], sha) for sha in found.hashes])
    # Over the limit, no key, or a stopped service would repeat under every indicator
    counts = {}
    for row in rows:
        for result in results.get(row.value, []):
            if result.for_the_run:
                counts[result.service, result.text] = counts.get((result.service, result.text), 0) + 1
            else:
                row.results.append(result)
    return rows, [NotLookedUp(service, text, count) for (service, text), count in counts.items()]


def _network(results: list[Reputation]) -> str:
    for result in results:
        if result.service == "AbuseIPDB" and result.status == LookupStatus.FOUND:
            return network(result.facts)
    return ""


def render_text(report: Report) -> str:
    # Every value from the email or a lookup is cut and escaped, our own words aren't
    title = _shown(report.email.subject or "(no subject)") if report.email else "alert text"
    lines = [f"Phishing triage: {title}", ""]
    if report.email:
        lines += ["Summary", f"  Strongest flag: {report.strongest_flag or 'none'}", f"  {_counts(report)}", "",
                  "Email", *_email_lines(report), "",
                  "Findings", *(line for check in report.findings for line in _check_lines(check)), ""]
    lines += ["Indicators, defanged", *_indicator_lines(report)]
    if report.warnings:
        lines += ["", "Warnings about the tool's reading", *(f"  {_shown(w, MAX_LONG_CHARS)}" for w in report.warnings)]
    return "\n".join(lines) + "\n"


def _counts(report: Report) -> str:
    flags = [check.strength for check in report.findings if check.result == Result.FLAG]
    flagged = ", ".join(f"{flags.count(s)} {s}" for s in STRENGTH_ORDER if s in flags) or "none"
    inconclusive = sum(check.result == Result.INCONCLUSIVE for check in report.findings)
    passed = sum(check.result == Result.PASS for check in report.findings)
    counts = [f"Flagged: {flagged}", f"Inconclusive: {inconclusive}", f"Passed: {passed}",
              f"Indicators: {len(report.indicators)}"]
    if report.warnings:
        counts.append(f"Warnings: {len(report.warnings)}")
    return "   ".join(counts)


def _email_lines(report: Report) -> list[str]:
    email = report.email
    lines = [f"  From:        {_address(email.from_addr) if email.from_addr else '(missing)'}"]
    for label, addresses in (("To:", email.to), ("Reply-To:", email.reply_to),
                             ("Return-Path:", [email.return_path] if email.return_path else [])):
        if addresses:
            lines.append(f"  {label:<12} {join_first_five(list(map(_address, addresses)))}")
    for label, value in (("Date:", email.date), ("Message-ID:", email.message_id)):
        if value:
            lines.append(f"  {label:<12} {_shown(value)}")
    lines += _origin_lines(report)
    lines.append(f"  Links: {email.links}   Attachments: {len(email.attachments)}")
    lines += [f"    {a.sha256}  {_shown(a.filename)} ({_shown(a.content_type)}, {a.size:,} bytes)"
              for a in email.attachments]
    return lines


def _address(address: Address) -> str:
    # Cut apart, so padding in the name can't hide the address
    if not address.display_name:
        return _shown(address.email)
    # Quotes escaped as in the header, after the cut, which could drop a backslash
    name = _cut(address.display_name, MAX_VALUE_CHARS).replace("\\", "\\\\").replace('"', '\\"')
    return f'"{_escape(name)}" <{_shown(address.email)}>'


def _origin_lines(report: Report) -> list[str]:
    origin = report.origin
    if origin is None:
        return ["  Origin:      unknown, no Received headers with an IP"]
    if origin.ip is None:
        return [f"  Origin:      none outside {_shown(base_domain(origin.received_by))}, every hop is inside the "
                "provider"]
    where = f", {_shown(report.origin_network)}" if report.origin_network else ""
    lines = [f"  Origin:      {origin.ip} ({_shown(origin.name)}) handed it to {_shown(origin.received_by)}{where}"]
    if origin.earliest_claim:
        lines.append(f"{'':15}lower hops claim {origin.earliest_claim} (could be forged)")
    return lines


def _check_lines(check: Check) -> list[str]:
    return ([f"  {check.result.upper():<12} {check.strength:<7} {check.name}: {_shown(check.evidence, MAX_LONG_CHARS)}"]
            + [f"{'':23}Caveat: {_shown(caveat, MAX_LONG_CHARS)}" for caveat in check.caveats])


def _indicator_lines(report: Report) -> list[str]:
    lines = [] if report.indicators else ["  none found"]
    # Defanged, so pasting them into a ticket or a chat doesn't make live links
    for row in report.indicators:
        named = f" (from the {row.named_by} check)" if row.named_by else ""
        lines.append(f"  {row.kind:<8} {_shown(defang(row.value), MAX_LONG_CHARS)}{named}")
        lines += [f"{'':11}{result.service}: {_shown(result.text, MAX_LONG_CHARS)}" for result in row.results]
    for missed in report.not_looked_up:
        covered = "1 indicator, the one" if missed.count == 1 else f"{missed.count} indicators, the ones"
        lines.append(f"  {missed.service}: {_shown(missed.text)} ({covered} with no {missed.service} line)")
    return lines


def _shown(text: str, limit: int = MAX_VALUE_CHARS) -> str:
    return _escape(_cut(text, limit))


def _cut(text: str, limit: int) -> str:
    # In the middle, since the end often matters most (the reason at the end of evidence, the
    # domain at the end of an address)
    if len(text) <= limit:
        return text
    half = limit // 2
    return f"{text[:half]} ... ({len(text) - 2 * half:,} characters left out) ... {text[-half:]}"


def _escape(text: str) -> str:
    # Control, invisible and line-breaking characters shown as codes: terminal codes can
    # rewrite lines above, a line separator can start a fake result line, and a right-to-left
    # override shows invoice<RLO>fdp.exe as invoiceexe.pdf
    return "".join(ascii(ch)[1:-1] if unicodedata.category(ch) in ("Cc", "Cf", "Zl", "Zp") else ch for ch in text)
