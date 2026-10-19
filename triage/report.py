"""Builds the report: everything the tool found about one email or one piece of alert text,
sorted, and written out for the terminal, as a Markdown triage note, and as JSON. All three
come from the same Report, so they can't disagree."""

import json
import re
import unicodedata
from dataclasses import dataclass, field

from .domains import base_domain
from .enrich import network
from .iocs import defang, defang_text
from .models import (Address, Attachment, Check, Indicators, LookupStatus, Origin, ParsedEmail, Reputation, Result,
                     Strength, join_first_five)
from .patterns import Pattern, find_patterns

# Text from an email can be any length (a Subject can be 260 KB), so what's shown is cut
MAX_VALUE_CHARS = 300
# Evidence, warnings and lookup results can hold several values, so they get more room
MAX_LONG_CHARS = 1_000

HASH_NAMES = {32: "MD5", 40: "SHA-1", 64: "SHA-256"}
RESULT_ORDER = [Result.FLAG, Result.INCONCLUSIVE, Result.PASS]
STRENGTH_ORDER = [Strength.VERY_STRONG, Strength.STRONG, Strength.MEDIUM, Strength.WEAK]

# Suggestions for the analyst, never steps the tool took
FOLLOW_UPS = [
    "Find other recipients of the same message (search by its Message-ID or sender)",
    "Check whether anyone clicked a link (proxy or DNS logs for the indicator domains) or replied",
    "Block the attacker's own sender address and domains, not spoofed or shared ones like a webmail or "
    "link-shortening service",
]
# Changed when a field is renamed, removed, or changes type, so tools reading the JSON can tell
JSON_FORMAT = 2


@dataclass
class EmailFacts:
    from_addrs: list[Address]
    sender: list[Address]
    to: list[Address]
    reply_to: list[Address]
    return_path: list[Address]
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
    patterns: list[Pattern] = field(default_factory=list)

    @property
    def strongest_flag(self) -> Strength | None:
        flags = [check.strength for check in self.findings if check.result == Result.FLAG]
        return min(flags, key=STRENGTH_ORDER.index) if flags else None


def build_report(parsed: ParsedEmail, origin: Origin | None, checks: list[Check], found: Indicators,
                 results: dict[str, list[Reputation]], warnings: list[str]) -> Report:
    email = EmailFacts(parsed.from_addrs, parsed.sender, parsed.to, parsed.reply_to, parsed.return_path, parsed.subject,
                       parsed.date, parsed.message_id, len(parsed.links), parsed.attachments)
    # sorted() keeps the checks' own order within a result and strength
    findings = sorted(checks, key=lambda check: (RESULT_ORDER.index(check.result),
                                                 STRENGTH_ORDER.index(check.strength)))
    # IPs a flag names that the email didn't list, like a faked Microsoft hop's, are indicators too
    named = {ip: check.name for check in findings if check.result == Result.FLAG for ip in check.ips
             if ip not in found.ips}
    indicators, not_looked_up = _indicator_rows(found, results, named)
    origin_network = _network(results.get(origin.ip, [])) if origin and origin.ip else ""
    return Report(email, origin, origin_network, findings, indicators, not_looked_up, warnings,
                  find_patterns(parsed, findings))


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
    lines = [_title(report, _shown), ""]
    if report.email:
        lines += ["Summary", f"  Strongest flag: {report.strongest_flag or 'none'}", f"  {'   '.join(_counts(report))}",
                  ""]
        if report.patterns:
            lines += ["Patterns", *(f"  {p.name} ({'; '.join(p.found)}): {p.why}" for p in report.patterns), ""]
        lines += ["Email", *_email_lines(report), "",
                  "Findings", *(line for check in report.findings for line in _check_lines(check)), ""]
    lines += ["Indicators, defanged", *_indicator_lines(report)]
    if report.warnings:
        lines += ["", "Warnings about the tool's reading", *(f"  {_shown(w, MAX_LONG_CHARS)}" for w in report.warnings)]
    return "\n".join(lines) + "\n"


def render_summary(report: Report, written: list[str]) -> str:
    # For the terminal when the note or JSON was written: what to look at first, and where the files are
    lines = [_title(report, _shown)]
    if report.email:
        lines += [f"Strongest flag: {report.strongest_flag or 'none'}", "   ".join(_counts(report))]
        if report.patterns:
            lines.append(f"Patterns: {'; '.join(p.name for p in report.patterns)}")
    else:
        lines.append(f"Indicators: {len(report.indicators)}")
    lines += [_missed_line(missed) for missed in report.not_looked_up]
    if written:
        lines.append(f"Wrote {' and '.join(map(_shown, written))}")
    return "\n".join(lines) + "\n"


def _title(report: Report, shown) -> str:
    # Our own words outside shown(), so they can't pass for the email's
    if report.email is None:
        return "Phishing triage: alert text"
    return f"Phishing triage: {shown(report.email.subject) if report.email.subject else '(no subject)'}"


def _counts(report: Report) -> list[str]:
    flags = [check.strength for check in report.findings if check.result == Result.FLAG]
    flagged = ", ".join(f"{flags.count(s)} {s}" for s in STRENGTH_ORDER if s in flags) or "none"
    inconclusive = sum(check.result == Result.INCONCLUSIVE for check in report.findings)
    passed = sum(check.result == Result.PASS for check in report.findings)
    counts = [f"Flagged: {flagged}", f"Inconclusive: {inconclusive}", f"Passed: {passed}",
              f"Indicators: {len(report.indicators)}"]
    if report.warnings:
        counts.append(f"Warnings: {len(report.warnings)}")
    return counts


def _email_lines(report: Report) -> list[str]:
    email = report.email
    lines = [] if email.from_addrs else ["  From:        (missing)"]
    for label, addresses in _address_fields(email):
        lines.append(f"  {label + ':':<12} {join_first_five(list(map(_address, addresses)))}")
    for label, value in (("Date", email.date), ("Message-ID", email.message_id)):
        if value:
            lines.append(f"  {label + ':':<12} {_shown(value)}")
    origin, *claim = _origin_parts(report, _shown)
    lines += [f"  Origin:      {origin}", *(f"{'':15}{line}" for line in claim)]
    lines.append(f"  Links: {email.links}   Attachments: {len(email.attachments)}")
    lines += [f"    {a.sha256}  {_file_name(a, _shown)} ({_shown(a.content_type)}, {a.size:,} bytes)"
              for a in email.attachments]
    return lines


def _file_name(attachment: Attachment, shown) -> str:
    return shown(attachment.filename) if attachment.filename else "(no name)"


def _address_fields(email: EmailFacts) -> list[tuple[str, list[Address]]]:
    fields = [("From", email.from_addrs), ("Sender", email.sender), ("To", email.to), ("Reply-To", email.reply_to),
              ("Return-Path", email.return_path)]
    return [(label, addresses) for label, addresses in fields if addresses]


def _address(address: Address) -> str:
    # Cut apart, so padding in the name can't hide the address
    if not address.display_name:
        return _shown(address.email)
    # Quotes escaped as in the header, after the cut, which could drop a backslash
    name = _cut(address.display_name, MAX_VALUE_CHARS).replace("\\", "\\\\").replace('"', '\\"')
    return f'"{_escape(name)}" <{_shown(address.email)}>'


def _origin_parts(report: Report, shown) -> list[str]:
    origin = report.origin
    if origin is None:
        return ["unknown, no Received headers with an IP"]
    if origin.ip is None:
        return [f"none outside {shown(base_domain(origin.received_by))}, every hop is inside the provider"]
    where = f", {shown(report.origin_network)}" if report.origin_network else ""
    parts = [f"{shown(origin.ip)} ({shown(origin.name)}) handed it to {shown(origin.received_by)}{where}"]
    if origin.earliest_claim:
        parts.append(f"lower hops claim {shown(origin.earliest_claim)} (could be forged)")
    return parts


def _check_lines(check: Check) -> list[str]:
    return ([f"  {check.result.upper():<12} {check.strength:<11} {check.name}: "
             f"{_shown(check.evidence, MAX_LONG_CHARS)}"]
            + [f"{'':27}Caveat: {_shown(caveat, MAX_LONG_CHARS)}" for caveat in check.caveats])


def _indicator_lines(report: Report) -> list[str]:
    lines = [] if report.indicators else ["  none found"]
    # Defanged, so pasting them into a ticket or a chat doesn't make live links
    for row in report.indicators:
        named = f" (from the {row.named_by} check)" if row.named_by else ""
        lines.append(f"  {row.kind:<8} {_shown(defang(row.value), MAX_LONG_CHARS)}{named}")
        lines += [f"{'':11}{result.service}: {_shown(result.text, MAX_LONG_CHARS)}" for result in row.results]
    return lines + [f"  {_missed_line(missed)}" for missed in report.not_looked_up]


def _missed_line(missed: NotLookedUp) -> str:
    covered = "1 indicator, the one" if missed.count == 1 else f"{missed.count} indicators, the ones"
    return f"{missed.service}: {_shown(missed.text)} ({covered} with no {missed.service} result)"


def render_markdown(report: Report) -> str:
    # Values from the email or a lookup go in defanged code spans, so they can't make links
    lines = [f"# {_title(report, _md)}", ""]
    if report.email:
        lines += ["## Summary", "", f"Strongest flag: {report.strongest_flag or 'none'}. {'. '.join(_counts(report))}.",
                  "", *_md_email(report), ""]
        if report.patterns:
            lines += ["## Patterns", "", *(f"- **{p.name}** ({'; '.join(p.found)}): {p.why}" for p in report.patterns),
                      ""]
        lines += _md_findings(report)
    lines += ["## Indicators", "", *_md_indicators(report), ""]
    if report.warnings:
        lines += ["## Warnings about the tool's reading", "",
                  *(f"- {_md(warning, MAX_LONG_CHARS)}" for warning in report.warnings), ""]
    if report.email:
        lines += ["## Typical follow-ups if confirmed malicious", "", "Suggestions, not actions taken:", "",
                  *_md_follow_ups(report), ""]
    lines += ["## Analyst decision", "", "- Verdict:", "- Actions taken:"]
    return "\n".join(lines) + "\n"


def _md_email(report: Report) -> list[str]:
    email = report.email
    lines = [] if email.from_addrs else ["- From: (missing)"]
    for label, addresses in _address_fields(email):
        lines.append(f"- {label}: {join_first_five(list(map(_md_address, addresses)))}")
    for label, value in (("Date", email.date), ("Message-ID", email.message_id)):
        if value:
            lines.append(f"- {label}: {_md(value)}")
    lines.append(f"- Origin: {'; '.join(_origin_parts(report, _md))}")
    lines.append(f"- Links: {email.links}. Attachments: {len(email.attachments)}")
    lines += [f"  - {_file_name(a, _md)} ({_md(a.content_type)}, {a.size:,} bytes), SHA-256 {_code(a.sha256)}"
              for a in email.attachments]
    return lines


def _md_address(address: Address) -> str:
    return _code(defang_text(_address(address)))


def _md_findings(report: Report) -> list[str]:
    lines = []
    for heading, result in (("Signals", Result.FLAG), ("Inconclusive", Result.INCONCLUSIVE)):
        body = []
        for check in report.findings:
            if check.result == result:
                body.append(f"- **{check.name}** ({check.strength}): {_md(check.evidence, MAX_LONG_CHARS)}")
                body += [f"  - Caveat: {_md(caveat, MAX_LONG_CHARS)}" for caveat in check.caveats]
        lines += [f"## {heading}", "", *(body or ["None."]), ""]
    passed = [check for check in report.findings if check.result == Result.PASS]
    # Semicolons, since one check's name has commas in it
    lines += ["## Passed", "", "; ".join(check.name for check in passed) or "None.", ""]
    # Caveats are for the analyst whatever the result, so the one-line list doesn't drop them
    caveats = [f"- Caveat on **{check.name}**: {_md(caveat, MAX_LONG_CHARS)}"
               for check in passed for caveat in check.caveats]
    return lines + ([*caveats, ""] if caveats else [])


def _md_indicators(report: Report) -> list[str]:
    if not report.indicators:
        return ["None found."]
    # Without lookups the column would be empty
    looked_up = report.not_looked_up or any(row.results for row in report.indicators)
    lines = ["| Type | Indicator, defanged | Reputation |" if looked_up else "| Type | Indicator, defanged |",
             "|---|---|---|" if looked_up else "|---|---|"]
    for row in report.indicators:
        named = f" (from the {row.named_by} check)" if row.named_by else ""
        cells = [row.kind, _md(defang(row.value), MAX_LONG_CHARS) + named]
        if looked_up:
            cells.append("; ".join(f"{r.service}: {_md(r.text, MAX_LONG_CHARS)}" for r in row.results))
        # A pipe ends a table cell even inside a code span, unless it's escaped
        lines.append(f"| {' | '.join(cell.replace('|', chr(92) + '|') for cell in cells)} |")
    if report.not_looked_up:
        lines += ["", *(f"- Not looked up: {_missed_line(missed)}" for missed in report.not_looked_up)]
    return lines


def _md_follow_ups(report: Report) -> list[str]:
    find, *rest = FOLLOW_UPS
    lines = [f"- {find}"]
    if report.email.message_id:
        lines.append(f"  - Message-ID: {_md(report.email.message_id)}")
    for label, addresses in (("From", report.email.from_addrs), ("Sender", report.email.sender)):
        if addresses:
            lines.append(f"  - {label}: {join_first_five([_md(a.email) for a in addresses])}")
    return lines + [f"- {suggestion}" for suggestion in rest]


def _md(text: str, limit: int = MAX_VALUE_CHARS) -> str:
    return _code(defang_text(_shown(text, limit)))


def _code(text: str) -> str:
    # The fence is longer than any run of backticks in the text, so none can close it early, and
    # text that starts or ends with one is padded, since Markdown takes a space off each end
    fence = "`" * (max(map(len, re.findall("`+", text)), default=0) + 1)
    pad = " " if text[:1] in "` " or text[-1:] in "` " else ""
    return f"{fence}{pad}{text}{pad}{fence}"


def render_json(report: Report) -> str:
    # Not cut or escaped like the note: a tool that blocks or searches needs the exact URL,
    # and json.dumps writes anything outside ASCII as an escape code
    email = report.email
    data = {
        "format": JSON_FORMAT,
        "email": None if email is None else {
            "from": list(map(_json_address, email.from_addrs)), "sender": list(map(_json_address, email.sender)),
            "to": list(map(_json_address, email.to)),
            "reply_to": list(map(_json_address, email.reply_to)),
            "return_path": list(map(_json_address, email.return_path)),
            "subject": email.subject, "date": email.date, "message_id": email.message_id, "link_count": email.links,
            "attachments": [{"filename": a.filename, "content_type": a.content_type, "size": a.size,
                             "sha256": a.sha256} for a in email.attachments],
        },
        "origin": None if report.origin is None else {
            "ip": report.origin.ip, "name": report.origin.name, "received_by": report.origin.received_by,
            "earliest_claim": report.origin.earliest_claim, "network": report.origin_network or None,
        },
        "summary": {
            "strongest_flag": report.strongest_flag,
            "flagged": {s: sum(c.result == Result.FLAG and c.strength == s for c in report.findings)
                        for s in STRENGTH_ORDER},
            "inconclusive": sum(c.result == Result.INCONCLUSIVE for c in report.findings),
            "passed": sum(c.result == Result.PASS for c in report.findings),
            "indicators": len(report.indicators), "warnings": len(report.warnings),
        },
        "patterns": [{"name": p.name, "found": p.found, "why": p.why} for p in report.patterns],
        "checks": [{"name": c.name, "result": c.result, "strength": c.strength, "evidence": c.evidence,
                    "caveats": c.caveats} for c in report.findings],
        "indicators": [{"type": row.kind, "value": row.value, "defanged": defang(row.value),
                        "named_by": row.named_by or None,
                        "lookups": [{"service": r.service, "status": r.status, "text": r.text, "facts": r.facts}
                                    for r in row.results]} for row in report.indicators],
        "not_looked_up": [{"service": m.service, "text": m.text, "count": m.count} for m in report.not_looked_up],
        "warnings": report.warnings,
        "follow_ups": FOLLOW_UPS if email else [],
        "analyst": {"verdict": None, "actions_taken": None},
    }
    return json.dumps(data, indent=2) + "\n"


def _json_address(address: Address) -> dict:
    return {"name": address.display_name, "address": address.email}


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
