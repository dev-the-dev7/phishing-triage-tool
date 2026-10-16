"""CLI entry point. Run with: python -m triage"""

import argparse
import codecs
import sys
import unicodedata
from datetime import date

from .checks import run_checks
from .domains import SUFFIX_LIST_DATE, base_domain
from .enrich import check_domain_age, check_microsoft_hops, look_up
from .iocs import defang, from_email, from_text
from .models import Check, Indicators, Reputation, Result
from .parser import parse_file
from .received import find_origin, received_warnings

# Alert text is short. This stops a log file passed by mistake from filling memory.
MAX_TEXT_BYTES = 10 * 1024 * 1024

HASH_NAMES = {32: "MD5", 40: "SHA-1", 64: "SHA-256"}

# The Public Suffix List copy only changes when it's updated by hand, so the tool says when
# it's older than this
OLD_SUFFIX_LIST_DAYS = 183


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="triage",
        description=(
            "Gather evidence for phishing triage from a reported email: check the "
            "sender headers, lookalike domains, and links, find the server it came "
            "from, and list its indicators. The verdict is left to the analyst."
        ),
    )

    # Input: either an .eml file or plain alert text, never both
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("eml", nargs="?", help="path to a reported email (.eml)")
    source.add_argument(
        "--text",
        metavar="FILE",
        help="extract indicators from a text file instead of an email ('-' reads standard input)",
    )

    parser.add_argument("--out", metavar="FILE", help="write the Markdown triage note to FILE. Not built yet")
    parser.add_argument("--json", metavar="FILE", help="write the JSON report to FILE. Not built yet")
    parser.add_argument(
        "--enrich",
        action="store_true",
        help="look up the indicators' reputation with VirusTotal and AbuseIPDB, using the keys in "
             "VT_API_KEY and ABUSEIPDB_API_KEY. Off by default, so nothing goes online without it",
    )
    return parser


def _print_escaped(text: str) -> None:
    # Terminal escape codes and invisible characters are printed as visible codes, since a
    # right-to-left override shows invoice<RLO>fdp.exe as invoiceexe.pdf
    shown = (ascii(ch)[1:-1] if unicodedata.category(ch) in ("Cc", "Cf") else ch for ch in text)
    print("".join(shown))


def _read_text(name: str) -> str:
    # One byte past the limit shows it's too big
    if name == "-":
        data = sys.stdin.buffer.read(MAX_TEXT_BYTES + 1)
    else:
        with open(name, "rb") as f:
            data = f.read(MAX_TEXT_BYTES + 1)
    if len(data) > MAX_TEXT_BYTES:
        raise ValueError(f"text is over {MAX_TEXT_BYTES // (1024 * 1024)} MB, too big to be alert text")
    # PowerShell 5 and Notepad can save text as UTF-16, which starts with a byte order mark.
    # Anything else is read as UTF-8, with bytes that aren't valid UTF-8 replaced.
    if data.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
        return data.decode("utf-16", errors="replace")
    return data.decode("utf-8-sig", errors="replace")


def _print_indicators(found: Indicators, reputation: dict[str, list[Reputation]]) -> None:
    # Defanged, so pasting them into a ticket or a chat doesn't make live links
    rows = ([("URL", url) for url in found.urls] + [("Domain", domain) for domain in found.domains]
            + [("IP", ip) for ip in found.ips] + [("Email", email) for email in found.emails]
            + [(HASH_NAMES[len(sha)], sha) for sha in found.hashes])
    if not rows:
        print("Indicators:  none found")
        return
    print("Indicators, defanged:")
    for kind, value in rows:
        _print_escaped(f"  {kind:<8} {defang(value)}")
        for result in reputation.get(value, []):
            _print_escaped(f"{'':<11}{result.service}: {result.text}")


def _print_check(check: Check) -> None:
    _print_escaped(f"  {check.result.upper():<12} {check.strength:<7} {check.name}: {check.evidence}")
    for caveat in check.caveats:
        _print_escaped(f"{'':<23}Caveat: {caveat}")


def _note_old_suffix_list() -> None:
    # About the tool's copy, not the email, so it goes to stderr and stays out of the results
    if SUFFIX_LIST_DATE and (date.today() - SUFFIX_LIST_DATE).days > OLD_SUFFIX_LIST_DAYS:
        print(f"Note: the Public Suffix List copy is from {SUFFIX_LIST_DATE}, over 6 months old, so endings "
              "added since aren't known. Update it with: python -m triage.update_suffixes", file=sys.stderr)


def main(argv=None) -> int:
    # Spam is full of emoji, and Windows uses an old encoding when output is redirected to a file
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")

    args = build_parser().parse_args(argv)
    try:
        return _run(args)
    except KeyboardInterrupt:
        # A second Ctrl+C during the lookups, or any other. 130 is the usual exit code for it.
        print("Stopped", file=sys.stderr)
        return 130


def _run(args: argparse.Namespace) -> int:
    # Stop instead of quietly skipping what was asked for. "is not None" because an empty
    # value (--out "") was still asked for.
    asked = {"--out": args.out is not None, "--json": args.json is not None}
    not_built = [flag for flag, given in asked.items() if given]
    if not_built:
        print(f"error: not built yet: {', '.join(not_built)}", file=sys.stderr)
        return 1

    if args.text is not None:
        try:
            text = _read_text(args.text)
        except (OSError, ValueError) as e:
            print(f"error: {e}", file=sys.stderr)
            return 1
        found = from_text(text)
        _print_indicators(found, look_up(found) if args.enrich else {})
        _note_old_suffix_list()
        return 0

    try:
        parsed = parse_file(args.eml)
    except (OSError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    # Temporary summary until the report module exists
    sender = parsed.from_addr.email if parsed.from_addr else "(missing)"
    _print_escaped(f"From:        {sender}")
    _print_escaped(f"Subject:     {parsed.subject}")
    _print_escaped(f"Links:       {len(parsed.links)}")
    _print_escaped(f"Attachments: {len(parsed.attachments)}")
    for a in parsed.attachments:
        _print_escaped(f"  {a.sha256}  {a.filename} ({a.content_type}, {a.size} bytes)")
    origin = find_origin(parsed)
    if origin is None:
        _print_escaped("Origin:      unknown, no Received headers with an IP")
    elif origin.ip is None:
        _print_escaped(f"Origin:      none outside {base_domain(origin.received_by)}, every hop is inside the provider")
    else:
        claim = f", lower hops claim {origin.earliest_claim} (could be forged)" if origin.earliest_claim else ""
        _print_escaped(f"Origin:      {origin.ip} ({origin.name}) handed it to {origin.received_by}{claim}")
    for w in parsed.parse_warnings + received_warnings(parsed):
        _print_escaped(f"Warning:     {w}")

    print()
    checks = run_checks(parsed)
    for check in checks:
        _print_check(check)
    print()
    found = from_email(parsed, origin)
    if args.enrich:
        # Lookalike domains are looked up first, and these checks need the lookups' results
        flagged = [domain for check in checks if check.result == Result.FLAG for domain in check.domains]
        results = look_up(found, parsed.attachments, flagged, origin)
        _print_indicators(found, results)
        print()
        _print_check(check_domain_age(found, results))
        _print_check(check_microsoft_hops(origin, results))
    else:
        _print_indicators(found, {})
    _note_old_suffix_list()
    return 0


if __name__ == "__main__":
    sys.exit(main())
