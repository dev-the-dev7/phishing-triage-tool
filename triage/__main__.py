"""CLI entry point. Run with: python -m triage"""

import argparse
import codecs
import sys
from datetime import date

from .checks import run_checks
from .domains import SUFFIX_LIST_DATE
from .enrich import check_domain_age, check_microsoft_hops, look_up
from .iocs import from_email, from_text
from .models import Indicators, Result
from .parser import parse_file
from .received import find_origin, received_warnings
from .report import build_report, build_text_report, render_text

# Alert text is short. This stops a log file passed by mistake from filling memory.
MAX_TEXT_BYTES = 10 * 1024 * 1024

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


def _say_looking_up(found: Indicators) -> None:
    # On stderr, since the report waits for the lookups and they can take a minute or two
    count = len(found.urls) + len(found.domains) + len(found.ips) + len(found.hashes)
    if count:
        print(f"Looking up {count} {'indicator' if count == 1 else 'indicators'}...", file=sys.stderr)


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
        results = {}
        if args.enrich:
            _say_looking_up(found)
            results = look_up(found)
        print(render_text(build_text_report(found, results)), end="")
        _note_old_suffix_list()
        return 0

    try:
        parsed = parse_file(args.eml)
    except (OSError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    origin = find_origin(parsed)
    checks = run_checks(parsed)
    found = from_email(parsed, origin)
    results = {}
    if args.enrich:
        _say_looking_up(found)
        # Lookalike domains are looked up first, and these checks need the lookups' results
        flagged = [domain for check in checks if check.result == Result.FLAG for domain in check.domains]
        results = look_up(found, parsed.attachments, flagged, origin)
        checks += [check_domain_age(found, results), check_microsoft_hops(origin, results)]
    warnings = parsed.parse_warnings + received_warnings(parsed)
    print(render_text(build_report(parsed, origin, checks, found, results, warnings)), end="")
    _note_old_suffix_list()
    return 0


if __name__ == "__main__":
    sys.exit(main())
