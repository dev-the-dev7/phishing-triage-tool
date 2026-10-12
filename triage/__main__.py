"""CLI entry point. Run with: python -m triage"""

import argparse
import sys
import unicodedata

from .checks import run_checks
from .domains import base_domain
from .parser import parse_file
from .received import find_origin, received_warnings


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="triage",
        description=(
            "Gather evidence for phishing triage from a reported email: check the "
            "sender headers, lookalike domains, and links, and find the server it "
            "came from. The verdict is left to the analyst."
        ),
    )

    # Input: either an .eml file or plain alert text, never both
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("eml", nargs="?", help="path to a reported email (.eml)")
    source.add_argument(
        "--text",
        metavar="FILE",
        help="extract indicators from a text file instead of an email ('-' reads standard input). Not built yet",
    )

    parser.add_argument("--out", metavar="FILE", help="write the Markdown triage note to FILE. Not built yet")
    parser.add_argument("--json", metavar="FILE", help="write the JSON report to FILE. Not built yet")
    parser.add_argument(
        "--enrich",
        action="store_true",
        help="look up indicator reputation (VirusTotal, AbuseIPDB). Off by default. Not built yet",
    )
    return parser


def _print_escaped(text: str) -> None:
    # Email text can hold terminal control codes (ESC sequences that move the cursor and
    # overwrite earlier lines) and invisible formatting characters (a right-to-left override
    # shows invoice<RLO>fdp.exe as invoiceexe.pdf). They're printed as visible codes instead.
    shown = (ascii(ch)[1:-1] if unicodedata.category(ch) in ("Cc", "Cf") else ch for ch in text)
    print("".join(shown))


def main(argv=None) -> int:
    # Spam is full of emoji, and Windows uses an old encoding when output is redirected to a file
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")

    args = build_parser().parse_args(argv)
    # Only the .eml summary is built so far. Stop instead of quietly skipping what was asked for.
    # "is not None" because an empty value (--text "") was still asked for.
    asked = {"--text": args.text is not None, "--out": args.out is not None,
             "--json": args.json is not None, "--enrich": args.enrich}
    not_built = [flag for flag, given in asked.items() if given]
    if not_built:
        print(f"error: not built yet: {', '.join(not_built)}", file=sys.stderr)
        return 1

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
    for c in run_checks(parsed):
        _print_escaped(f"  {c.result.upper():<12} {c.strength:<7} {c.name}: {c.evidence}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
