"""CLI entry point. Run with: python -m triage"""

import argparse
import sys

from .parser import parse_file


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="triage",
        description=(
            "Gather evidence for phishing triage: check headers, extract and "
            "defang indicators, optionally look up their reputation, and write "
            "a ticket-ready note. The verdict is left to the analyst."
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

    parser.add_argument("--out", metavar="FILE", help="write the Markdown triage note to FILE")
    parser.add_argument("--json", metavar="FILE", help="write the JSON report to FILE")
    parser.add_argument(
        "--enrich",
        action="store_true",
        help="look up indicator reputation (VirusTotal, AbuseIPDB). Off by default",
    )
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    if args.text:
        print("Text mode isn't built yet.", file=sys.stderr)
        return 1

    try:
        parsed = parse_file(args.eml)
    except (OSError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    # Temporary summary until the report module exists
    sender = parsed.from_addr.email if parsed.from_addr else "(missing)"
    print(f"From:        {sender}")
    print(f"Subject:     {parsed.subject}")
    print(f"Links:       {len(parsed.links)}")
    print(f"Attachments: {len(parsed.attachments)}")
    for a in parsed.attachments:
        print(f"  {a.sha256}  {a.filename} ({a.content_type}, {a.size} bytes)")
    for w in parsed.parse_warnings:
        print(f"Warning:     {w}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
