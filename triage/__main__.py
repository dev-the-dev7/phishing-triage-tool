"""CLI entry point. Run with: python -m triage"""

import argparse
import codecs
import errno
import os
import sys
from datetime import date
from pathlib import Path

from .checks import run_checks
from .checks.lookups import check_domain_age, check_microsoft_hops
from .domains import SUFFIX_LIST_DATE
from .enrich import look_up
from .models import Indicators, Result
from .reading.iocs import from_email, from_text
from .reading.origin import find_origin, received_warnings
from .reading.parser import parse_file
from .report import Report, build_report, build_text_report, render_json, render_markdown, render_summary, render_text

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

    parser.add_argument("--out", metavar="FILE",
                        help="write the Markdown triage note to FILE, for a ticket ('-' prints it instead)")
    parser.add_argument("--json", metavar="FILE",
                        help="write the report as JSON to FILE, for other tools ('-' prints it instead)")
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
    except BrokenPipeError:
        # The program reading the output stopped early (| head). Python would complain again
        # when it flushes at exit, so the rest goes nowhere, as Python's docs suggest.
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        return 1


def _run(args: argparse.Namespace) -> int:
    # Checked before the work, which can take minutes with --enrich
    problem = _output_problem(args)
    if problem:
        print(f"error: {problem}", file=sys.stderr)
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
        return _send(build_text_report(found, results), args)

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
    return _send(build_report(parsed, origin, checks, found, results, warnings), args)


def _output_problem(args: argparse.Namespace) -> str:
    source = args.eml if args.text is None else args.text
    for flag, name in (("--out", args.out), ("--json", args.json)):
        # "is not None" because an empty value (--out "") was still asked for
        if name is not None and not name.strip():
            return f"{flag} needs a file name"
        if name and name != "-":
            if Path(name).is_dir():
                return f"{flag} names a folder"
            # Writing it would replace the email or alert text, which is the evidence
            if source != "-" and _same_file(name, source):
                return f"{flag} names the file being read"
    if args.out == args.json == "-":
        return "only one of --out and --json can be - (standard output)"
    if args.out and args.json and "-" not in (args.out, args.json) and _same_file(args.out, args.json):
        return "--out and --json name the same file"
    return ""


def _same_file(a: str, b: str) -> bool:
    # normcase, since Windows file names ignore case
    return os.path.normcase(Path(a).resolve()) == os.path.normcase(Path(b).resolve())


def _send(report: Report, args: argparse.Namespace) -> int:
    # "-" sends the note or JSON to standard output for a pipe, so the summary goes to stderr
    outputs = [(name, render) for name, render in ((args.out, render_markdown), (args.json, render_json)) if name]
    terminal = sys.stderr if "-" in (args.out, args.json) else sys.stdout
    written = []
    for name, render in outputs:
        if name == "-":
            _print(render(report), sys.stdout)
            continue
        try:
            _write(Path(name), render(report))
        except OSError as e:
            # Printed in full, so a run that waited on lookups isn't lost
            also = f" ({written[0]} was written)" if written else ""
            print(f"error: couldn't write {name}: {e.strerror or e}{also}", file=sys.stderr)
            _print(render_text(report), terminal)
            return 1
        written.append(name)
    _print(render_summary(report, written) if outputs else render_text(report), terminal)
    _note_old_suffix_list()
    return 0


def _print(text: str, stream) -> None:
    # Sent in full now, so a reader that stopped early (| head) is found here and not when
    # Python flushes at exit. Windows says EINVAL when the reader was gone before the write.
    try:
        print(text, end="", file=stream, flush=True)
    except OSError as e:
        if e.errno == errno.EINVAL:
            raise BrokenPipeError(errno.EPIPE, "the program reading the output stopped") from e
        raise


def _write(path: Path, text: str) -> None:
    # Written next to the file and then swapped in, so a failed write doesn't leave half a note.
    # With \n line endings, which Windows would otherwise change.
    new_file = path.with_name(path.name + ".new")
    try:
        with open(new_file, "w", encoding="utf-8", newline="\n") as f:
            f.write(text)
        new_file.replace(path)
    except OSError:
        new_file.unlink(missing_ok=True)
        raise


if __name__ == "__main__":
    sys.exit(main())
