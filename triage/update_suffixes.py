"""Downloads a newer copy of the Public Suffix List. Run with: python -m triage.update_suffixes"""

import sys

import requests

from .domains import PUBLIC_SUFFIX_FILE, list_date

# The tool never updates its copy by itself, so it doesn't go online without being asked.
# This is run by hand, and the new copy shows in git diff before you commit it.

# The only address the list says to download it from
LIST_URL = "https://publicsuffix.org/list/public_suffix_list.dat"
# The list is about 330 KB. This stops a server sending something far bigger from filling memory.
MAX_LIST_BYTES = 5 * 1024 * 1024
# Seconds to wait to connect or for more data, not for the whole download
TIMEOUT = 30
# A whole list has both sections, in this order. A download that was cut short, or a block
# page from a company's web proxy, doesn't.
MARKERS = ["// ===BEGIN ICANN DOMAINS===", "// ===END ICANN DOMAINS===",
           "// ===BEGIN PRIVATE DOMAINS===", "// ===END PRIVATE DOMAINS==="]


def download() -> bytes:
    with requests.get(LIST_URL, timeout=TIMEOUT, stream=True) as response:
        response.raise_for_status()
        data = b""
        for chunk in response.iter_content(64 * 1024):
            data += chunk
            if len(data) > MAX_LIST_BYTES:
                raise ValueError(f"it's over {MAX_LIST_BYTES // (1024 * 1024)} MB, too big to be the list")
    return data


def find_problem(data: bytes) -> str | None:
    # Why the download can't be used as the list, or None when it can
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return "it isn't UTF-8 text, which the list is"
    positions = [text.find(marker) for marker in MARKERS]
    if -1 in positions or positions != sorted(positions):
        return "a section's start or end is missing or out of place, so it was cut short or isn't the list"
    if list_date(text) is None:
        return "it has no VERSION line saying when it was published"
    return None


def main() -> int:
    try:
        new = download()
    except (requests.RequestException, ValueError) as e:
        print(f"error: couldn't download the list: {e}", file=sys.stderr)
        return 1
    problem = find_problem(new)
    if problem:
        print(f"error: the download wasn't saved: {problem}", file=sys.stderr)
        return 1

    old = PUBLIC_SUFFIX_FILE.read_bytes()
    old_date, new_date = list_date(old.decode("utf-8", errors="replace")), list_date(new.decode("utf-8"))
    # Compared line by line, since Git for Windows can check the copy out with \r\n line endings
    if new.splitlines() == old.splitlines():
        print(f"No change: the copy is already the newest list, from {new_date}")
        return 0
    # A list older than the copy could come from an out-of-date cache. Saving it would take
    # back endings the copy already has.
    if old_date and new_date < old_date:
        print(f"error: the download wasn't saved: it's from {new_date}, older than the copy from {old_date}",
              file=sys.stderr)
        return 1

    # Written next to the copy and then swapped in, so a failed write leaves the copy whole.
    # As bytes, so Windows doesn't change the line endings.
    written = PUBLIC_SUFFIX_FILE.with_name(PUBLIC_SUFFIX_FILE.name + ".new")
    written.write_bytes(new)
    written.replace(PUBLIC_SUFFIX_FILE)
    was = f"from {old_date}" if old_date else "undated"
    print(f"Updated the Public Suffix List to the one from {new_date} (the copy was {was}).")
    print("Look over the change with git diff and run the tests before committing it.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
