"""Tests for updating the Public Suffix List (triage/update_suffixes.py). The download is
mocked, and the copy is one in a temporary folder, so the real one is never changed."""

import runpy
import sys
from unittest import mock

import pytest
import requests

from triage import update_suffixes
from triage.domains import PUBLIC_SUFFIX_FILE


def suffix_list(version: str, rules: str = "com\nco.uk\n") -> bytes:
    return (f"// VERSION: {version}\n\n// ===BEGIN ICANN DOMAINS===\n{rules}// ===END ICANN DOMAINS===\n\n"
            "// ===BEGIN PRIVATE DOMAINS===\ngithub.io\n// ===END PRIVATE DOMAINS===\n").encode()


OLD = suffix_list("2026-10-07_07-28-19_UTC")
NEW = suffix_list("2026-11-02_07-30-00_UTC", "com\nco.uk\nnew-ending\n")
VERSION, ICANN, PRIVATE = NEW.split(b"\n\n")


@pytest.fixture
def copy(tmp_path, monkeypatch):
    path = tmp_path / "public_suffix_list.dat"
    path.write_bytes(OLD)
    monkeypatch.setattr(update_suffixes, "PUBLIC_SUFFIX_FILE", path)
    return path


def serve(monkeypatch, *chunks: bytes) -> mock.Mock:
    response = mock.MagicMock()
    response.__enter__.return_value = response
    response.iter_content.return_value = list(chunks)
    get = mock.Mock(return_value=response)
    monkeypatch.setattr(requests, "get", get)
    return get


def run(capsys) -> tuple[int, str, str]:
    code = update_suffixes.main()
    out, err = capsys.readouterr()
    return code, out, err


def test_a_newer_list_replaces_the_copy(capsys, monkeypatch, copy):
    get = serve(monkeypatch, NEW[:100], NEW[100:])
    code, out, _ = run(capsys)
    assert code == 0
    get.assert_called_once_with("https://publicsuffix.org/list/public_suffix_list.dat", timeout=30, stream=True)
    assert copy.read_bytes() == NEW
    assert [path.name for path in copy.parent.iterdir()] == ["public_suffix_list.dat"]
    assert out.startswith("Updated the Public Suffix List to the one from 2026-11-02 (the copy was from 2026-10-07).\n")


@pytest.mark.parametrize("line_end", [b"\n", b"\r\n"], ids=["LF", "CRLF"])
def test_the_same_list_changes_nothing(capsys, monkeypatch, copy, line_end):
    # Git for Windows can check the copy out with \r\n line endings, and it's still the same list
    copy.write_bytes(OLD.replace(b"\n", line_end))
    serve(monkeypatch, OLD)
    code, out, _ = run(capsys)
    assert code == 0
    assert out == "No change: the copy is already the newest list, from 2026-10-07\n"


def test_an_older_list_isnt_saved(capsys, monkeypatch, copy):
    # It would take back endings the copy already has
    serve(monkeypatch, suffix_list("2026-09-01_07-00-00_UTC"))
    code, _, err = run(capsys)
    assert code == 1
    assert copy.read_bytes() == OLD
    assert err == ("error: the download wasn't saved: it's from 2026-09-01, older than the copy from "
                   "2026-10-07\n")


def test_a_copy_without_a_date_is_replaced(capsys, monkeypatch, copy):
    copy.write_bytes(b"com\n")
    serve(monkeypatch, NEW)
    code, out, _ = run(capsys)
    assert code == 0
    assert copy.read_bytes() == NEW
    assert "(the copy was undated)" in out


@pytest.mark.parametrize("download, problem", [
    (NEW[:-40], "a section's start or end is missing or out of place"),
    (NEW.replace(b"// ===END ICANN DOMAINS===\n", b""), "a section's start or end is missing or out of place"),
    (b"\n\n".join([VERSION, PRIVATE, ICANN]), "a section's start or end is missing or out of place"),
    (b"<html><body>Blocked by your company's web proxy</body></html>",
     "a section's start or end is missing or out of place"),
    (NEW + b"\xff", "it isn't UTF-8 text"),
    (b"\n\n".join([ICANN, PRIVATE]), "it has no VERSION line"),
], ids=["cut short", "a section without its end", "sections out of order", "block page", "not UTF-8",
        "no VERSION line"])
def test_a_download_that_isnt_the_whole_list_isnt_saved(capsys, monkeypatch, copy, download, problem):
    serve(monkeypatch, download)
    code, _, err = run(capsys)
    assert code == 1
    assert copy.read_bytes() == OLD
    assert err.startswith(f"error: the download wasn't saved: {problem}")


def test_a_download_too_big_to_be_the_list_stops(capsys, monkeypatch, copy):
    monkeypatch.setattr(update_suffixes, "MAX_LIST_BYTES", 10)
    serve(monkeypatch, b"x" * 6, b"x" * 6, b"never read")
    code, _, err = run(capsys)
    assert code == 1
    assert copy.read_bytes() == OLD
    assert err.startswith("error: couldn't download the list: it's over ")
    assert err.endswith(" MB, too big to be the list\n")


@pytest.mark.parametrize("failure", [requests.ConnectionError("no route"), requests.Timeout("timed out")])
def test_a_failed_download_leaves_the_copy(capsys, monkeypatch, copy, failure):
    monkeypatch.setattr(requests, "get", mock.Mock(side_effect=failure))
    code, _, err = run(capsys)
    assert code == 1
    assert copy.read_bytes() == OLD
    assert err.startswith("error: couldn't download the list: ")


def test_an_error_from_the_server_leaves_the_copy(capsys, monkeypatch, copy):
    get = serve(monkeypatch, NEW)
    get.return_value.raise_for_status.side_effect = requests.HTTPError("404 Client Error: Not Found")
    code, _, err = run(capsys)
    assert code == 1
    assert copy.read_bytes() == OLD
    assert err == "error: couldn't download the list: 404 Client Error: Not Found\n"


def test_the_copy_passes_the_checks_a_download_has_to():
    assert update_suffixes.find_problem(PUBLIC_SUFFIX_FILE.read_bytes()) is None


def test_runs_with_python_m(capsys, monkeypatch):
    # The command the README gives. runpy runs it fresh, the way python -m does, so it's taken
    # out of sys.modules first. The download fails, so the real copy isn't touched.
    monkeypatch.setattr(requests, "get", mock.Mock(side_effect=requests.ConnectionError("no route")))
    monkeypatch.delitem(sys.modules, "triage.update_suffixes")
    with pytest.raises(SystemExit) as exit_info:
        runpy.run_module("triage.update_suffixes", run_name="__main__")
    assert exit_info.value.code == 1
    assert capsys.readouterr().err == "error: couldn't download the list: no route\n"


def test_the_tests_cant_go_online():
    # conftest.py makes every connection fail, so a test that forgets to mock one can't send it
    with pytest.raises(requests.ConnectionError):
        requests.get("https://publicsuffix.org/", timeout=5)
