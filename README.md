# Phishing Triage Tool

[![Tests](https://github.com/dev-the-dev7/phishing-triage-tool/actions/workflows/tests.yml/badge.svg)](https://github.com/dev-the-dev7/phishing-triage-tool/actions/workflows/tests.yml)
![Python 3.14+](https://img.shields.io/badge/python-3.14%2B-blue)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

A Python CLI for Tier 1 phishing triage. It gathers the evidence an analyst would collect
by hand for a reported email (sender authentication, lookalike domains, where links really
go, and indicator reputation) and writes a note ready to paste into the ticket. The
analyst makes the call.

## Sample output

The findings from the note for `tests/fixtures/suspicious.eml`, a made-up phishing email.
Values from the email are defanged and kept in code spans, so none of them can become a
link. Around them, the note has a summary with the email's headers and origin, the
indicators, follow-ups picked from what was found, and space for the analyst's decision.
The full note is in [samples/suspicious.md](samples/suspicious.md), and the same report as
JSON in [samples/suspicious.json](samples/suspicious.json).

```markdown
## Signals

- **DMARC** (strong): `dmarc=fail for paypa1[.]com (from mx[.]example[.]net, ignored 1 untrusted header(s))`
- **Reply-To mismatch** (strong): `Replies go to account-resolution[.]example, not paypa1[.]com`
- **Lookalike domain** (strong): `paypa1[.]com [link, sender] spells 'paypal' with lookalike characters but isn't paypal[.]com`
- **Link mismatch** (strong): `text shows www[.]paypal[.]com but goes to paypa1[.]com`
- **Display name mismatch** (medium): `"PayPal Security" mentions "paypal" but the mail is from paypa1[.]com`

## Inconclusive

- **DKIM** (medium): `dkim=none (from mx[.]example[.]net, ignored 1 untrusted header(s))`

## Passed

SPF; Script, file or app link; Return-Path mismatch; Free webmail sender; Brand joined to a word
```

## What it checks

- **The sender:** SPF, DKIM, and DMARC from your provider's Authentication-Results, a From
  that mail clients can read more than one way, a Reply-To, Return-Path, or display name
  that doesn't match the sender, and free webmail
- **Lookalikes:** lookalike domains and brands joined to other words, in the sender and in
  links, with short brand names like Apple checked against an English word list so
  ordinary words aren't flagged
- **Links and content:** link text that shows one domain but goes to another, links that
  run a script or open a file share or another program, links rewritten by Safe Links,
  Proofpoint, or Google's redirect read as where they really go, text hidden inside
  words, emails that are only an image, and text added by CSS
- **Origin and indicators:** the server that handed the email to your provider, and the
  URLs, domains, IPs, email addresses, and file hashes, defanged, from an email or from
  alert text
- **Reputation, with `--enrich`:** VirusTotal and AbuseIPDB lookups, each IP's network and
  country, domains registered in the last 30 days, and hops faked as Microsoft's servers

Findings that mean more together, like a lookalike domain that passes DMARC, are named as
patterns. Every check ends as flag, pass, or inconclusive, with a fixed strength.

## Quick start

The tool needs Python 3.14 or newer, and is tested with 3.14 and 3.15 on Windows and
Linux. On an older version it stops with an error, since an older Python can read an email
differently, and a check can then pass when it shouldn't. It runs from the repository's
folder, without being installed as a package. In PowerShell:

```powershell
git clone https://github.com/dev-the-dev7/phishing-triage-tool
cd phishing-triage-tool
# 3.14, or a newer version
py -3.14 -m venv .venv
# If PowerShell won't run scripts, allow them for this window only:
# Set-ExecutionPolicy -Scope Process RemoteSigned
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt

# The made-up email the tests use
python -m triage tests/fixtures/suspicious.eml
```

On Linux, create the environment with `python3.14 -m venv .venv`, or the newer version you
have, and activate it with `source .venv/bin/activate`. Each package in `requirements.txt`
is pinned to one version, so a new release isn't picked up without anyone looking at it.

## Usage

```powershell
# Real emails and alert text, and anything made from them, stay in data\, which git
# ignores, since they hold personal data
python -m triage data\reported.eml --out data\note.md --json data\report.json --enrich
python -m triage --text data\alert.txt --enrich

# The note on the clipboard, ready to paste. Windows PowerShell reads a program's output in
# the console's old code page, which garbles letters like Cyrillic lookalikes, so set UTF-8
# first.
[Console]::OutputEncoding = [Text.Encoding]::UTF8
python -m triage data\reported.eml --out - | Set-Clipboard
```

- `--out` writes the Markdown note and `--json` the same report as JSON. With either, the
  terminal shows a short summary. `-` prints one instead of writing a file, for a pipe,
  and the summary goes to stderr.
- `--text` lists the indicators in alert text, and `-` reads it from standard input.
- `--enrich` looks the indicators up. It reads the API keys from `VT_API_KEY` and
  `ABUSEIPDB_API_KEY`, set up as in [docs/CONFIGURATION.md](docs/CONFIGURATION.md).
- `python -m triage.update_suffixes` updates the tool's copy of the Public Suffix List.

Your domains, executives, brands, and lookup limits are in `triage/settings.py`. The part
about your organization ships empty, so its checks do nothing until you fill it in, and
the limits are set for the free keys. What each part is for is in
[docs/CONFIGURATION.md](docs/CONFIGURATION.md), and each setting is explained where it's
set.

## Key design decisions

- **No phishing score or verdict.** The checks overlap, so adding them up counts one fact
  several times. The tool lists what it found, and the analyst decides.
- **Only the topmost Authentication-Results header is trusted.** Your provider adds it on
  top. One lower down was already in the message, so the sender could have faked a pass.
- **Nothing in the email is opened, and nothing is uploaded.** HTML is read as text, never
  rendered, and attachments are hashed in memory. `--enrich` only asks for reports the
  services already have.
- **Not found means unknown, not clean.** A phishing domain registered yesterday has no
  history.
- **Lookalikes are matched word by word, not by a similarity percentage.** So the same
  typo on another TLD or in a subdomain is still caught, and "one typo" is easier to
  defend than a threshold picked by testing.
- **Text from the email can't change how the report looks.** Control, invisible, and
  line-breaking characters are shown as codes, so a right-to-left override can't disguise
  a filename, and a newline in the Subject can't add a fake result line.

The reasons behind these and the rest are in [docs/DESIGN.md](docs/DESIGN.md).

## Limitations

- **Reputation lags behind new phishing.** A domain registered this morning is usually not
  found or clean, so a clean result is no reason to close a report.
- **Phishing sent through a real platform passes the sender checks**, like a Facebook page
  named "Meta Support". The evidence there is where the links end up.
- **A real signed email resent by someone else (DKIM replay) still passes DKIM and
  DMARC**, since the signature is genuine.
- **Rules in a `<style>` block aren't read.** Text they hide isn't flagged, and where they
  could change a link's text, the link check is inconclusive instead of a pass.
- **VirusTotal's free key is for personal use**, and with it a run makes at most 8
  VirusTotal lookups, showing the rest as skipped. Triage at work needs your
  organization's paid key.

The full list is in [docs/LIMITATIONS.md](docs/LIMITATIONS.md).

## Future work

- An optional `--render` that shows the HTML in a headless browser with scripts off, in a
  container with no network, so what CSS hides or adds becomes evidence instead of
  inconclusive
- Links inside attachments, like a PDF's, read in the same kind of container
- Feeding the JSON to a ticket system or SOAR playbook
- Lookups in parallel, for paid keys that allow hundreds a run

The rest is at the end of [docs/DESIGN.md](docs/DESIGN.md).

## Running the tests

From the repository's folder, with the environment active:

```powershell
# What the tool needs, plus pytest and coverage
python -m pip install -r requirements-dev.txt
# Every test but the slow ones, in about 20 seconds
python -m pytest
# The timing sweep and a long run on damaged emails, in a minute or two
python -m pytest -m slow
# Which lines and branches the tests reach, leaving out the timing tests, since measuring
# slows the code down. erase clears an earlier run's data, which report would add in, and
# report fails below 100%.
python -m coverage erase
python -m coverage run -m pytest --ignore=tests/test_timing.py
python -m coverage report
```

On a slower or busier machine, `$env:TIMING_SCALE = 3` triples the timing tests'
one-second limit and the sweep's allowance for timer noise, as the GitHub Actions workflow
does.

## How the code is laid out

`python -m triage` runs `triage/__main__.py`, which passes the email through each stage in
turn: `reading/` reads it, `checks/` judges it, `enrich.py` looks up its indicators with
`--enrich`, and `report/` builds the report, which `__main__.py` prints or saves. Alert
text from `--text` goes straight to the indicators.

```text
triage/
  __init__.py             stops on a Python older than 3.14
  __main__.py             the command, which runs the stages in order
  reading/                reads the email, judging nothing
    __init__.py           makes the folder a package, so coverage sees its files
    parser.py             reads a .eml file into a ParsedEmail: headers, addresses,
                          bodies, links, and attachment hashes
    html_reader.py        reads an HTML body the way a mail client shows it
    link_wrappers.py      reads the real link out of a rewritten one
    origin.py             finds which outside server handed the email to your provider
    iocs.py               lists the indicators, from the email or from --text alert text
  checks/                 judges the email: each check gives flag, pass, or inconclusive
    __init__.py           runs the ones that need only the email
    headers.py            SPF, DKIM, DMARC, Ambiguous From, Reply-To and Return-Path
                          mismatches, free webmail
    impersonation.py      posing as a brand, your organization, or an executive
    links.py              where links go and what they open
    content.py            hidden text, image-only emails, text added by CSS
    lookups.py            the two that need --enrich: domain age and faked Microsoft hops
    english_words.txt     the word list short brand names are checked against
  enrich.py               looks the indicators up in VirusTotal and AbuseIPDB, with a
                          cache and the limits from settings.py
  report/                 turns what was found into the report
    __init__.py           builds one report and renders it for the terminal, as
                          Markdown, and as JSON, so the three can't disagree
    patterns.py           finds patterns in the findings, without changing any result
    follow_ups.py         picks the follow-ups the note suggests from what was found
  models.py               the data passed between the stages, and how evidence is written
  domains.py              helpers for domains, hosts, and IPs
  public_suffix_list.dat  the Public Suffix List that domains.py reads
  update_suffixes.py      downloads a newer copy of it
  settings.py             what's yours to change
```

The tests in `tests/` mostly have one file per module, plus `test_cli.py` for the command
line, `test_robustness.py` for damaged emails, and `test_timing.py` for input crafted to
be slow. The emails in `tests/fixtures/` are made up.

## How it was built and tested

- I planned the structure, wrote the first skeleton and the first version of the checks,
  and made the design decisions. An AI coding assistant reviewed the code for mistakes and
  ways around the checks. Its reviews kept growing the scope, so from there it wrote most
  of the code, and I reviewed every change before committing it.
- It was tested on made-up phishing emails, in `tests/fixtures/`, and on ordinary emails
  from my own inbox, which stay out of the repository.
- Every line and branch is covered by a test, and CI fails below 100%, on Windows and
  Linux with Python 3.14 and the newest release.
- Timing tests run crafted input that made the tool take minutes while it was being
  built, or could. Each input must finish within a second, and in a longer sweep,
  doubling it mustn't more than triple the time. A long run feeds the tool damaged emails.
- Some limitations are tests of what should happen, marked xfail. One that starts passing
  fails the run, until its mark and its line in [docs/LIMITATIONS.md](docs/LIMITATIONS.md)
  are removed.
