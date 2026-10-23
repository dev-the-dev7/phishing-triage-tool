# Phishing Triage Tool

A Python CLI that gathers evidence for phishing triage from a reported email.
The analyst makes the call.

## What it does

- Parsing the email: headers, addresses, text and HTML bodies, links, and attachment hashes
  (SHA-256, computed in memory)
- Checks on the sender: SPF, DKIM, and DMARC results, a From that can be read more than
  one way, a Reply-To, Return-Path, or display name that doesn't match the sender, and
  free webmail
- Lookalike domains and brands joined to other words, in the sender and in links, with
  short brand names like Apple and Meta checked against an English word list, so ordinary
  words aren't flagged
- Link text that shows one domain but goes to another, and links that run a script or
  open a file share or another program
- Links rewritten by Microsoft's Safe Links, Proofpoint, or Google's redirect, read as where
  they really go, with a weak flag for a link the sender put behind Google's redirect
- Text hidden inside words, emails that are only an image, and text added by CSS
- Named patterns that combine findings, like a lookalike domain that passes DMARC
- The server that handed the email to your provider, found from the Received headers
- Indicators (URLs, domains, IPs, email addresses, hashes), defanged for sharing. From an
  email, or from alert text with `python -m triage --text alert.txt` (`-` reads standard
  input)
- Reputation lookups with `--enrich`: VirusTotal for hashes, domains, URLs, and IPs, and
  AbuseIPDB for IPs, with each IP's network and country, and checks for domains
  registered in the last 30 days and for hops faked as Microsoft's servers
- Updating the tool's copy of the Public Suffix List with `python -m triage.update_suffixes`
- A report in the terminal: a summary with the strongest flag and the count of each
  result, any patterns, the email's details and origin, every check with flags first, and
  the indicators
- A Markdown triage note to paste into a ticket with `--out note.md`, and the same report
  as JSON for other tools with `--json report.json`. With either, the terminal shows a
  short summary. `-` prints one instead of writing a file, for a pipe, and the summary
  goes to stderr. There's a sample of each, from a synthetic email, in `samples/`.

## Installing

The tool needs Python 3.14 or newer, and is tested with 3.14 and 3.15 on Windows and
Linux. On an older version it stops with an error instead of running, since an older
Python can read an email differently, and a check can then pass when it shouldn't.

It runs from this folder with `python -m triage`, without being installed as a package.
To set it up in PowerShell:

```powershell
# 3.14, or a newer version you have, like py -3.15
py -3.14 -m venv .venv
# If PowerShell won't run scripts, allow them for this window only:
# Set-ExecutionPolicy -Scope Process RemoteSigned
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

On Linux, create the environment with `python3.14 -m venv .venv`, or the newer version you
have, and activate it with `source .venv/bin/activate`.

`requirements.txt` holds what the tool needs: `requests` for the lookups, `idna` for
writing domains as browsers do, and what `requests` installs, each pinned to one version
so a new release isn't picked up without anyone looking at it. To run the tests too,
install `requirements-dev.txt` instead, which adds pytest and coverage.

## Running it

With the environment active, from this folder:

```powershell
# The made-up email the tests use, to see what a report looks like
python -m triage tests/fixtures/suspicious.eml

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

## Setting up the lookups

`--enrich` needs an API key from [VirusTotal](https://www.virustotal.com) and one from
[AbuseIPDB](https://www.abuseipdb.com). Its limits are set for the free keys, so with your
organization's paid keys, raise them in `triage/settings.py`. The tool reads the keys from
environment variables. In PowerShell:

```powershell
# For this window only. Read-Host keeps the key out of PowerShell's history file, which
# saves everything typed at the prompt.
$env:VT_API_KEY = Read-Host "VirusTotal API key"
$env:ABUSEIPDB_API_KEY = Read-Host "AbuseIPDB API key"

# For every new window, saved in your Windows account. Apps already open, like VS Code,
# only see it once they're restarted.
[Environment]::SetEnvironmentVariable("VT_API_KEY", (Read-Host "VirusTotal API key"), "User")
[Environment]::SetEnvironmentVariable("ABUSEIPDB_API_KEY", (Read-Host "AbuseIPDB API key"), "User")
```

Then run `python -m triage path/to/email.eml --enrich`. Without a key, that service's
lookups show as unavailable and the rest of the output is the same.

Behind a proxy that inspects TLS, as many company networks have, the lookups show as
unavailable with `SSLError` until `REQUESTS_CA_BUNDLE` points to a certificate file that
includes the company's root certificate.

## Your organization's settings

What's yours to change is in `triage/settings.py`, explained in
[docs/CONFIGURATION.md](docs/CONFIGURATION.md).

## Running the tests

With `requirements-dev.txt` installed, from this folder:

```powershell
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

The timing tests run crafted input that made the tool take minutes while it was being
built, or could. Each input must finish within a second, and in the slow sweep, doubling
the input mustn't more than triple the time. On a slower or busier machine,
`$env:TIMING_SCALE = 3` triples the one-second limit and the sweep's allowance for timer
noise, as the GitHub Actions workflow does.

Each test marked xfail is one of the limitations in
[docs/LIMITATIONS.md](docs/LIMITATIONS.md), written as what should happen. One that starts
passing fails the run, until its mark and its line there are removed.

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
  report/                 shows what was found
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

## Design decisions

Why the tool works the way it does, and what could come next, is in
[docs/DESIGN.md](docs/DESIGN.md).

## Limitations

What the tool can miss or get wrong is in [docs/LIMITATIONS.md](docs/LIMITATIONS.md).
