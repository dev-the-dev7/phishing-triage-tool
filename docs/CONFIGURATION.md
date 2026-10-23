# Configuration

## API keys

`--enrich` needs an API key from [VirusTotal](https://www.virustotal.com) and one from
[AbuseIPDB](https://www.abuseipdb.com). The tool reads the keys from environment
variables. In PowerShell:

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

Without a key, that service's lookups show as unavailable and the rest of the output is
the same.

Behind a proxy that inspects TLS, as many company networks have, the lookups show as
unavailable with `SSLError` until `REQUESTS_CA_BUNDLE` points to a certificate file that
includes the company's root certificate.

## Your organization's settings

What's yours to change is in `triage/settings.py`, in three parts.

The first part is about your organization and ships empty, so its checks do nothing until
you fill it in: your names and domains (`OWN_NAMES`, `OWN_DOMAINS`), executives attackers
might pose as (`EXECUTIVES`), and your provider's server name if it might not add its own
Authentication-Results (`TRUSTED_AUTHSERV_IDS`). Your names and executives need
`OWN_DOMAINS` too.

The second comes filled in with what turns up in most mail: brands, webmail providers, the
words phishers join to a brand's name (`JOIN_WORDS`), and words that look like a brand
but aren't (`ALLOWED_NAMES`). Add to it, or take out what doesn't fit yours. A supplier
or partner you get mail from goes in `BRANDS` with its domains, so someone posing as them
is flagged too.

The last is how many lookups `--enrich` makes, set for the free keys. With your
organization's paid keys, raise them to what the keys allow: `VT_LOOKUPS_PER_RUN` and
`ABUSEIPDB_LOOKUPS_PER_RUN` a run, and `VT_LOOKUPS_PER_MINUTE`. At the limit a minute the
tool waits, then carries on until the limit a run. A key with no limit a minute can set
it as high as the limit a run, so it never waits. There's always a limit a run, so an
email with hundreds of links can't send a lookup for each.

Each setting is explained where it's set. After changing any of them, check your entries,
with the test tools from `requirements-dev.txt` installed:

```powershell
python -m pytest tests/test_settings.py
```

The full test suite checks the tool against the second part's lists as they ship, so after
changing them some of its tests can fail without anything being wrong. The first and last
parts don't affect it. `tests/test_settings.py` is the one that checks your changes.
