# Phishing Triage Tool

A Python CLI that gathers evidence for phishing triage from a reported email.
The analyst makes the call.

## Status

Work in progress. What works now, with `python -m triage path/to/email.eml`:

- Parsing the email: headers, addresses, text and HTML bodies, links, and attachment hashes
  (SHA-256, computed in memory)
- Checks on the sender: SPF, DKIM, and DMARC results, Reply-To, Return-Path, display name,
  and free webmail
- Lookalike domains and brands joined to other words, in the sender and in links
- Link text that shows one domain but goes to another
- The server that handed the email to your provider, found from the Received headers

Planned:

- Indicators (URLs, domains, IPs, hashes) pulled from the email or from pasted alert text,
  defanged for sharing
- Optional reputation lookups with VirusTotal and AbuseIPDB, off unless asked for
- A Markdown triage note and a JSON report, with findings sorted by strength
- Automated tests

The `--text`, `--out`, `--json`, and `--enrich` options are there, but stop with
"not built yet".

## Design decisions

### Results and safety

- **Evidence, not a verdict.** There's no phishing score. A weighted number would need
  labeled data to calibrate, and the checks overlap: one lookalike domain like
  `paypa1.com` trips the display name, lookalike, and link checks at once, so adding them
  up counts the same fact three times. The tool lists what it found, and the analyst
  decides.

- **Every check ends as flag, pass, or inconclusive.** Inconclusive means the email didn't
  have enough evidence either way, like a message with no DKIM signature. Each check has a
  fixed strength (strong, medium, weak) that says how much it matters when it flags.

- **Nothing in the email is opened.** Attachments are hashed in memory and never written
  to disk. HTML is read as text to pull out links, never rendered, so tracking pixels
  don't load and links aren't visited.

### Headers and origin

- **Only the topmost Authentication-Results header is trusted.** Your mail provider adds
  it on top. Anything below was already in the message when it arrived, so the sender
  could have written it, including a fake `dmarc=pass`. If your provider might not add
  one, list its server name in `TRUSTED_AUTHSERV_IDS` (`mx.google.com` for Gmail) and only
  headers from it count, as RFC 8601 recommends.

- **When SPF or DMARC reports more than one result, the worst one counts.** Each gives one
  result per message, so extra results mean someone added text to the header. An attacker
  can add a fake pass but can't remove a real fail. DKIM is the exception, since several
  signatures on one message are normal.

- **A DKIM pass only counts when the signature is from the From domain's organization.**
  Anyone can sign mail with their own domain, so a valid signature from evil.com on mail
  claiming to be paypal.com isn't a pass. This is the same alignment DMARC requires. A
  signature with `l=` covers only the start of the body, so text could have been added
  after it, and that isn't counted as a pass either.

- **A DMARC pass only counts for the From the tool shows.** The provider names the From
  domain it checked (`header.from`). With two From headers, or two addresses in one, it
  can check one while the mail client shows the other, so a pass for a different domain
  isn't counted.

- **Encoded text is only decoded where it's allowed.** Python's email library decodes
  `=?utf-8?q?...?=` encoded words anywhere in a header, but they're only allowed in plain
  text like the Subject and display names. Received, Authentication-Results, and
  Return-Path copy text the sender chose (the envelope address, the HELO name), and
  decoding the valid address `=?utf-8?q?x=3Bdkim=3Dpass?=@evil.com` adds a fake DKIM pass.
  In a From address, `service@=?utf-8?q?paypal=2Ecom?=` would read as paypal.com. These
  are read as written, and an address with encoded text gets a warning showing what some
  mail clients display instead.

- **The originating server comes from the receiver's reverse DNS lookup, not the name the
  sender claims.** The sender can claim to be `mx.google.com`. The reverse DNS name is
  looked up by the receiving server. Hops below the handoff are shown as claims because
  they could be forged.

### Lookalikes and links

- **Lookalike domains are matched word by word, not with a similarity percentage.** The
  domain is split on dots and dashes, lookalike characters are swapped back (`0` to `o`,
  Cyrillic `а` to `a`), and each word is compared to the brand name: an exact match or one
  typo. Letter pairs (`rn` for `m`) are compared both swapped and as written, since a swap
  can hide a match: `amazonnow.com` contains amazon, but swapping `nn` gives `amazomow`.
  Comparing whole domains missed the same typo on another TLD (`paypa1.xyz`) or in a
  subdomain, and "one typo" is easier to defend than a percentage picked by testing. A
  brand's real domain put in front of someone else's
  (`login.microsoftonline.com.evil.net`) is flagged too, which also covers real domains
  that don't contain the brand name.

- **Links are read the way a browser reads them, not the way Python's URL parser does.**
  The two disagree in ways phishers use. A browser treats `\` as `/`, so
  `http://evil.com\@paypal.com` goes to evil.com, while Python reads the host as
  paypal.com. Browsers also percent-decode the host and turn fullwidth letters and dots
  into plain ones, so `%70aypa1.com` and `ｐａｙｐａ１。com` both go to `paypa1.com`. They skip
  tabs and line breaks anywhere in a link (`h<tab>ttp:\\evil.com`) and invisible
  characters like the zero-width space in a host. The tool does the same before checking a
  link. It also finds links the way a mail client shows them: the first `href` when a tag
  has two, relative links resolved against a `<base href>`, and every HTML part a client
  could display, not just the first.

## Limitations

### Lists and configuration

- **The brand list in `triage/lists.py` is short.** It's a starting point, not a complete
  list.

- **Brands use more real domains than `BRANDS` lists** (Google alone has hundreds). An
  unlisted real domain gets flagged as a lookalike, and the analyst has to judge it.

- **Free webmail providers missing from `FREE_EMAIL_DOMAINS` are treated like company
  domains.** A Reply-To pointing to a different account on the same unlisted provider
  isn't flagged, and neither is the free sender.

- **`OWN_NAMES`, `OWN_DOMAINS`, and `EXECUTIVES` start empty.** Lookalikes of your own
  domain, your company's name in a display name ("Contoso IT Support" from Gmail), and
  executive impersonation are only caught once you fill them in.

- **Domains are compared by an approximate base domain** (`mail.paypal.com` becomes
  `paypal.com`). Common country formats (`co.uk`, `com.au`, `ne.jp`) and shared hosting
  services (`github.io`, `onmicrosoft.com`) are handled, but not every case. The Public
  Suffix List would be exact.

### Headers and origin

- **Received headers are read in the formats Gmail, Microsoft, Postfix, Exim, and qmail
  use.** A header with an IP in another format is skipped with a warning. Run the tool
  once on a known-good email from your own mail system to check the origin it reports.

- **Microsoft's Received header format doesn't include a reverse DNS name**, so for mail
  received by Outlook the originating server name is the one the sender gave. The tool
  uses that name to skip Microsoft's internal relays, so a sender that calls itself
  `something.outlook.com` is skipped too, and a forged hop below it can be reported as the
  origin. Only the IP in that hop can be trusted, and checking who owns it needs a lookup.

- **A real signed email resent by someone else (DKIM replay) still passes DKIM and
  DMARC**, since the signature is genuine, and nothing in the headers shows the resend.
  The clues are a To address that isn't the person who reported it, and an old Date.

- **DKIM is matched to the From domain using the signing domain your provider names** in
  Authentication-Results (`header.d`, or `header.i` for Gmail). If it names none, DKIM
  shows inconclusive.

- **Help desk systems (Zendesk, Freshdesk) often set Reply-To to their own domain** so
  replies land in a ticket queue. That gets flagged the same way as a phishing Reply-To,
  and the analyst has to judge it.

### Parsing

- **Python's email library is slow on some crafted headers** (a 160 KB Content-Type took
  90 seconds). The tool refuses an email with a header over 4 KB that the library parses
  itself, like Content-Type, and decodes only the first 4 KB of a long Subject or display
  name. Real headers are far shorter. A crafted email with many parts can still be slow,
  up to about a second per part.

- **Addresses are read with Python's strict address parser**, which drops what it can't
  read instead of guessing. A header with an address it dropped (an unclosed comment, an
  IP address in brackets) gets a warning, and if no From address is left, the checks that
  need it show inconclusive.

- **An email attached to the one being checked (a phish forwarded as an attachment) isn't
  checked itself.** The tool warns about it, and the attachment has to be saved and run on
  its own. Outlook `.msg` files need saving as `.eml` first.

### Lookalikes and brands

- **Brand names are matched as whole words**, so a company with a brand in its name gets
  flagged: "Apple Valley Dental" in a display name, or `apple-valley-dental.com` as a
  lookalike domain. A brand split inside a word is caught in a domain (`pay-pal.com`) but
  not in a display name ("Pay Pal"). A multi-word name split by a dot is caught when
  spelled right (`wells.fargo-alerts.com`), but not with a typo
  (`wells.farqo-alerts.com`).

- **A brand joined to another word (`paypalsecure.com`) is only a weak flag**, because
  brands own domains like that too (`googleapis.com`). Short brand names aren't checked
  this way, since they sit inside ordinary words (pineapple, purchase).

- **Short brand names like Apple and Chase are one letter from common words** (apply,
  phase), so typos of them are only checked in the registered domain name, not in
  subdomains. `appel.com` and `chose.com` are flagged, `appel.example.com` isn't. A
  registered name that's a real word next to a brand still gets flagged, like
  `apply-now.com` or `chaser-games.com`.

- **Names under five letters, like Meta, aren't checked for typos at all**, since nearly
  every word that short is one letter from another (beta, mega, metal). `meta-support.com`
  and `m3ta.com` are still flagged, `metta.com` isn't.

- **Lookalike characters cover the common cases, not all of Unicode:** digit swaps (`0`
  for `o`), the Cyrillic and Greek letters Unicode lists as looking like a Latin one (`а`,
  `ο`), capitals that look like lowercase letters in display names (`PayPaI` with a
  capital I, Cyrillic `Ь` for `b`), letter pairs (`rn` and `nn` for `m`, `vv` for `w`,
  `cl` for `d`), and fullwidth or styled letters (`ｐ`, `𝐩`). Invisible characters
  (zero-width space, soft hyphen) are dropped first, since the reader doesn't see them.
  Other scripts (Armenian `օ`) and Latin variants (`ɡ`, dotless `ı`) aren't covered, and
  neither are capitals that only look Latin in uppercase (Cyrillic `М`), since text is
  lowercased first. Brand names are stored in lowercase, so `Linkedln` with a lowercase l
  isn't caught in a display name, though it is in a domain.

### Links and platforms

- **Legitimate click tracking looks the same as a phishing link**: the text shows one
  domain and the link goes to another. The flag is correct, and the analyst has to judge
  it.

- **Phishing sent through the real platform passes the sender checks**: a Facebook page
  named "Meta Support" gets its notifications sent from `facebookmail.com` with valid DKIM
  and DMARC. Links through a brand's own redirect (`l.facebook.com/l.php?u=`,
  `linkedin.com/slink`) look like they go to the brand. The evidence there is where the
  links end up.
