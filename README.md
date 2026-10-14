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
- Link text that shows one domain but goes to another, and links that run a script or
  open a file share or another program
- Text hidden inside words, emails that are only an image, and text added by CSS
- The server that handed the email to your provider, found from the Received headers
- Indicators (URLs, domains, IPs, email addresses, hashes), defanged for sharing. From an
  email, or from alert text with `python -m triage --text alert.txt` (`-` reads standard
  input)
- Updating the tool's copy of the Public Suffix List with `python -m triage.update_suffixes`

Planned:

- Optional reputation lookups with VirusTotal and AbuseIPDB, off unless asked for
- A Markdown triage note and a JSON report, with findings sorted by strength

The `--out`, `--json`, and `--enrich` options are there, but stop with "not built yet".

## Design decisions

### Results and safety

- **No phishing score or verdict.** A weighted number would need labeled data to
  calibrate, and the checks overlap: one lookalike domain like `paypa1.com` trips the
  display name, lookalike, and link checks at once, so adding them up counts the same fact
  three times. The tool lists what it found, and the analyst decides.

- **Every check ends as flag, pass, or inconclusive.** Inconclusive means the check
  couldn't tell either way, like DKIM on a message with no signature, or a link whose text
  CSS could change. Each check has a fixed strength (strong, medium, weak) that says how
  much it matters when it flags.

- **A check can carry caveats:** something close to it that it couldn't check, or a
  pointer to a related check. The analyst should look at them whatever the result is. A
  caveat is never the reason for the result, which is what the evidence is for. When a
  check can't tell, the result is inconclusive, not a pass with a caveat.

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

- **Domains are compared by the part one owner controls, using the Public Suffix List.**
  `mail.paypal.com` and `paypal.com` are one organization, while `b.co.uk` and `c.co.uk`
  aren't, and neither are `paypal-login.github.io` and `my-blog.github.io`. Browsers use
  the same list to keep one site's cookies away from another's. A copy ships with the
  tool (`triage/public_suffix_list.dat`, under the Mozilla Public License 2.0), so it
  works offline, and the tool reads its rules itself. A few hosting services the list
  doesn't have yet are added in `lists.py`. A domain written in text also has to end in
  a real TLD, or one that looks like it to the reader (`.com` with a Cyrillic `о`), so
  `invoice.pdf` and `Thanks.Regards` aren't read as domains.

- **The list is updated by hand, never by the tool.** `python -m triage.update_suffixes`
  downloads the newest list from publicsuffix.org and replaces the copy, which `git diff`
  then shows. The download isn't saved unless both sections start and end, and it isn't
  older than the copy. Updating by itself would mean the tool going online without being
  asked, and changing its own files where you can't see it. The tool notes when the copy
  is over 6 months old.

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

- **Links are read the way a browser reads them.** Python's URL parser disagrees with
  browsers in ways phishers use. A browser treats `\` as `/`, so
  `http://evil.com\@paypal.com` goes to evil.com, while Python reads the host as
  paypal.com. Browsers also percent-decode the host and turn fullwidth letters and dots
  into plain ones, so `%70aypa1.com` and `ｐａｙｐａ１。com` both go to `paypa1.com`. They skip
  tabs and line breaks anywhere in a link (`h<tab>ttp:\\evil.com`) and invisible
  characters like the zero-width space in a host. The tool does the same before checking a
  link.

- **Links are found the way a mail client shows them:** the first `href` when a tag has
  two, relative links resolved against a `<base href>`, every HTML part a client could
  display, not just the first, and URLs written out in a plain text part, which clients
  make clickable. Links inside `<!--[if mso]>` are read too: every other client takes that
  as a comment, but Outlook for Windows shows it, so a link can be there for Outlook users
  only.

- **A link's text is read with and without the parts a browser hides.**
  `paypal<span style="font-size:0"> </span>.com` shows paypal.com, but read as written it's
  "paypal .com", which isn't a domain, so a hidden space would make the link check pass.
  The tool follows the common ways to hide text (`display:none`, the `hidden` attribute,
  `visibility:hidden`, font size 0, opacity 0, `<template>`, and the inside of `<style>` or
  `<script>`) and the tags a browser closes on its own, checked against Edge. It can't get
  every case right without being a browser, so the link check reads the text both ways,
  and a mistake either way can't hide a domain.

- **Where CSS could change what a link shows, the tool says it can't tell instead of
  guessing.** It reads a tag's own `style`, but not the rules in a `<style>` block.
  Working those out means selectors, the cascade, and `@media`, and every rule handled
  leaves another way around it. So it looks at the places CSS would have to work. A tag
  in the middle of a domain in a link's text (`pay<b>pal</b>.com`, where hiding a space or
  adding `.evil` changes what the reader sees) makes the link check inconclusive instead
  of a pass, since a pass would promise more than the tool knows. A `<style>` block that
  adds text to the page (`::before { content: "." }`) gets its own content check, like an
  image-only email, since in both the reader sees text the tool can't read. Legitimate
  email rarely does either. The link's real address isn't affected, so the lookalike and
  link type checks still see it.

- **Links that don't open a web page or an email are flagged**, checked against a short
  list of safe link types (`https:`, `mailto:`, `tel:`) rather than a list of bad ones,
  so a new trick isn't missed. That covers `javascript:`, `data:` pages, `file:` and
  `\\server\share` file shares, and Windows programs like `search-ms:` and
  `ms-appinstaller:`, which phishing has used to run malware. Outlook for Windows opens a
  file share link over SMB, and Windows can send the reader's sign-in hash to that server.

- **Numeric hosts are read as the IP the browser goes to.** `http://3627734532/`,
  `http://0xd83ad604/`, and `http://0330.072.0326.04/` all open 216.58.214.4. Python's
  `ipaddress` refuses these forms, so without this the host would be listed as an odd
  domain and an IP lookup would miss it.

### Content

- **Hidden text is only flagged inside a word.** `Mic<span style="font-size:0">xyz</span>rosoft`
  shows Microsoft to the reader while a filter reads "Micxyzrosoft" (the ZeroFont trick).
  Hidden text on its own isn't flagged, because nearly every marketing email hides a
  preview line at the top for the inbox list.

- **An email that's only an image is flagged**, since text in a picture or a QR code can't
  be read by filters or by this tool. **Text added by CSS** is flagged for the same reason,
  but only as weak, since templates add small decorations that way too. Icon fonts,
  empty `content: ""`, and images (`content: url(...)`, which email trackers use) aren't
  counted, since they add nothing that reads.

- **These content checks only appear when they find something.** An email with no hidden
  text isn't safer for it, so a pass would read as reassurance the check can't give.
  There's no check on wording like "urgent" or "verify your account": real work email is
  full of it, so it would flag half the inbox, and a pass for calm wording would be false
  comfort.

### Indicators

- **From an email, only what it links to, loads, or came from is listed.** That's its
  links, images and form targets, URLs written in the plain text part, the sender
  addresses, the origin IP, and attachment hashes. Phishing names the real brand's domain
  to look genuine ("log in at paypal.com"), so a domain or IP that's only mentioned in the
  text isn't listed, since blocking it would be a mistake. Neither is a URL written as a
  link's text, which is only what the link shows. Alert text is different: tools and
  analysts write bare domains, IPs, and hashes there, so those count.

- **Indicators are defanged on the way out and refanged on the way in.**
  `hxxps://evil[.]com` can't turn into a live link when pasted into a ticket or a chat.
  Alert text often arrives defanged already, so `[.]`, `(dot)`, `[@]`, and `hxxp` are
  turned back before searching it.

- **URLs and domains are listed the way the browser asks for them**, with the host in the
  `xn--` form that DNS, proxy logs, and blocklists use. `http://%70aypa1.com/` is listed as
  `http://paypa1.com/`, and `http://3627734532/` as `http://216.58.214.4/`. Defanged, a
  Cyrillic `pаypal[.]com` looks just like the real one, and `xn--pypal-4ve[.]com` doesn't.

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

- **The Public Suffix List is only as new as the copy.** An ending added since it was
  downloaded isn't known until it's updated: a name under it is compared by its last two
  labels, and text ending in a new TLD isn't read as a domain.

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

### Content

- **Only hiding done in a tag's own `style` is seen.** Text hidden by a rule in a `<style>`
  block (`.x {display:none}`), by its color matching the background, by positioning it off
  screen, or by a zero height is read as shown, and so is a value a browser skips as
  invalid (`display:none; display:x` is still `none`). Hidden letters in a link's text are
  still caught, since the link check reads every bit of it, but a hidden space,
  punctuation mark, or line break splits the domain: `paypal<span class="x"> </span>.com`
  reads as "paypal .com", which isn't a domain, so the link check can't flag it. It shows
  inconclusive instead, naming the tag in the middle of paypal.com, so the analyst knows
  to look.

- **A stylesheet the email loads (`<link rel="stylesheet">`, `@import`) isn't read**,
  since the tool never fetches anything, so text it adds isn't flagged as Text added by
  CSS. Some mail clients load one, and most block it.

- **An image with a line of text next to it isn't flagged**, and that's what most QR code
  phishing looks like ("Scan to review your document"). The tool doesn't read images or
  QR codes.

### Indicators

- **The list is what the email contains, not what's safe to block.** Phishing often links
  to the real brand's site too (a footer link to `paypal.com`), and those are listed with
  the rest. The analyst picks what to block.

- **Some URLs in an email aren't listed:** URLs in CSS (`background: url(...)`), and a URL
  written as plain text in an HTML part, which some clients make clickable.

- **Alert text is read by pattern, so some text reads as an indicator when it isn't.**
  File names that end in a real TLD (`script.py`, `invoice.zip`) read as domains, unless
  they're in a path (`C:\Temp\script.py`), and a version number like `1.2.3.4` reads as an
  IP. Internal names that don't end in a real TLD (`srv01.corp.local`) aren't listed.
