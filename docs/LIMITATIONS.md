# Limitations

## Lists and configuration

- **The brand list in `triage/settings.py` is short.** It's a starting point, not a
  complete list.

- **Brands use more real domains than `BRANDS` lists** (Google alone has hundreds). An
  unlisted real domain gets flagged as a lookalike, and the analyst has to judge it, or
  add it to that brand's domains.

- **Free webmail providers missing from `FREE_EMAIL_DOMAINS` are treated like company
  domains.** A Reply-To pointing to a different account on the same unlisted provider
  isn't flagged, and neither is the free sender.

- **`OWN_NAMES`, `OWN_DOMAINS`, and `EXECUTIVES` in `triage/settings.py` start empty.**
  Lookalikes of your own domain, your company's name in a display name ("Contoso IT
  Support" from Gmail), and executive impersonation are only caught once you fill them in.

- **The Public Suffix List is only as new as the copy.** An ending added since it was
  downloaded isn't known until it's updated: a name under it is compared by its last two
  labels, and text ending in a new TLD isn't read as a domain.

## Headers and origin

- **Received headers are read in the formats Gmail, Microsoft, Postfix, Exim, and qmail
  use.** A header with an IP in another format is skipped with a warning. Run the tool
  once on a known-good email from your own mail system to check the origin it reports.

- **Microsoft's Received header format doesn't include a reverse DNS name**, so for mail
  received by Outlook the originating server name is the one the sender gave. The tool uses
  that name to skip Microsoft's internal relays, so a sender that calls itself
  `something.outlook.com` is skipped too, and a forged hop below it can be reported as the
  origin. Only `--enrich` checks who owns that hop's IP. A server rented on Microsoft's
  cloud (Azure) has a Microsoft IP and passes, though Azure blocks sending mail straight to
  other servers for most accounts. A company's own Exchange server writes names the same
  way, and only Microsoft 365's are checked.

- **A real signed email resent by someone else (DKIM replay) still passes DKIM and
  DMARC**, since the signature is genuine, and nothing in the headers shows the resend.
  The clues are a To address that isn't the person who reported it, and an old Date.

- **DKIM is matched to the From domain using the signing domain your provider names** in
  Authentication-Results (`header.d`, or `header.i` for Gmail). If it names none, DKIM
  shows inconclusive.

- **An envelope address with an unquoted `;` can add a fake pass.** Providers copy the
  sender's envelope address into Authentication-Results, and nothing there marks where it
  ends, so in `x;dkim=pass.header.i=@paypal.com;@evil.com` the part between the `;`s reads
  as a DKIM pass for paypal.com. A real DMARC fail still flags, and no pattern counts the
  DKIM pass then. A From domain with no DMARC record has no fail to show, so the DKIM pass
  counts, and so does a DMARC pass added the same way if your provider writes no DMARC
  result. Such an address isn't valid, so this needs a provider that accepts it and copies
  it unchanged.

- **Help desk systems (Zendesk, Freshdesk) often set Reply-To to their own domain** so
  replies land in a ticket queue. That gets flagged the same way as a phishing Reply-To,
  and the analyst has to judge it.

## Parsing

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

## Lookalikes and brands

- **Brand names are matched as whole words**, so a company with a brand in its name gets
  flagged: "Apple Valley Dental" in a display name, or `apple-valley-dental.com` as a
  lookalike domain. A brand split inside a word is caught in a domain (`pay-pal.com`) but
  not in a display name ("Pay Pal"). A multi-word name split by a dot is caught when
  spelled right (`wells.fargo-alerts.com`), but not with a typo
  (`wells.farqo-alerts.com`).

- **A brand joined to another word (`paypalsecure.com`) is only a weak flag**, because
  brands own domains like that too (`googleapis.com`). A short brand name joined to a word
  that isn't in `JOIN_WORDS` or the word list is inconclusive, which includes real company
  names (`applebyfarms.com`) until they're added to `BRANDS` with their domains, or to
  `ALLOWED_NAMES` when you don't get mail from them.

- **Typos of short brand names are only checked in the registered domain name**, not in
  subdomains, so `appel.example.com` isn't flagged. A phisher can write the real name in a
  subdomain for free, and hostnames are full of short labels like `mta` or `cdn` that
  aren't words. A typo that's an English word, like `apply-now.com` or `beta.com`, comes
  out inconclusive, so the analyst sees it even though most are harmless.

- **The word list is English and from around 2000**, so newer and foreign words read as
  not words: a typo that's one is flagged, and a short name inside one is inconclusive,
  until it's added to `ALLOWED_NAMES`. Real names that aren't words are treated the same:
  `metra.com`, Chicago's commuter rail, is flagged as a typo of meta.

- **Names under four letters aren't typo-checked or looked for inside words**, since
  nearly every short label is one letter from them. They're still caught spelled right
  (`ibm-login.com`) or with lookalike characters.

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

## Links and platforms

- **Legitimate click tracking looks the same as a phishing link**: the text shows one
  domain and the link goes to another. The flag is correct, and the analyst has to judge
  it.

- **Phishing sent through the real platform passes the sender checks**: a Facebook page
  named "Meta Support" gets its notifications sent from `facebookmail.com` with valid DKIM
  and DMARC. Links through a brand's own redirect (`l.facebook.com/l.php?u=`,
  `linkedin.com/slink`) look like they go to the brand. The evidence there is where the
  links end up.

- **Links rewritten by other services keep their wrapper.** Mimecast's links hold only a
  token, so the real link can't be read from them, and other services' formats (Barracuda,
  Cisco, Trend Micro), Google's redirect on its other domains (`google.co.uk/url`), and
  Google's AMP links (`google.com/amp/s/evil.com`) aren't read yet. The link check flags
  each one, since its text shows one domain and it goes to the service, and the real
  destination isn't listed or looked up with `--enrich`.

## Content

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

## Indicators

- **The list is what the email contains, not what's safe to block.** Phishing often links
  to the real brand's site too (a footer link to `paypal.com`), and those are listed with
  the rest. The analyst picks what to block.

- **Some URLs in an email aren't listed:** URLs in CSS (`background: url(...)`), and a URL
  written as plain text in an HTML part, which some clients make clickable.

- **Alert text is read by pattern, so some text reads as an indicator when it isn't.**
  File names that end in a real TLD (`script.py`, `invoice.zip`) read as domains, unless
  they're in a path (`C:\Temp\script.py`), and a version number like `1.2.3.4` reads as an
  IP. Internal names that don't end in a real TLD (`srv01.corp.local`) aren't listed.

## Lookups

- **VirusTotal's free key is for personal use.** Its terms say the free API "must not be
  used in commercial products or services" or in business workflows. Triage at work needs
  your organization's paid key, with its limits in `settings.py`.

- **Reputation lags behind new phishing.** A domain registered this morning is usually not
  found or clean, and so is a link made for one reader. A clean result is no reason to
  close a report.

- **A URL can carry the reader's identity in a form the tool can't see**, like a token or
  a base64-encoded address, and that's sent to VirusTotal with the URL. So is a live
  sign-in or password reset link, when a real email is reported by mistake.

- **Any 32, 40, or 64 hex characters in alert text are looked up as a file hash.** A
  token or ID written that way is sent to VirusTotal too.

- **Internal names under a public domain are only kept back once `OWN_DOMAINS` is filled
  in.** Until then, a name like `wks-0231.corp.contoso.com` in alert text is looked up like
  any other domain.

- **The free key's 8 VirusTotal lookups don't cover an email with many links or a long
  alert.** The rest are shown as skipped. With a paid key, raise `VT_LOOKUPS_PER_RUN` in
  `settings.py`.

- **Links to forms and files on a brand's own domain go last**, with the brand's real
  links, so in an email past the limit they can be skipped. Phishing pages are often made
  with these services (`docs.google.com/forms`, `forms.office.com`), since the domain
  looks safe. They go last because phishing also copies the brand's real links (privacy
  policy, help pages) to look genuine, and those would use up the lookups instead.

- **A result from the cache can be up to a day old.**

- **The network and country are AbuseIPDB's record of the sending server**, not of the
  sender, and an IP's owner chooses the network name it registers.

- **Domain age needs `--enrich`, and only covers the domains that were looked up.** Some
  domains have no registration date in VirusTotal, and that check is then inconclusive. A
  phishing site on a hacked or long-held domain is old, so it passes.
