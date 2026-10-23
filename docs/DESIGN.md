# Design decisions

## Results and safety

- **No phishing score or verdict.** A weighted number would need labeled data to
  calibrate, and the checks overlap: one lookalike domain like `paypa1.com` trips the
  display name, lookalike, and link checks at once, so adding them up counts the same fact
  three times. The tool lists what it found, and the analyst decides.

- **Every check ends as flag, pass, or inconclusive.** Inconclusive means the check
  couldn't tell either way, like DKIM on a message with no signature, or a link whose text
  CSS could change. Each check has a fixed strength (very strong, strong, medium, weak)
  that says how much it matters when it flags. Very strong is for what no known legitimate
  sender does, like two From headers, and strong for what real mail does now and then, like
  a mailing list breaking DMARC.

- **A check can carry caveats:** something close to it that it couldn't check, or a
  pointer to a related check. The analyst should look at them whatever the result is. A
  caveat is never the reason for the result, which is what the evidence is for. When a
  check can't tell, the result is inconclusive, not a pass with a caveat.

- **Checks are about the email, warnings are about the tool's reading.** Something the
  sender did, like two Reply-To headers, goes in a check's evidence or caveats, next to the
  result it affects. A warning means part of the email couldn't be read, like a header the
  tool couldn't parse, an unknown charset, or an email attached to this one, so that part
  needs checking by hand.

- **At most five of anything a sender can repeat are named,** with a count of the rest, in
  evidence, caveats, and warnings, so padding an email with thousands of headers or links
  can't bury the findings or warnings. Warnings are grouped by kind instead of cut off at
  a number, since a cut would let a flood of one kind push out another. Indicators and
  attachments are listed in full, since each one may need blocking or checking, and so are
  the SPF, DKIM, and DMARC results your provider reports, since the worst one decides the
  check.

- **The report puts flags first, strongest first,** then inconclusive checks, then passes.
  Its summary gives the strongest flag and the count of each result. The strongest flag
  isn't a score: two weak flags don't add up to a medium one, since they can be the same
  fact seen twice.

- **Patterns name findings that mean more together than apart**, each with a line on why.
  A lookalike domain that passes DMARC or DKIM only shows the attacker set up their own
  domain. An authenticated sender with a lookalike link may be a hacked account, which
  changes who to tell and what to block. Each is made from findings about different
  facts, since one lookalike domain tripping three checks is still one fact. A pattern
  never changes a check's result, and the section only appears when one matches, since "no
  patterns" would read as reassurance.

- **Text from the email can't change how the report looks.** Control, invisible, and
  line-breaking characters are shown as codes: terminal codes could rewrite lines above, a
  newline or line separator in an encoded Subject could add a fake result line, and a
  right-to-left override shows `invoice<RLO>fdp.exe` as `invoiceexe.pdf`. Long text is
  cut in the middle, with how much was left out, since a Subject or display name can be
  260 KB and the end often matters most (the reason at the end of a check's evidence). A
  display name and its address are cut apart, so padding in the name can't push the
  address out of sight, and quotes in the name are escaped, so a name like
  `PayPal" <service@paypal.com>` can't pass for the address. The same goes for text from
  the lookup services, like a network's name.

- **The note is written for a ticket.** It follows the usual triage note: a summary, any
  patterns, the flags with their evidence, what was inconclusive or passed, the indicators,
  follow-ups worded as suggestions, and blank fields for the analyst's verdict and
  actions, which the tool never fills in. Every value from the email or a lookup is in a
  code span and defanged, so it can't make a link, an image, or formatting, whether the
  ticket system reads Markdown or not. That includes the Message-ID and addresses, which
  have to be refanged before searching for them.

- **The follow-ups are picked from what was found**, so the analyst edits a list instead
  of writing one. The reply search names the Reply-To when there is one, the click search
  only appears when there are URLs, and the EDR search when there are attachments. Only
  lookalike and newly registered domains are named for blocking, since they're likely the
  attacker's own, and blocking a spoofed or shared domain would cut off real senders. For
  a free webmail sender, it's the address, never the webmail domain. A display name
  posing as someone adds telling them, and an authenticated sender with a lookalike link
  adds telling the sender's organization instead of blocking. They're picked from
  results, flagged domains, and pattern names, never from evidence or caveats, which are
  written for people to read.

- **The JSON keeps values exactly as found**, since a tool that blocks or searches needs
  the real URL, with each indicator's defanged form next to it. It's plain ASCII: anything
  else, control characters included, is written as an escape code, so no viewer can be
  fooled by it. A `format` number says when a field is renamed, removed, or changes type.

- **Files are written whole or not at all.** Each goes to a file next to it first and is
  then swapped in, with `\n` line endings on any system. If one can't be written, the full
  report prints in the terminal instead, so a run that waited on lookups isn't lost. File
  names are checked before the work starts, and a note can't be written over the email or
  text it's about, since that's the evidence.

- **Nothing in the email is opened.** Attachments are hashed in memory and never written
  to disk. HTML is read as text to pull out links, never rendered, so tracking pixels
  don't load and links aren't visited.

## Headers and origin

- **Only the topmost Authentication-Results header is trusted.** Your mail provider adds
  it on top. Anything below was already in the message when it arrived, so the sender
  could have written it, including a fake `dmarc=pass`. If your provider might not add
  one, list its server name in `TRUSTED_AUTHSERV_IDS` (`mx.google.com` for Gmail) and only
  headers from it count, as RFC 8601 recommends. Return-Path can't be read that way. Most
  providers remove one that came with the message and add their own, but not all put
  theirs on top: Microsoft 365's is below the From. So with more than one, the Return-Path
  check is inconclusive and names them, as the report does.

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

- **A From that can be read more than one way is a very strong flag.** Two From headers,
  two addresses in one, or encoded text in the address let a mail client show a different
  From than the one DMARC checked, which researchers used to get past DMARC at large
  providers ("Composition Kills", 2020). Several authors in one From is allowed, but common
  mail programs only send from one address, so the Ambiguous From check is only listed
  when it finds something.

- **Every From address is checked.** Mail clients don't agree on which one they show, so
  each check that compares the From runs on every one: a flag on any of them counts, and a
  pass needs all of them to pass. A DMARC pass for the attacker's own domain in one From
  doesn't cover a brand's domain in the other. Past 10 addresses the rest aren't compared,
  since comparing thousands with every Reply-To would take minutes, so those checks can't
  pass.

- **The Sender header is shown and its domain checked, but it isn't compared with the
  From.** Outlook shows it as "Sender on behalf of From", and it can name the account that
  really sent the email. Mailing lists and assistants set it on ordinary mail, though, and
  DMARC doesn't read it, so a Sender that isn't the From isn't flagged. It's listed as an
  indicator, and the lookalike checks read its domain. Only one is allowed, but like From
  and Reply-To, every Sender header in the email is read. When From has several addresses,
  the standard requires a Sender header naming who sent it, and Ambiguous From says when
  there isn't one.

- **Encoded text is only decoded where it's allowed.** Python's email library decodes
  `=?utf-8?q?...?=` encoded words anywhere in a header, but they're only allowed in plain
  text like the Subject and display names. Received, Authentication-Results, and
  Return-Path copy text the sender chose (the envelope address, the HELO name), and
  decoding the valid address `=?utf-8?q?x=3Bdkim=3Dpass?=@evil.com` adds a fake DKIM pass.
  In a From address, `service@=?utf-8?q?paypal=2Ecom?=` would read as paypal.com. These
  are read as written, along with what mail clients hit by the Mailsploit bugs display
  instead. In the From address that's a flag, and in a Reply-To that otherwise matches the
  sender it makes the check inconclusive, since such a client may reply to what it shows.
  In To, Sender, or Return-Path it's a warning.

- **The originating server comes from the receiver's reverse DNS lookup, not the name the
  sender claims.** The sender can claim to be `mx.google.com`. The reverse DNS name is
  looked up by the receiving server. Hops below the handoff are shown as claims because
  they could be forged.

## Lookalikes and links

- **Domains are compared by the part one owner controls, using the Public Suffix List.**
  `mail.paypal.com` and `paypal.com` are one organization, while `b.co.uk` and `c.co.uk`
  aren't, and neither are `paypal-login.github.io` and `my-blog.github.io`. Browsers use
  the same list to keep one site's cookies away from another's. A copy ships with the
  tool (`triage/public_suffix_list.dat`, under the Mozilla Public License 2.0), so it
  works offline, and the tool reads its rules itself. A few hosting services the list
  doesn't have yet are added in `domains.py`. A domain written in text also has to end in
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

- **Short brand names are told apart from ordinary words with a word list.** A name under
  six letters is one letter from ordinary words (apple: apply) and sits inside others
  (pineapple), so spelling alone can't tell a lookalike from a word. The tool asks ENABLE,
  an English word list its authors released into the public domain, which ships with the
  tool (`triage/checks/english_words.txt`, `enable1.txt` from github.com/dolph/dictionary)
  so it works offline. A typo that isn't a word (`appie.com`, `metq.com`) is flagged. One
  that is a word is inconclusive, since it can be harmless (`apply.com`) or a typosquat
  (`appel.com`). A short name joined to a word phishers use (`appleid.com`, `mymeta.com`,
  from `JOIN_WORDS` in `settings.py`) is flagged, inside an English word (`pineapple.com`)
  it passes, and inside anything else (`applebyfarms.com`) it's inconclusive.
  `ALLOWED_NAMES` passes the rest: it ships with newer words the list lacks (`mega`,
  `metadata`), and others from your own mail (`metaverse`) can be added there. A supplier
  is better added to `BRANDS` with its domains, which also flags someone posing as them.
  So in the registered domain, nothing one letter from a short name or holding it passes,
  except a longer English word holding it, a word you've allowed, or a brand's own domain.

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
  only. With several different `<base>` tags, links are read against each, since browsers
  skip one inside `<template>` or `<svg>` and a decoy can come first. The link check says
  so in a caveat, and past 10 it can't pass, since the rest weren't read.

- **A link rewritten by a mail security service is read as where it really goes.**
  Microsoft Defender's Safe Links and Proofpoint rewrite every link in delivered mail to go
  through them first, and phishing puts links behind Google's redirect
  (`google.com/url?q=`) so they start with google.com. The tool reads the real link out of
  each (`url=` for Safe Links, `u=` and the v3 format for Proofpoint, `q=` or `url=` for
  Google), even when one wraps another, and the checks, the indicators, and `--enrich` all
  use it. Alert text gets the same, since users often report the Safe Links URL they
  clicked. The link inside is read the way a browser reads it, so a space in front or
  `//evil.com` doesn't hide it. Only the services' own hosts are read, so
  `safelinks.protection.outlook.com.evil.com` is checked as the link it is. A wrapper naming
  two different links is read as a link to each, since which one the service follows isn't
  known, so the checks, the indicators, and `--enrich` see both, and a warning names them,
  so a "Click here" can't hide them. In a link's text, only Safe Links and Proofpoint URLs
  are read this way, since they rewrite what a plain text part shows. A Google redirect
  shown in the text was the sender's choice, so the reader sees google.com, and the link
  check flags it.

- **A link the sender put behind Google's redirect is a weak flag**, even when Safe Links
  or Proofpoint wrapped it again on the way in, since a filter that judges a link by where
  it points sees google.com. It's weak because Google's own mail, like Calendar
  invitations, sends links through it too. Like the content checks, it's only listed when
  it finds one.

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

## Content

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

- **What the email says is left to the analyst.** There's no check on wording like
  "urgent" or "verify your account", or on what the email asks for, like gift cards or a
  bank transfer. The analyst reads the body anyway, and a list of phrases only knows
  English, misses a request worded another way, and flags ordinary mail: real work email
  is full of urgency, and invoices ask for bank transfers. The checks are for what the
  reader can't see, can't easily check, or can only see by linking it to something else,
  like where a link really goes or who owns an IP.

## Indicators

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
  The `xn--` form is written by the newer standard browsers follow (IDNA 2008), so
  `straße.de` is `xn--strae-oqa.de`. Python's own encoder, which turns it into
  `strasse.de`, a different domain, only writes what that standard refuses, like an emoji.
  The checks treat both forms as one domain, so `müller.de` in `settings.py` and
  `xn--mller-kva.de` in an email are the same, but their evidence shows a domain as the
  email wrote it, so `xn--pypal-4ve.com` can't pass for paypal.com.

- **The sender's domains and the origin are listed first**, since a long email can link to
  a dozen domains before them. An IP a check flags, like a faked Microsoft hop's, is listed
  too, even though the email didn't name it as one.

## Lookups

- **Nothing goes online without `--enrich`, and nothing is uploaded with it.** Every
  request is a GET for a report the service already has. Attachments are looked up by
  their SHA-256 hash: an uploaded file is shared with every VirusTotal customer, and it
  could hold your company's data. Scanning a URL takes a POST, which the tool never sends,
  so a URL VirusTotal hasn't seen just comes back as not found.

- **Not found means unknown, not clean.** A phishing domain registered yesterday has no
  history. Results are written plainly ("9 of 89 engines flagged it malicious") with the
  date VirusTotal last checked, since a page can turn malicious after a clean scan.
  Engines that timed out or don't scan that kind of file aren't counted.

- **An IP's network and country are context, not a check.** AbuseIPDB's answer names the
  network an IP belongs to and where it is (`Google LLC in US`), and the tool shows them
  with its reports, but nothing is flagged by country. Big providers send from their own
  servers wherever the sender is, attackers use servers near their targets and hacked
  accounts, and real mail passes through data centers abroad. Location is strong evidence
  in sign-in logs (two countries an hour apart), not in email. Whether AbuseIPDB lists the
  IP as trusted is shown too, since that's why a server like Google's 8.8.8.8 has hundreds
  of reports and 0% confidence.

- **A domain registered in the last 30 days is flagged.** Most phishing domains are used
  within days of being registered, and 30 days is a common cut-off for newly registered
  domains in mail and web filters. The date comes from VirusTotal's domain report, so it
  costs no extra lookup, and it's shown on each domain's line as well. A subdomain has its
  domain's date (`www.google.com` shows `google.com`'s). A name a hosting service handed
  out (`paypal-login.github.io`, `contoso.sharepoint.com`) only has the service's date,
  which says nothing about the site, so it isn't shown and the check is inconclusive for
  that name. The Public Suffix List's private section and `SHARED_HOSTING` tell these
  apart. An old domain counts too: a lookalike registered in 2004 is likelier to be a real
  business one letter from a brand (`netflux.com`), and no rule about spelling can tell
  that apart. So the check passes when every domain is older, with each one's date in the
  evidence, and is inconclusive when a domain has no date or wasn't looked up. It's medium
  strength, since real companies register new domains for campaigns too. Domains the
  lookalike and brand-joined checks flagged are looked up straight after attachments, so an
  email with many links can't push them past the limit. The brands' domains, webmail, your
  own, and names that aren't sent aren't in question.

- **A hop that calls itself a Microsoft server has to have a Microsoft IP.** Microsoft's
  Received headers give the name the sending server chose for itself, and the tool skips
  Microsoft's own relays by that name. So a sender calling itself `x.prod.outlook.com` is
  skipped too, and fake headers it adds below can be reported as the origin. The IP in that
  hop was written down by Microsoft's server, so it can't be faked. With `--enrich`, each
  hop taken as Microsoft's on its name is looked up in AbuseIPDB, whose answer names the
  IP's owner, and one that isn't Microsoft's (`microsoft.com`, or one of its mail domains
  like `outlook.com`) is flagged. It's very strong, and its reports are in the evidence.
  When every hop above it is Microsoft's, the first such hop is the server Microsoft
  really got the email from. When one above it couldn't be checked, that one could be, so
  it's named in a caveat. These IPs are only sent to AbuseIPDB, and only a faked one is
  listed as an indicator, since the rest are meant to be Microsoft's.

- **What would tell the service about your network or your people isn't sent.** Private
  and reserved IPs and internal names (`srv01.corp.local`) mean nothing outside your
  network. Neither are your own domains in `OWN_DOMAINS`: alert text can name your
  machines (`wks-0231.corp.contoso.com`), and VirusTotal can't tell you anything new about
  them. DNS's own `.arpa` names aren't sent either: they're never websites, and a reverse
  lookup in a DNS log (`5.0.168.192.in-addr.arpa`) has an IP in it, often a private one.
  That IP is listed on its own (192.168.0.5) and looked up if it's public. The part of a
  URL after `#` never reaches the website, and phishing kits put the reader's address
  there, so it's left off. A URL with an email address anywhere else, even encoded twice
  (`%2540`) inside a link it carries, isn't looked up at all, and its domain is looked up
  instead.

- **The limits decide the order.** VirusTotal's free key allows 4 lookups a minute and 500
  a day, so as shipped a run sends at most 8, waiting when it has to, and AbuseIPDB gets
  at most 10. A paid key's limits are set in `settings.py`. AbuseIPDB has no limit a
  minute, so its lookups go first and are done before any wait. For AbuseIPDB, the origin
  goes first, then the hops named as Microsoft's servers from the top down, so fake ones
  added below can't push the real sender's past the limit. For VirusTotal, attachments go
  first, then domains the lookalike and brand-joined checks flagged, the sender's domains,
  the domains links go to, the links, pictures, and IPs, which AbuseIPDB covers too. The
  sender's domains come before the links' because there are only one to three, and an
  email can link to a dozen domains and use up every lookup. Pictures are mostly logos,
  like the ones in an Outlook signature, and VirusTotal rarely has them. A picture is
  declared as one and named like one (`.png`, `.jpg`), so it opens in a picture viewer and
  can't run. An SVG can hold scripts, so it goes first with the other files. The brands'
  real domains, free webmail, and links to them go last. Anything past the limit is shown
  as skipped. A run only counts its own lookups, so one started straight after another can
  find VirusTotal's minute used up, and so can a run whose limit a minute is set higher
  than the key allows. It then waits a minute and tries once more, and if it's refused
  again, the day's limit was reached. When a key is refused, the day's limit is reached, a
  service can't be reached, or a proxy or sign-in page answers for it, the rest of its
  lookups show as unavailable without being sent. Ctrl+C during a wait does the same for
  both services, so the indicators are still shown, and a second Ctrl+C stops the tool.

- **With `--enrich`, the report prints once the lookups are done,** so the checks that need
  them sort in with the rest. Waits are said on stderr as they happen. A lookup missed for
  the whole run (over the limit, no key, or the service stopped) is said once, with how
  many indicators it covered, instead of under each one.

- **Found results are kept for a day** in your own cache folder
  (`%LOCALAPPDATA%\phishing-triage` on Windows, under `$XDG_CACHE_HOME` or `~/.cache`
  elsewhere), so running the tool again doesn't use up the limits. If none of these can
  be found, as in some stripped-down environments, nothing is kept and the tool says so.
  Not found isn't kept, and neither is a report no engine has checked yet, since either
  can change within the hour. Each entry is filed under a hash of what was sent, so the
  file isn't a readable list of what you've looked up, and the same campaign's link with
  each reader's address after `#` is only looked up once.

- **The keys come from environment variables**, never from a file in the repository, and
  are sent in a request header, never in the address, so they stay out of error messages
  and proxy logs, which record addresses. Redirects aren't followed, since the key header
  would go along to wherever one points.

## Future work

- A display name check on the Sender header, which Outlook shows as "Sender on behalf of
  From", and an Ambiguous Sender check like Ambiguous From
- Caveats that point out signs of a mailing list, like a DKIM signature from the Sender's
  domain, since lists break DMARC on real mail. They'd add context, not change a result
- An optional `--render` that hands the HTML to a headless browser with scripts off, in a
  container with no network, and compares what it shows with the tool's reading, so what
  CSS hides or adds becomes evidence instead of inconclusive
- Links inside attachments, like a PDF's, read in the same kind of container
- More lookup sources, still lookups only. With a third, `enrich.py` becomes a package
- Feeding the JSON to a ticket system or SOAR playbook, so a reported email gets its
  report without anyone running the tool
- Your settings in a file outside the package, so updating the tool can't clash with your
  changes, and your additions kept apart from the shipped lists
- Lookups in parallel, since with a paid key a run can make hundreds, and one at a time
  those can take minutes
