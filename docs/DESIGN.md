# Design decisions

## Results and safety

- **No phishing score or verdict.** A weighted number would need labeled data to
  calibrate, and the checks overlap: one lookalike domain like `paypa1.com` trips the
  display name, lookalike, and link checks at once, so adding them up counts the same fact
  three times. The tool lists what it found, and the analyst decides.

- **Every check ends as flag, pass, or inconclusive, with a fixed strength.** Inconclusive
  means the check couldn't tell, like DKIM on a message with no signature, and it's never
  a pass with a doubt attached. The strength says how much a flag matters: very strong is
  for what no known legitimate sender does, like two From headers, and strong for what
  real mail does now and then, like a mailing list breaking DMARC.

- **Evidence, caveats, and warnings each have one job.** The evidence is why a check got
  its result. A caveat is something close to it the analyst should look at whatever the
  result, and it's never the reason for it. A warning is about the tool's reading: part of
  the email couldn't be read, like an unknown charset or an attached email, so it needs
  checking by hand.

- **At most five of anything a sender can repeat are named,** with a count of the rest, so
  padding an email with thousands of headers or links can't bury the findings. Warnings
  are grouped by kind rather than cut off at a number, so a flood of one kind can't push
  out another. Indicators and attachments are listed in full, since each may need blocking
  or checking.

- **The report puts flags first, strongest first,** then inconclusive checks, then passes.
  The summary's strongest flag isn't a score: two weak flags don't add up to a medium one,
  since they can be the same fact seen twice.

- **Patterns name findings that mean more together than apart.** A lookalike domain that
  passes DMARC only shows the attacker set up their own domain, and an authenticated
  sender with a lookalike link may be a hacked account, which changes who to tell. Each
  combines findings about different facts, a pattern never changes a result, and the
  section only appears when one matches, since "no patterns" would read as reassurance.

- **Text from the email can't change how the report looks.** Control, invisible, and
  line-breaking characters are shown as codes, so a right-to-left override can't show
  `invoice<RLO>fdp.exe` as `invoiceexe.pdf`, and a newline in the Subject can't add a fake
  result line. Long text is cut in the middle, since the end often matters most, and a
  display name is cut apart from its address, so padding in the name can't push the
  address out of sight.

- **The note is written for a ticket.** It follows the usual triage note, with follow-ups
  worded as suggestions and blank fields for the analyst's verdict, which the tool never
  fills in. Every value from the email or a lookup is in a code span and defanged, so it
  can't make a link, an image, or formatting, whether the ticket system reads Markdown or
  not.

- **The follow-ups are picked from what was found**, so the analyst edits a list instead
  of writing one. Only lookalike and newly registered domains are suggested for blocking,
  since they're likely the attacker's own, and blocking a spoofed or shared domain would
  cut off real senders. They're picked from results, flagged domains, and pattern names,
  never from evidence, which is written for people to read.

- **The JSON keeps values exactly as found**, since a tool that blocks or searches needs
  the real URL, with each indicator's defanged form next to it. It's plain ASCII, with
  anything else escaped, and a `format` number says when a field is renamed, removed, or
  changes type.

- **Files are written whole or not at all,** and a note can't be written over the email
  it's about, since that's the evidence. If one can't be written, the full report prints
  in the terminal instead, so a run that waited on lookups isn't lost.

- **Nothing in the email is opened.** Attachments are hashed in memory and never written
  to disk. HTML is read as text to pull out links, never rendered, so tracking pixels
  don't load and links aren't visited.

## Headers and origin

- **Only the topmost Authentication-Results header is trusted.** Your mail provider adds
  it on top. Anything below was already in the message when it arrived, so the sender
  could have written it, including a fake `dmarc=pass`. If your provider might not add
  one, list its server in `TRUSTED_AUTHSERV_IDS` and only headers from it count, as
  RFC 8601 recommends. Return-Path can't be trusted by position, since not every provider
  puts theirs on top, so with more than one, that check is inconclusive.

- **When SPF or DMARC reports more than one result, the worst one counts.** Each gives one
  result per message, so an extra one means someone added text to the header, and an
  attacker can add a fake pass but can't remove a real fail.

- **A pass only counts for the From the reader sees.** A DKIM signature has to be from the
  From domain's organization, since anyone can sign mail with their own domain. A DMARC
  pass has to name the From domain the tool shows, since with two From addresses a
  provider can check one while the mail client shows the other.

- **A From that can be read more than one way is a very strong flag.** Two From headers,
  two addresses in one, or encoded text in the address let a mail client show a different
  From than the one DMARC checked, which researchers used to get past DMARC at large
  providers ("Composition Kills", 2020). Since clients don't agree on which From they
  show, every check that compares the From runs on each one: a flag on any counts, and a
  pass needs all of them.

- **The Sender header is shown and its domain checked, but it isn't compared with the
  From.** Outlook shows it as "Sender on behalf of From", but mailing lists and assistants
  set it on ordinary mail, and DMARC doesn't read it, so a Sender that isn't the From
  isn't flagged.

- **Encoded text is only decoded where it's allowed.** Python's email library decodes
  `=?utf-8?q?...?=` anywhere in a header, but it's only allowed in text like the Subject.
  Authentication-Results copies text the sender chose, like the envelope address, and
  decoding the valid address `=?utf-8?q?x=3Bdkim=3Dpass?=@evil.com` there adds a fake DKIM
  pass, while `service@=?utf-8?q?paypal=2Ecom?=` in a From reads as paypal.com. So these
  are read as written, along with what mail clients hit by the Mailsploit bugs show, and
  in a From address that's a flag.

- **The originating server comes from the receiver's reverse DNS lookup, not the name the
  sender claims.** The sender can claim to be `mx.google.com`, and hops below the handoff
  are shown as claims, since they could be forged.

## Lookalikes and links

- **Domains are compared by the part one owner controls, using the Public Suffix List.**
  `mail.paypal.com` and `paypal.com` are one organization, while `paypal-login.github.io`
  and `my-blog.github.io` aren't. A copy ships with the tool, so it works offline, and
  it's only updated when you run `python -m triage.update_suffixes`, since updating itself
  would mean going online without being asked. The tool notes when the copy is over 6
  months old.

- **Lookalike domains are matched word by word, not with a similarity percentage.** The
  domain is split on dots and dashes, lookalike characters are swapped back (`0` to `o`,
  Cyrillic `а` to `a`), and each word is compared to the brand name: an exact match or one
  typo. Comparing whole domains missed the same typo on another TLD (`paypa1.xyz`) or in a
  subdomain, and "one typo" is easier to defend than a percentage picked by testing.

- **Short brand names are checked against an English word list.** A name under six letters
  is one letter from ordinary words (apple: apply) and sits inside others (pineapple), so
  spelling alone can't tell a lookalike from a word. A typo that isn't a word
  (`appie.com`) is flagged, and one that is (`appel.com`) is inconclusive, since it can be
  a typosquat or harmless. The list, ENABLE, is public domain and ships with the tool, so
  it works offline, and `ALLOWED_NAMES` passes newer words it lacks.

- **Links are read the way a browser and mail client show them.** Python's URL parser
  disagrees with browsers in ways phishers use: a browser treats `\` as `/`, so
  `http://evil.com\@paypal.com` goes to evil.com while Python reads paypal.com, and a
  numeric host like `http://3627734532/` opens an IP that Python's `ipaddress` refuses.
  Links are found the way a client shows them, including a `<base href>` and Outlook-only
  `<!--[if mso]>` blocks, and a link's text is read with and without the parts a browser
  hides, so a mistake either way can't hide a domain.

- **A link rewritten by a mail security service is read as where it really goes.** Safe
  Links and Proofpoint rewrite every link in delivered mail, and phishing puts links
  behind Google's redirect so they start with google.com. The tool reads the real link out
  of each, even when one wraps another, and the checks, the indicators, and `--enrich` all
  use it. Only the services' own hosts are read, so
  `safelinks.protection.outlook.com.evil.com` is checked as the link it is. A link the
  sender put behind Google's redirect is also a weak flag, since a filter that judges a
  link by where it points sees google.com. It's weak because Google's own mail, like
  Calendar invitations, uses the redirect too.

- **Where CSS could change what a link shows, the tool says it can't tell instead of
  guessing.** It reads a tag's own `style` but not `<style>` blocks: working those out
  means selectors, the cascade, and `@media`, and every rule handled leaves another way
  around it. So a tag in the middle of a domain in a link's text (`pay<b>pal</b>.com`)
  makes the link check inconclusive instead of a pass, since a pass would promise more
  than the tool knows.

- **Links that don't open a web page or an email are flagged**, checked against a short
  list of safe types (`https:`, `mailto:`, `tel:`) rather than a list of bad ones, so a
  new trick isn't missed. That covers `javascript:`, file shares, and Windows programs
  like `search-ms:` that phishing has used to run malware. Outlook for Windows opens a
  file share link over SMB, and Windows can send the reader's sign-in hash to that server.

## Content

- **Hidden text is only flagged inside a word.**
  `Mic<span style="font-size:0">xyz</span>rosoft` shows Microsoft to the reader while a
  filter reads "Micxyzrosoft" (the ZeroFont trick). Hidden text on its own isn't flagged,
  because nearly every marketing email hides a preview line at the top for the inbox list.

- **An email that's only an image is flagged**, since text in a picture or a QR code can't
  be read by filters or by this tool. **Text added by CSS** is flagged for the same
  reason, but only as weak, since templates add small decorations that way too.

- **These content checks only appear when they find something.** An email with no hidden
  text isn't safer for it, so a pass would read as reassurance the check can't give.

- **What the email says is left to the analyst.** There's no check on wording like
  "urgent" or "verify your account", or on requests like gift cards or a bank transfer. A
  list of phrases only knows English, misses a request worded another way, and flags
  ordinary mail: real work email is full of urgency, and invoices ask for bank transfers.
  The checks are for what the reader can't see, can't easily check, or can only see by
  linking it to something else.

## Indicators

- **From an email, only what it links to, loads, or came from is listed.** Phishing names
  the real brand's domain to look genuine ("log in at paypal.com"), so a domain or IP only
  mentioned in the text isn't listed, since blocking it would be a mistake. Alert text is
  different: tools and analysts write bare domains, IPs, and hashes there, so those count.

- **Indicators are defanged on the way out and refanged on the way in.**
  `hxxps://evil[.]com` can't turn into a live link when pasted into a ticket or a chat,
  and alert text that arrives defanged is turned back before it's searched.

- **URLs and domains are listed the way the browser asks for them**, with the host in the
  `xn--` form that DNS, proxy logs, and blocklists use. Defanged, a Cyrillic
  `pаypal[.]com` looks just like the real one (an IDN homograph), and
  `xn--pypal-4ve[.]com` doesn't. The `xn--` form follows IDNA 2008, as browsers do, since
  Python's own encoder turns `straße.de` into `strasse.de`, a different domain.

- **The sender's domains and the origin are listed first**, since a long email can link to
  a dozen domains before them.

## Lookups

- **Nothing goes online without `--enrich`, and nothing is uploaded with it.** Every
  request is a GET for a report the service already has. Attachments are looked up by
  their SHA-256 hash: an uploaded file is shared with every VirusTotal customer, and it
  could hold your company's data.

- **Not found means unknown, not clean.** A phishing domain registered yesterday has no
  history. Results are written plainly ("9 of 89 engines flagged it malicious") with the
  date VirusTotal last checked, since a page can turn malicious after a clean scan.

- **An IP's network and country are context, not a check.** Big providers send from their
  own servers wherever the sender is, attackers use servers near their targets and hacked
  accounts, and real mail passes through data centers abroad. Location is strong evidence
  in sign-in logs (two countries an hour apart), not in email.

- **A domain registered in the last 30 days is flagged.** Most phishing domains are used
  within days of being registered, and 30 days is a common cut-off for newly registered
  domains in mail and web filters. It's medium strength, since real companies register new
  domains for campaigns too. A name a hosting service handed out
  (`paypal-login.github.io`) only has the service's date, which says nothing about the
  site, so the check is inconclusive for it.

- **A hop that calls itself a Microsoft server has to have a Microsoft IP.** The tool
  skips Microsoft's own relays by the name the sending server gives itself, so a sender
  calling itself `x.prod.outlook.com` is skipped too, and fake headers it adds below can
  be reported as the origin. The IP in that hop was written down by Microsoft's server, so
  it can't be faked. With `--enrich` it's looked up in AbuseIPDB, and one whose owner
  isn't Microsoft is flagged as very strong and listed as an indicator.

- **What would tell the service about your network or your people isn't sent.** Private
  IPs and internal names mean nothing outside your network. Your own domains in
  `OWN_DOMAINS` and names under them aren't sent either: alert text can name your machines
  (`wks-0231.corp.contoso.com`), and VirusTotal can't tell you anything new about them.
  The part of a URL after `#` never reaches the website, and phishing kits put the
  reader's address there, so it's left off. A URL with an email address anywhere else
  isn't looked up at all, and its domain is looked up instead.

- **The limits decide the order.** VirusTotal's free key allows 4 lookups a minute and 500
  a day, so as shipped a run sends at most 8, and AbuseIPDB at most 10. For VirusTotal,
  what matters most goes first, so a long email can't push it past the limit: attachments,
  then domains the lookalike checks flagged, then the sender's domains, then links. The
  brands' real domains and free webmail go last. Anything past the limit is shown as
  skipped.

- **With `--enrich`, the report prints once the lookups are done,** so the checks that
  need them sort in with the rest. A lookup missed for the whole run (over the limit, no
  key, or the service stopped) is said once, instead of under each indicator.

- **Found results are kept for a day** in your own cache folder, so running the tool again
  doesn't use up the limits. Not found isn't kept, since it can change within the hour,
  and each entry is filed under a hash of what was sent, so the file isn't a readable list
  of what you've looked up.

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
