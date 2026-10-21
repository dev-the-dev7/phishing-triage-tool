"""Checks for an email pretending to be a brand, your organization, or an executive."""

import functools
import re
from pathlib import Path

from .domains import (base_domain, decode_idn, decoded_base, is_ip, lookalike_forms, normalize_unicode,
                      registered_name, url_host)
from .models import Address, Check, ParsedEmail, Result, Strength, for_each_from, join_first_five
from .settings import ALLOWED_NAMES, BRANDS, EXECUTIVES, FREE_EMAIL_DOMAINS, JOIN_WORDS, OWN_DOMAINS, OWN_NAMES

# Shorter brand names are one letter from ordinary words (apple: apply) and sit inside others
# (pineapple), so an English word list decides what a typo or joined word means. They're
# only typo-checked on the registered name, since a subdomain is free and a phisher would
# write the real name there.
LONG_NAME_LENGTH = 6

# Shorter names aren't typo-checked or looked for inside words, since one letter from them,
# or a word holding them, is almost any short label (ibm: ibn, ibmx). They're still caught
# spelled right or with lookalikes.
MIN_NAME_LENGTH = 4

# ENABLE, an English word list in the public domain
WORDS_FILE = Path(__file__).with_name("english_words.txt")


def check_display_name(parsed: ParsedEmail) -> Check:
    return for_each_from(parsed.from_addrs, _check_display_name)


def _check_display_name(from_addr: Address | None) -> Check:
    name, strength = "Display name", Strength.MEDIUM
    if not from_addr:
        return Check(name, Result.INCONCLUSIVE, strength, "No readable From address")
    if not from_addr.display_name:
        return Check(name, Result.PASS, strength, "No display name")

    display = from_addr.display_name
    # The whole address when there's no domain to show (From: "PayPal" <support>)
    domain = from_addr.domain or from_addr.email
    base = decoded_base(from_addr.domain)
    display_forms = lookalike_forms(display)
    hits = []

    # A display name like "security@paypal.com" hides the real address in many clients.
    # Normalized first, which also catches a fullwidth ＠.
    for addr_domain in re.findall(r"@([\w-]+(?:\.[\w-]+)+)", normalize_unicode(display)):
        if decoded_base(addr_domain) != base:
            hits.append(f'shows an address at {addr_domain} but the mail is from {domain}')

    reported = []  # one hit per organization
    for target, target_domains in _impersonation_targets():
        if target_domains in reported or base in target_domains:
            continue
        if _mentions(display, target):
            hits.append(f'mentions "{target}" but the mail is from {domain}')
        elif any(_mentions(form, target_form) for form in display_forms for target_form in _name_forms(target)):
            hits.append(f'spells "{target}" with lookalike characters but the mail is from {domain}')
        else:
            continue
        reported.append(target_domains)

    own_domains = _own_domains()
    for executive in sorted(EXECUTIVES):
        # Each part as its own word: "Sarah Chen (CEO)" and "Chen, Sarah" both match.
        name_found = any(_has_words(form, executive_form) for form in display_forms
                         for executive_form in _name_forms(executive))
        if name_found and base not in own_domains:
            hits.append(f"uses executive {executive}'s name but the mail is from {domain}, outside your "
                        "organization's domains")

    if hits:
        return Check(name, Result.FLAG, strength, f'"{display}" ' + "; ".join(hits))
    return Check(name, Result.PASS, strength,
                 f'"{display}" doesn\'t show another address or claim a brand or executive it isn\'t from')


def check_lookalike(parsed: ParsedEmail) -> Check:
    name, strength = "Lookalike domain", Strength.STRONG
    hits, unsure, flagged = [], [], []
    targets = [(target, domains, _main_domain(target, domains)) for target, domains in _impersonation_targets()]
    # A word more than one letter longer than every name can't equal one or be a typo of one
    max_length = max(len(form) for t, _, _ in targets for form in _name_forms(t.replace(" ", ""))) + 1
    for label, display_domain, base in _unlisted_domains(parsed):
        # The TLD can't hold a lookalike, and without it a brand's own TLD (applecard.apple)
        # doesn't match its name
        suffix = base.partition(".")[2]
        name_part = display_domain.removesuffix("." + suffix)
        forms = lookalike_forms(name_part)
        # Words are compared, not whole domains, so changing the TLD (paypa1.xyz) or
        # moving the brand into a subdomain (paypa1.com.evil.net) doesn't hide it.
        words = {word for form in forms for word in _domain_words(form, max_length)}
        name_words = {word for form in lookalike_forms(registered_name(base))
                      for word in _domain_words(form, max_length)}
        # The part in front of the registered domain, which its owner can set to anything:
        # login.microsoftonline.com.evil.net gives login.microsoftonline.com
        subdomains = display_domain.rstrip(".").removesuffix(base).removesuffix(".")
        # One hit per organization, since "microsoft" and "office 365" share their domains
        reported = []
        for target, target_domains, main_domain in targets:
            if target_domains in reported:
                continue
            # Without spaces, as in a domain, so "ken nelson" gives kemelson like kennelson.com
            keywords = _name_forms(target.replace(" ", ""))
            # A real domain in front of someone else's is the clearest evidence, and catches
            # real domains that aren't the name (microsoftonline.com)
            real_domain = next((d for d in target_domains if _whole_name_pattern(d).search(subdomains)), None)
            if real_domain:
                hit = f"puts the real domain {real_domain} in front of {base}"
            elif _whole_name_pattern(target).search(name_part):
                hit = f"contains '{target}' but isn't {main_domain}"
            elif any(_whole_name_pattern(target_form).search(form) for target_form in _name_forms(target)
                     for form in forms):
                hit = f"spells '{target}' with lookalike characters but isn't {main_domain}"
            elif any(_typo_or_equal(keyword, words, name_words) for keyword in keywords):
                hit = f"has a typo of '{target}' but isn't {main_domain}"
            else:
                english = sorted({word for keyword in keywords for word in _english_typos(keyword, name_words)})
                if english:
                    unsure.append(f"{label} is one letter from '{target}', but '{english[0]}' is also an English word")
                continue
            hits.append(f"{label} {hit}")
            flagged.append(display_domain)
            reported.append(target_domains)

    by_hand = f"{join_first_five(unsure)}. A name that short is one letter from many words, so check it by hand."
    if hits:
        return Check(name, Result.FLAG, strength, join_first_five(hits), [by_hand] if unsure else [],
                     domains=list(dict.fromkeys(flagged)))
    if unsure:
        return Check(name, Result.INCONCLUSIVE, strength, by_hand)
    return Check(name, Result.PASS, strength, "No sender or link domain resembles a brand or your own domains")


def check_brand_joined(parsed: ParsedEmail) -> Check:
    # paypalsecure.com and mypaypal.com. Weak, not part of the lookalike check, because
    # brands own domains like this too (googleapis.com, paypalobjects.com).
    name, strength = "Brand joined to a word", Strength.WEAK
    hits, unsure, flagged = [], [], []
    targets = []
    for target, domains in _impersonation_targets():
        forms = _name_forms(target.replace(" ", ""))
        targets.append((target, domains, {k for k in forms if len(k) >= LONG_NAME_LENGTH},
                        {k for k in forms if MIN_NAME_LENGTH <= len(k) < LONG_NAME_LENGTH}))
    for label, display_domain, base in _unlisted_domains(parsed):
        # Split on dashes only. Joining them back would flag paypal-secure.com here as well.
        name_words = {word for form in lookalike_forms(registered_name(base)) for word in form.split("-")}
        reported = []  # one hit per organization
        for target, target_domains, long_forms, short_forms in targets:
            if target_domains in reported:
                continue
            # The name on its own (paypal-secure.com) is the lookalike check's job
            if any(keyword in word for keyword in long_forms for word in name_words if word not in long_forms):
                result = Result.FLAG
            else:
                result = _short_name_joined(short_forms, name_words)
            if result == Result.FLAG:
                hits.append(f"{label} has '{target}' joined to another word but isn't "
                            f"{_main_domain(target, target_domains)}")
                flagged.append(display_domain)
                reported.append(target_domains)
            elif result == Result.INCONCLUSIVE:
                unsure.append(f"{label} has '{target}' inside a word that isn't in the word list")

    by_hand = f"{join_first_five(unsure)}. A name that short is often part of a real name, so check it by hand."
    if hits:
        return Check(name, Result.FLAG, strength, join_first_five(hits), [by_hand] if unsure else [],
                     domains=list(dict.fromkeys(flagged)))
    if unsure:
        return Check(name, Result.INCONCLUSIVE, strength, by_hand)
    return Check(name, Result.PASS, strength, "No sender or link domain has a brand joined to another word")


def _short_name_joined(keywords: set[str], name_words: set[str]) -> Result | None:
    # Only a word phishers use makes it a flag (appleid, mymeta). Any other word that isn't
    # English could be a real name (applebees), so it's inconclusive.
    found = None
    for keyword in keywords:
        for word in name_words:
            if keyword not in word or word in keywords or _ordinary(word):
                continue
            start = word.find(keyword)
            while start >= 0:
                if all(not part or part in JOIN_WORDS for part in (word[:start], word[start + len(keyword):])):
                    return Result.FLAG
                found = Result.INCONCLUSIVE
                start = word.find(keyword, start + 1)
    return found


def _ordinary(word: str) -> bool:
    return word in ALLOWED_NAMES or word in _english_words()


@functools.cache
def _english_words() -> frozenset[str]:
    # Read only when a short name needs it, since most emails never do
    return frozenset(WORDS_FILE.read_text(encoding="ascii").split())


def _impersonation_targets() -> list[tuple[str, list[str]]]:
    # Decoded like the email's domains, so settings.py can write xn--mller-kva.de or müller.de
    brands = [(name, [decode_idn(d) for d in domains]) for name, domains in BRANDS.items()]
    own_domains = _own_domains()
    if not own_domains:
        return brands
    # Owning contosocorp.com makes contosocorp.net a lookalike, even if your name is "contoso"
    names = sorted(n.lower() for n in OWN_NAMES) + [registered_name(d) for d in own_domains]
    # Every name gets the same domain list, so the checks treat them as one organization
    return brands + [(name, own_domains) for name in dict.fromkeys(names)]


def _own_domains() -> list[str]:
    # Base domains, so mail.contoso.com still matches contoso.com. Repeats are dropped in
    # order, so the main one stays first.
    return list(dict.fromkeys(decoded_base(d) for d in OWN_DOMAINS))


def _main_domain(target: str, target_domains: list[str]) -> str:
    # The real domain to name in the evidence: the one spelled like the name (instagram.com
    # for "instagram", in Meta's shared list), or else the first, which is the main domain
    keyword = target.replace(" ", "")
    return next((d for d in target_domains if registered_name(d) == keyword), target_domains[0])


def _unlisted_domains(parsed: ParsedEmail) -> list[tuple[str, str, str]]:
    # The From, Sender, Reply-To and link domains that aren't a target's or free webmail, as
    # (label, domain as displayed, base domain). Links matter, since mail from a hacked account
    # comes from a normal address.
    found_in = {}
    for a in [*parsed.from_addrs, *parsed.sender, *parsed.reply_to]:
        if a.domain:
            found_in.setdefault(a.domain, set()).add("sender")
    for link in parsed.links:
        link_host = url_host(link.href)
        if link_host and not is_ip(link_host):
            found_in.setdefault(link_host, set()).add("link")

    owned_domains = {d for _, domains in _impersonation_targets() for d in domains}
    free_webmail = {decode_idn(d) for d in FREE_EMAIL_DOMAINS}
    unlisted = []
    for domain in sorted(found_in):
        # The domain as the reader sees it: xn--pypal-4ve.com shows as pаypal.com
        display_domain = decode_idn(domain)
        base = base_domain(display_domain)
        # Free webmail domains are real providers, not lookalikes, and have their own check
        if base in owned_domains or base in free_webmail:
            continue
        label = domain if display_domain == domain else f"{domain} (displays as {display_domain})"
        label += f" [{', '.join(sorted(found_in[domain]))}]"
        unlisted.append((label, display_domain, base))
    return unlisted


def _mentions(text: str, name: str) -> bool:
    # The name's words in order, each a whole word. They can be joined by a space, dot,
    # dash, underscore, or nothing: WellsFargo, Wells-Fargo
    pattern = r"[\s._-]*".join(re.escape(word) for word in name.split())
    return re.search(rf"\b{pattern}\b", text, re.I) is not None


def _has_words(text: str, name: str) -> bool:
    return all(re.search(rf"\b{re.escape(word)}\b", text) for word in name.split())


def _typo_or_equal(keyword: str, words: set[str], name_words: set[str]) -> bool:
    # Equal counts too, for a dash in the wrong place: pay-pal becomes paypal
    if len(keyword) >= LONG_NAME_LENGTH:
        return any(word == keyword or _one_typo_apart(word, keyword) for word in words)
    # An English word one letter from a short name could be a typo or just the word (appel,
    # apply), so it doesn't count here
    return any(word == keyword or (_short_typo(word, keyword) and not _ordinary(word)) for word in name_words)


def _english_typos(keyword: str, name_words: set[str]) -> list[str]:
    # English words one letter from a short name, for the analyst to judge
    if len(keyword) >= LONG_NAME_LENGTH:
        return []
    return [word for word in name_words
            if _short_typo(word, keyword) and word not in ALLOWED_NAMES and word in _english_words()]


def _short_typo(word: str, keyword: str) -> bool:
    return len(keyword) >= MIN_NAME_LENGTH and _one_typo_apart(word, keyword)


def _domain_words(domain: str, max_length: int) -> list[str]:
    # In each part between dots, every run of dash-separated pieces, joined: wells-farqo-login
    # gives wells, farqo, login, wellsfarqo, farqologin and wellsfarqologin. Runs past
    # max_length can't match a name, and skipping them keeps thousands of dashes quick.
    words = []
    for part in domain.split("."):
        # Empty pieces (from "--") are dropped so every piece makes the run longer
        pieces = [p for p in part.split("-") if p]
        for start in range(len(pieces)):
            for end in range(start + 1, len(pieces) + 1):
                run = "".join(pieces[start:end])
                if len(run) > max_length:
                    break
                words.append(run)
    return words


@functools.cache
def _name_forms(name: str) -> frozenset[str]:
    # A name's lookalike spellings. These and the patterns below are worked out once, since the
    # names only come from settings.py and every domain in the email is compared with them. Doing
    # it for each domain took 14 seconds for 20,000.
    return frozenset(lookalike_forms(name))


@functools.cache
def _whole_name_pattern(target: str) -> re.Pattern:
    # The name as its own word, with all its words in order. They can be joined by a dash
    # (wells-fargo) or a dot, since a free subdomain can supply the first word: wells.fargo-alerts.com
    return re.compile(r"(^|[.-])" + "[.-]?".join(re.escape(w) for w in target.split()) + r"($|[.-])")


def _one_typo_apart(a: str, b: str) -> bool:
    # One letter wrong, two neighbors swapped, one added, or one missing
    if len(a) == len(b):
        diffs = [i for i in range(len(a)) if a[i] != b[i]]
        if len(diffs) == 1:
            return True
        if len(diffs) == 2:
            i, j = diffs
            return j == i + 1 and a[i] == b[j] and a[j] == b[i]
        return False
    if abs(len(a) - len(b)) != 1:
        return False
    shorter, longer = sorted((a, b), key=len)
    return any(longer[:i] + longer[i + 1:] == shorter for i in range(len(longer)))
