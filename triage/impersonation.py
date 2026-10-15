"""Checks for an email pretending to be a brand, your organization, or an executive."""

import functools
import re

from .domains import (base_domain, decode_idn, is_ip, lookalike_forms, normalize_unicode,
                      registered_name, url_host)
from .lists import BRANDS, EXECUTIVES, FREE_EMAIL_DOMAINS, OWN_DOMAINS, OWN_NAMES
from .models import Check, ParsedEmail, Result, Strength, join_first_five

# Shorter brand names are one letter from common words (apple/apply) and sit inside others
# (pineapple), so they skip the joined check and are only typo-checked on the registered
# name. A subdomain is free, so a phisher would write the real name there, not a typo.
LONG_NAME_LENGTH = 6

# Shorter names aren't typo-checked, since nearly every short word is one letter from another
# (meta: beta, mega). They're still caught spelled right or with lookalikes (m3ta.com).
MIN_TYPO_LENGTH = 5


def check_display_name(parsed: ParsedEmail) -> Check:
    name, strength = "Display name", Strength.MEDIUM
    if not parsed.from_addr:
        return Check(name, Result.INCONCLUSIVE, strength, "No readable From address")
    if not parsed.from_addr.display_name:
        return Check(name, Result.PASS, strength, "No display name")

    display = parsed.from_addr.display_name
    # The whole address when there's no domain to show (From: "PayPal" <support>)
    domain = parsed.from_addr.domain or parsed.from_addr.email
    base = base_domain(parsed.from_addr.domain)
    display_forms = lookalike_forms(display)
    hits = []

    # A display name like "security@paypal.com" hides the real address in many clients.
    # Normalized first, which also catches a fullwidth ＠.
    for addr_domain in re.findall(r"@([\w-]+(?:\.[\w-]+)+)", normalize_unicode(display)):
        if base_domain(addr_domain) != base:
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

    own_domains = {base_domain(d) for d in OWN_DOMAINS}
    for executive in sorted(EXECUTIVES):
        # Each part as its own word: "Sarah Chen (CEO)" and "Chen, Sarah" both match.
        name_found = any(_has_words(form, executive_form) for form in display_forms
                         for executive_form in _name_forms(executive))
        if name_found and base not in own_domains:
            hits.append(f"uses executive {executive}'s name but the mail is from {domain}, outside your organization's domains")

    if hits:
        return Check(name, Result.FLAG, strength, f'"{display}" ' + "; ".join(hits))
    return Check(name, Result.PASS, strength, f'"{display}" doesn\'t show another address or claim a brand or executive it isn\'t from')


def check_lookalike(parsed: ParsedEmail) -> Check:
    name, strength = "Lookalike domain", Strength.STRONG
    hits, flagged = [], []
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
                continue
            hits.append(f"{label} {hit}")
            flagged.append(display_domain)
            reported.append(target_domains)

    if hits:
        return Check(name, Result.FLAG, strength, join_first_five(hits), domains=list(dict.fromkeys(flagged)))
    return Check(name, Result.PASS, strength, "No sender or link domain resembles a brand or your own domains")


def check_brand_joined(parsed: ParsedEmail) -> Check:
    # paypalsecure.com and mypaypal.com. Weak, not part of the lookalike check, because
    # brands own domains like this too (googleapis.com, paypalobjects.com).
    name, strength = "Brand joined to a word", Strength.WEAK
    hits, flagged = [], []
    targets = [(target, domains, {k for k in _name_forms(target.replace(" ", "")) if len(k) >= LONG_NAME_LENGTH})
               for target, domains in _impersonation_targets()]
    for label, display_domain, base in _unlisted_domains(parsed):
        # Split on dashes only. Joining them back would flag paypal-secure.com here as well.
        name_words = {word for form in lookalike_forms(registered_name(base)) for word in form.split("-")}
        reported = []  # one hit per organization
        for target, target_domains, keywords in targets:
            if target_domains in reported or not keywords:
                continue
            # The name on its own (paypal-secure.com) is the lookalike check's job
            if any(keyword in word for keyword in keywords for word in name_words if word not in keywords):
                hits.append(f"{label} has '{target}' joined to another word but isn't {_main_domain(target, target_domains)}")
                flagged.append(display_domain)
                reported.append(target_domains)

    if hits:
        return Check(name, Result.FLAG, strength, join_first_five(hits), domains=list(dict.fromkeys(flagged)))
    return Check(name, Result.PASS, strength, "No sender or link domain has a brand joined to another word")


def _impersonation_targets() -> list[tuple[str, list[str]]]:
    if not OWN_DOMAINS:
        return list(BRANDS.items())
    # Base domains, so mail.contoso.com still matches contoso.com. Repeats are dropped in
    # order, so the main one stays first.
    own_domains = list(dict.fromkeys(base_domain(d) for d in OWN_DOMAINS))
    # Owning contosocorp.com makes contosocorp.net a lookalike, even if your name is "contoso"
    names = sorted(n.lower() for n in OWN_NAMES) + [registered_name(d) for d in own_domains]
    # Every name gets the same domain list, so the checks treat them as one organization
    return list(BRANDS.items()) + [(name, own_domains) for name in dict.fromkeys(names)]


def _main_domain(target: str, target_domains: list[str]) -> str:
    # The real domain to name in the evidence: the one spelled like the name (instagram.com
    # for "instagram", in Meta's shared list), or else the first, which is the main domain
    keyword = target.replace(" ", "")
    return next((d for d in target_domains if registered_name(d) == keyword), target_domains[0])


def _unlisted_domains(parsed: ParsedEmail) -> list[tuple[str, str, str]]:
    # Sender and link domains that aren't a target's or free webmail, as (label, domain as
    # displayed, base domain). Links matter, since mail from a hacked account has a normal sender.
    found_in = {}
    for a in [parsed.from_addr, *parsed.reply_to]:
        if a and a.domain:
            found_in.setdefault(a.domain, set()).add("sender")
    for link in parsed.links:
        link_host = url_host(link.href)
        if link_host and not is_ip(link_host):
            found_in.setdefault(link_host, set()).add("link")

    owned_domains = {d for _, domains in _impersonation_targets() for d in domains}
    unlisted = []
    for domain in sorted(found_in):
        # The domain as the reader sees it: xn--pypal-4ve.com shows as pаypal.com
        display_domain = decode_idn(domain)
        base = base_domain(display_domain)
        # Free webmail domains are real providers, not lookalikes, and have their own check
        if base in owned_domains or base in FREE_EMAIL_DOMAINS:
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
    checked = words if len(keyword) >= LONG_NAME_LENGTH else name_words
    typos_checked = len(keyword) >= MIN_TYPO_LENGTH
    return any(word == keyword or (typos_checked and _one_typo_apart(word, keyword)) for word in checked)


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
    # names only come from lists.py and every domain in the email is compared with them. Doing
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
