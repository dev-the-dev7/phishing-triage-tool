"""Checks that the sender headers add up: SPF/DKIM/DMARC, one clear From, Reply-To, Return-Path,
free webmail."""

import re
from collections.abc import Callable
from dataclasses import replace

from ..domains import base_domain, decode_idn, decoded_base
from ..models import Address, Check, ParsedEmail, Result, Strength, describe_encoded_addresses, join_first_five
from ..settings import FREE_EMAIL_DOMAINS, TRUSTED_AUTHSERV_IDS


# Results that count as a failure. Others besides pass (none, neutral, temperror) are
# inconclusive: not a failure, but not verified either.
AUTH_FAILURES = ("fail", "softfail", "permerror")

# A check that compares the From runs once for each From address. Real mail has one, and on
# thousands the Reply-To check alone would take minutes.
MAX_FROMS = 10


def check_spf(parsed: ParsedEmail) -> Check:
    # About the envelope sender, not the From, and medium because forwarding breaks it
    results, source, cut_short = _trusted_results(parsed)
    return _no_pass_if(cut_short, _check_single_result("SPF", results.get("spf", []), Strength.MEDIUM, source))


def check_dkim(parsed: ParsedEmail) -> Check:
    # Medium, since mailing lists break it
    results, source, cut_short = _trusted_results(parsed)
    return _no_pass_if(cut_short, for_each_from(parsed.from_addrs, lambda from_addr: _check_dkim(
        results.get("dkim", []), parsed.dkim_signatures, from_addr, source)))


def check_dmarc(parsed: ParsedEmail) -> Check:
    # Strong, as the one that ties authentication to the From domain the reader sees
    results, source, cut_short = _trusted_results(parsed)
    return _no_pass_if(cut_short, for_each_from(parsed.from_addrs, lambda from_addr: _check_dmarc(
        results.get("dmarc", []), from_addr, source)))


def _trusted_results(parsed: ParsedEmail) -> tuple[dict[str, list[tuple[str, str]]], str, bool]:
    if TRUSTED_AUTHSERV_IDS:
        # Only headers from your provider's servers count, as RFC 8601 recommends,
        # since anyone can write this header
        trusted_ids = {i.lower() for i in TRUSTED_AUTHSERV_IDS}
        trusted = [h for h in parsed.auth_results if _parse_auth_results(h)[0].lower() in trusted_ids]
    else:
        # Only the topmost header was added by your own provider. Anything below it was
        # already in the message when it arrived, so the sender could have written it.
        trusted = parsed.auth_results[:1]

    cut_short = False
    if trusted:
        authserv_id, results, cut_short = _parse_auth_results(trusted[0])
        source = f"from {authserv_id}"
        if cut_short:
            # The sender's text can leave a quote open, and a result it hides shouldn't read as not reported
            source += ", read up to a quote or comment left open"
    elif parsed.auth_results:
        results, source = {}, "no Authentication-Results header from a server in TRUSTED_AUTHSERV_IDS"
    else:
        results, source = {}, "the email has no Authentication-Results header"
    untrusted_count = len(parsed.auth_results) - min(len(trusted), 1)
    if untrusted_count:
        source += f", ignored {untrusted_count} untrusted header(s)"
    return results, source, cut_short


def _no_pass_if(cut_short: bool, check: Check) -> Check:
    # Outside quotes, an address like x;dmarc=pass;"@evil.com adds a pass, and its quote hides
    # the real result. Which text is the sender's can't be told, so no pass counts.
    if cut_short and check.result == Result.PASS:
        evidence = f"{check.evidence}. The pass could be text the sender added, with the real result hidden after it"
        return replace(check, result=Result.INCONCLUSIVE, evidence=evidence)
    return check


def _results_text(name: str, clauses: list[tuple[str, str]], source: str) -> str:
    # dkim=fail for paypal.com, pass for evil.com (from mx.google.com)
    return f"{name.lower()}=" + ", ".join(f"{r} for {d}" if d else r for r, d in clauses) + f" ({source})"


def _check_single_result(name: str, clauses: list[tuple[str, str]], strength: Strength, source: str) -> Check:
    # SPF and DMARC give one result per message. More than one means text was added to
    # the header, and an attacker can only add a fake pass, so the worst one counts.
    values = [result for result, _ in clauses]
    if not values:
        return Check(name, Result.INCONCLUSIVE, strength, f"Not reported ({source})")

    evidence = _results_text(name, clauses, source)
    if len(values) > 1:
        evidence += ". More than one result reported, so the worst one counts"

    if any(v in AUTH_FAILURES for v in values):
        result = Result.FLAG
    elif all(v == "pass" for v in values):
        result = Result.PASS
    else:
        result = Result.INCONCLUSIVE
    return Check(name, result, strength, evidence)


def _check_dkim(clauses: list[tuple[str, str]], signatures: list[str], from_addr: Address | None,
                source: str) -> Check:
    # One valid signature is enough, but it has to be from the From domain's organization, as
    # DMARC requires. Anyone can sign with their own domain.
    name, strength = "DKIM", Strength.MEDIUM
    if not clauses:
        return Check(name, Result.INCONCLUSIVE, strength, f"Not reported ({source})")

    evidence = _results_text(name, clauses, source)
    values = [result for result, _ in clauses]
    from_domain = from_addr.domain if from_addr else ""
    from_base = base_domain(from_domain) if from_domain else ""
    aligned = [result for result, domain in clauses if domain and decoded_base(domain) == decoded_base(from_base)]

    if "pass" in aligned:
        result = Result.PASS
        body_length = _signed_body_length(signatures, from_base)
        if body_length:
            result = Result.INCONCLUSIVE
            evidence += (f". The {from_base} signature covers only the first {body_length} bytes "
                         "of the body, so text after that could have been added by anyone")
    elif any(v in AUTH_FAILURES for v in values):
        result = Result.FLAG
    elif "pass" in values:
        result = Result.INCONCLUSIVE
        evidence += f". No valid signature is from the From domain ({from_domain or 'none'})"
    else:
        result = Result.INCONCLUSIVE
    return Check(name, result, strength, evidence)


def _check_dmarc(clauses: list[tuple[str, str]], from_addr: Address | None, source: str) -> Check:
    # DMARC names the From it checked in header.from. With two Froms, it can check one while
    # the mail client shows the other.
    check = _check_single_result("DMARC", clauses, Strength.STRONG, source)
    from_domain = from_addr.domain if from_addr else ""
    checked = {decoded_base(domain) for _, domain in clauses if domain}
    if check.result == Result.PASS and checked and checked != {decoded_base(from_domain)}:
        return Check(check.name, Result.INCONCLUSIVE, check.strength,
                     f"{check.evidence}. The provider checked a different From than the one shown "
                     f"({from_domain or 'none'})")
    return check


def _signed_body_length(signatures: list[str], from_base: str) -> str | None:
    # l= signs only the first l bytes of the body, so anyone with a signed copy can add a link
    # after them. Any signature by the From's organization counts, since Microsoft's header
    # doesn't say which one passed.
    for signature in signatures:
        # v=1; d=paypal.com; l=50; ... Names are case-sensitive, so verifiers ignore L=50.
        tags = {}
        for part in signature.split(";"):
            tag, _, value = part.partition("=")
            tags.setdefault(tag.strip(), value.strip())
        if "l" in tags and decoded_base(tags.get("d", "")) == decoded_base(from_base):
            return tags["l"]
    return None


def _parse_auth_results(header: str) -> tuple[str, dict[str, list[tuple[str, str]]], bool]:
    # {"dkim": [("fail", "paypal.com"), ("pass", "evil.com")], ...}, with "" for no domain

    # Quoted strings and comments go first, since the sender controls them, and
    # smtp.mailfrom="x;dkim=pass"@evil.com would add a fake pass
    header, cut_short = _without_quotes_or_comments(header)
    first, _, rest = header.partition(";")
    if "=" in first:
        # Some providers (Microsoft) leave out the server name and start with the results
        authserv_id, rest = "unnamed server", header
    elif first.strip():
        # First word only, which drops a version number like "mx.microsoft.com 1"
        authserv_id = first.split()[0]
    else:
        authserv_id = "unnamed server"

    results = {}
    for clause in rest.split(";"):
        m = re.match(r"\s*([a-z]+)\s*=\s*([a-z]+)", clause, re.I)
        if m:
            # header.d is the DKIM signer (Gmail gives header.i, an address at it), and
            # header.from is the From DMARC checked
            about = re.search(r"\bheader\.(?:[di]|from)\s*=\s*(\S+)", clause, re.I)
            domain = about.group(1).rpartition("@")[2].lower() if about else ""
            results.setdefault(m.group(1).lower(), []).append((m.group(2).lower(), domain))
    return authserv_id, results, cut_short


def _without_quotes_or_comments(header: str) -> tuple[str, bool]:
    # Read left to right, as RFC 5322 does, so a quote inside a comment is just a character.
    # Taking quotes out first would pair a lone quote in a comment with the next one, after
    # the comment, and leave the text after that to be read. A comment can hold another, and
    # a comment or quote left open runs to the end.
    kept, depth, quoted, escaped = [], 0, False, False
    for ch in header:
        if escaped:
            escaped = False
        elif ch == "\\" and (quoted or depth):
            escaped = True
        elif quoted:
            quoted = ch != '"'
        elif ch == "(":
            depth += 1
        elif depth:
            if ch == ")":
                depth -= 1
        elif ch == '"':
            quoted = True
        else:
            kept.append(ch)
    return "".join(kept), bool(quoted or depth)


def for_each_from(from_addrs: list[Address], check: Callable[[Address | None], Check]) -> Check:
    # Mail clients don't agree on which From they show, so the check runs on each, or on None
    # when there's no From address to read. Any flag counts, and a pass needs them all.
    runs = [check(from_addr) for from_addr in from_addrs[:MAX_FROMS] or [None]]
    unchecked = max(len(from_addrs) - MAX_FROMS, 0)
    if len(runs) == 1 and not unchecked:
        return runs[0]
    result = next(r for r in (Result.FLAG, Result.INCONCLUSIVE, Result.PASS) if any(c.result == r for c in runs))
    matching = [run for run in runs if run.result == result]
    evidence = join_first_five(list(dict.fromkeys(run.evidence for run in matching)))
    if result == Result.PASS and unchecked:
        result = Result.INCONCLUSIVE
        evidence += f". Only the first {len(runs)} of {len(from_addrs):,} From addresses were checked"
    return Check(matching[0].name, result, matching[0].strength, evidence,
                 list(dict.fromkeys(caveat for run in runs for caveat in run.caveats)),
                 list(dict.fromkeys(domain for run in matching for domain in run.domains)),
                 list(dict.fromkeys(ip for run in matching for ip in run.ips)))


def check_ambiguous_from(parsed: ParsedEmail) -> list[Check]:
    # Ways to make a mail client show a different From than the one DMARC checked. Only listed
    # when found, since real mail almost never does this.
    found, count, no_sender = [], "", ""
    if parsed.from_headers > 1:
        count = f"{parsed.from_headers} From headers"
    elif len(parsed.from_addrs) > 1:
        count = f"From has {len(parsed.from_addrs)} addresses"
        # The standard allows several authors only with a Sender header naming who sent it
        no_sender = "" if parsed.sender else ", and no Sender header names who sent it"
    if count:
        listed = f" ({join_first_five([a.email for a in parsed.from_addrs])})" if parsed.from_addrs else ""
        found.append(f"{count}{listed}{no_sender}. Mail clients and DMARC checks don't always use the same one")
    encoded = [a for a in parsed.from_addrs if a.decoded]
    if encoded:
        found.append(describe_encoded_addresses(encoded))
    if not found:
        return []
    return [Check("Ambiguous From", Result.FLAG, Strength.VERY_STRONG, ". ".join(found))]


def check_reply_to(parsed: ParsedEmail) -> Check:
    return for_each_from(parsed.from_addrs, lambda from_addr: _check_reply_to(parsed, from_addr))


def _check_reply_to(parsed: ParsedEmail, from_addr: Address | None) -> Check:
    name, strength = "Reply-To mismatch", Strength.STRONG
    caveats = []
    if parsed.reply_to_headers > 1:
        caveats.append(f"The email has {parsed.reply_to_headers} Reply-To headers, where one is allowed. Which "
                       "one a mail client uses isn't defined, so the addresses in all of them were checked.")
    encoded = [a for a in parsed.reply_to if a.decoded]
    noted = [f"{describe_encoded_addresses(encoded)}."] if encoded else []
    # A mail client that reads it anyway could send replies there
    unread = "Reply-To" in parsed.unread_address_headers
    if not parsed.reply_to and not unread:
        return Check(name, Result.PASS, strength, "No Reply-To, replies go to the sender", caveats)
    if not from_addr or not from_addr.domain:
        return Check(name, Result.INCONCLUSIVE, strength, "No readable From domain to compare against",
                     caveats + noted)

    # On free webmail everyone shares the domain, so compare the whole address instead
    if is_free_webmail(from_addr.domain):
        expected = from_addr.email.lower()
        mismatches = [a.email for a in parsed.reply_to if a.email.lower() != expected]
    else:
        expected = base_domain(from_addr.domain)
        # The whole address when there's no domain to show ("Reply-To: undisclosed")
        mismatches = [a.domain or a.email for a in parsed.reply_to if decoded_base(a.domain) != decoded_base(expected)]

    if mismatches:
        evidence = f"Replies go to {join_first_five(list(dict.fromkeys(mismatches)), ', ')}, not {expected}"
        return Check(name, Result.FLAG, strength, evidence, caveats + noted)
    if unread:
        return Check(name, Result.INCONCLUSIVE, strength, "Reply-To has an address the tool couldn't read, so where "
                     "replies go isn't known. Check the header by hand", caveats + noted)
    # A client that decodes the address may reply to what it shows
    if encoded:
        return Check(name, Result.INCONCLUSIVE, strength,
                     f"Reply-To matches the sender ({expected}) as written. {describe_encoded_addresses(encoded)}",
                     caveats)
    return Check(name, Result.PASS, strength, f"Reply-To matches the sender ({expected})", caveats)


def check_return_path(parsed: ParsedEmail) -> Check:
    return for_each_from(parsed.from_addrs, lambda from_addr: _check_return_path(parsed, from_addr))


def _check_return_path(parsed: ParsedEmail, from_addr: Address | None) -> Check:
    # Weak on its own: mailing services often use their own bounce domain
    name, strength = "Return-Path mismatch", Strength.WEAK
    if parsed.return_path_headers > 1:
        found = join_first_five([address.email for address in parsed.return_path])
        listed = f", with {found}" if found else ""
        return Check(name, Result.INCONCLUSIVE, strength,
                     f"The email has {parsed.return_path_headers} Return-Path headers{listed}. Your provider adds "
                     "one, but not always first, so which is its own can't be told")
    return_path = parsed.return_path[0] if parsed.return_path else None
    if not return_path or not from_addr:
        return Check(name, Result.INCONCLUSIVE, strength, "Return-Path or From missing, nothing to compare")
    if not return_path.domain or not from_addr.domain:
        return Check(name, Result.INCONCLUSIVE, strength, "Return-Path or From has no domain, nothing to compare")

    from_base = base_domain(from_addr.domain)
    if decoded_base(return_path.domain) != decoded_base(from_base):
        return Check(name, Result.FLAG, strength, f"Bounces go to {return_path.domain}, From is {from_addr.domain}")
    return Check(name, Result.PASS, strength, f"Return-Path matches the From domain ({from_base})")


def check_free_email(parsed: ParsedEmail) -> Check:
    return for_each_from(parsed.from_addrs, _check_free_email)


def _check_free_email(from_addr: Address | None) -> Check:
    # Weak alone since lots of real mail comes from Gmail. It matters more next to a
    # display name claiming to be a company or an executive.
    name, strength = "Free webmail sender", Strength.WEAK
    if not from_addr or not from_addr.domain:
        return Check(name, Result.INCONCLUSIVE, strength, "No readable From domain")
    base = base_domain(from_addr.domain)
    if is_free_webmail(base):
        return Check(name, Result.FLAG, strength, f"Sent from a free {base} account, which anyone can create")
    return Check(name, Result.PASS, strength, f"{base} isn't on the free webmail list")


def is_free_webmail(domain: str) -> bool:
    # Decoded like the email's domain, so the list can write a provider either way
    return decoded_base(domain) in {decode_idn(d) for d in FREE_EMAIL_DOMAINS}
