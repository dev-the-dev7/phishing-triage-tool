"""Checks that the sender headers add up: SPF/DKIM/DMARC, Reply-To, Return-Path, free webmail."""

import re

from .domains import base_domain
from .lists import FREE_EMAIL_DOMAINS, TRUSTED_AUTHSERV_IDS
from .models import Check, ParsedEmail, Result, Strength


# Results that count as a failure. Others besides pass (none, neutral, temperror) are
# inconclusive: not a failure, but not verified either.
AUTH_FAILURES = ("fail", "softfail", "permerror")


def check_authentication(parsed: ParsedEmail) -> list[Check]:
    if TRUSTED_AUTHSERV_IDS:
        # Only headers from your provider's servers count, as RFC 8601 recommends,
        # since anyone can write this header
        trusted_ids = {i.lower() for i in TRUSTED_AUTHSERV_IDS}
        trusted = [h for h in parsed.auth_results if _parse_auth_results(h)[0].lower() in trusted_ids]
    else:
        # Only the topmost header was added by your own provider. Anything below it was
        # already in the message when it arrived, so the sender could have written it.
        trusted = parsed.auth_results[:1]

    if trusted:
        authserv_id, results = _parse_auth_results(trusted[0])
        source = f"from {authserv_id}"
    elif parsed.auth_results:
        results, source = {}, "no Authentication-Results header from a server in TRUSTED_AUTHSERV_IDS"
    else:
        results, source = {}, "the email has no Authentication-Results header"
    untrusted_count = len(parsed.auth_results) - min(len(trusted), 1)
    if untrusted_count:
        source += f", ignored {untrusted_count} untrusted header(s)"

    # DMARC is strong because it's the one that ties authentication to the visible From
    # domain. Forwarding breaks SPF and mailing lists break DKIM, so those mean less alone.
    return [
        _check_single_result("SPF", results.get("spf", []), Strength.MEDIUM, source),
        _check_dkim(results.get("dkim", []), parsed, source),
        _check_dmarc(results.get("dmarc", []), parsed, source),
    ]


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


def _check_dkim(clauses: list[tuple[str, str]], parsed: ParsedEmail, source: str) -> Check:
    # One valid signature is enough, but it has to be from the From domain's organization, as
    # DMARC requires. Anyone can sign with their own domain.
    name, strength = "DKIM", Strength.MEDIUM
    if not clauses:
        return Check(name, Result.INCONCLUSIVE, strength, f"Not reported ({source})")

    evidence = _results_text(name, clauses, source)
    values = [result for result, _ in clauses]
    from_domain = parsed.from_addr.domain if parsed.from_addr else ""
    from_base = base_domain(from_domain) if from_domain else ""
    aligned = [result for result, domain in clauses if domain and base_domain(domain) == from_base]

    if "pass" in aligned:
        result = Result.PASS
        body_length = _signed_body_length(parsed.dkim_signatures, from_base)
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


def _check_dmarc(clauses: list[tuple[str, str]], parsed: ParsedEmail, source: str) -> Check:
    # DMARC names the From it checked in header.from. With two Froms, it can check one while
    # the mail client shows the other.
    check = _check_single_result("DMARC", clauses, Strength.STRONG, source)
    from_domain = parsed.from_addr.domain if parsed.from_addr else ""
    checked = {base_domain(domain) for _, domain in clauses if domain}
    if check.result == Result.PASS and checked and checked != {base_domain(from_domain)}:
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
        if "l" in tags and base_domain(tags.get("d", "")) == from_base:
            return tags["l"]
    return None


def _parse_auth_results(header: str) -> tuple[str, dict[str, list[tuple[str, str]]]]:
    # {"dkim": [("fail", "paypal.com"), ("pass", "evil.com")], ...}, with "" for no domain

    # Quoted strings and comments go first, since the sender controls them, and
    # smtp.mailfrom="x;dkim=pass"@evil.com would add a fake pass. Quotes before comments,
    # since a quoted address can hold a "(". An unclosed quote runs to the end.
    header = re.sub(r'"(?:[^"\\]|\\.)*"?', "", header)
    header = re.sub(r"\([^()]*\)", "", header)
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
    return authserv_id, results


def check_reply_to(parsed: ParsedEmail) -> Check:
    name, strength = "Reply-To", Strength.STRONG
    if not parsed.reply_to:
        return Check(name, Result.PASS, strength, "No Reply-To, replies go to the sender")
    if not parsed.from_addr or not parsed.from_addr.domain:
        return Check(name, Result.INCONCLUSIVE, strength, "No readable From domain to compare against")

    sender = parsed.from_addr
    # On free webmail everyone shares the domain, so compare the whole address instead
    if base_domain(sender.domain) in FREE_EMAIL_DOMAINS:
        expected = sender.email.lower()
        mismatches = [a.email for a in parsed.reply_to if a.email.lower() != expected]
    else:
        expected = base_domain(sender.domain)
        # The whole address when there's no domain to show ("Reply-To: undisclosed")
        mismatches = [a.domain or a.email for a in parsed.reply_to if base_domain(a.domain) != expected]

    if mismatches:
        return Check(name, Result.FLAG, strength, f"Replies go to {', '.join(dict.fromkeys(mismatches))}, not {expected}")
    return Check(name, Result.PASS, strength, f"Reply-To matches the sender ({expected})")


def check_return_path(parsed: ParsedEmail) -> Check:
    # Weak on its own: mailing services often use their own bounce domain
    name, strength = "Return-Path domain", Strength.WEAK
    if not parsed.return_path or not parsed.from_addr:
        return Check(name, Result.INCONCLUSIVE, strength, "Return-Path or From missing, nothing to compare")
    if not parsed.return_path.domain or not parsed.from_addr.domain:
        return Check(name, Result.INCONCLUSIVE, strength, "Return-Path or From has no domain, nothing to compare")

    from_base = base_domain(parsed.from_addr.domain)
    rp_base = base_domain(parsed.return_path.domain)
    if rp_base != from_base:
        return Check(name, Result.FLAG, strength,
                     f"Bounces go to {parsed.return_path.domain}, From is {parsed.from_addr.domain}")
    return Check(name, Result.PASS, strength, f"Return-Path matches the From domain ({from_base})")


def check_free_email(parsed: ParsedEmail) -> Check:
    # Weak alone since lots of real mail comes from Gmail. It matters more next to a
    # display name claiming to be a company or an executive.
    name, strength = "Free webmail sender", Strength.WEAK
    if not parsed.from_addr or not parsed.from_addr.domain:
        return Check(name, Result.INCONCLUSIVE, strength, "No readable From domain")
    base = base_domain(parsed.from_addr.domain)
    if base in FREE_EMAIL_DOMAINS:
        return Check(name, Result.FLAG, strength, f"Sent from a free {base} account, which anyone can create")
    return Check(name, Result.PASS, strength, f"{base} isn't on the free webmail list")
