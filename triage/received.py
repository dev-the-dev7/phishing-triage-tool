"""Reads the Received headers to find which outside server handed the email to your provider."""

import ipaddress
import re

from .domains import base_domain, has_ip, is_internal_ip
from .models import Origin, ParsedEmail


def find_origin(parsed: ParsedEmail) -> Origin | None:
    # None when no Received hop has an IP, so the route is unknown
    hops = _read_hops(parsed)
    if not hops:
        return None
    index = _handoff_index(hops)
    if index is None:
        return Origin(None, None, hops[0]["by"])

    hop = hops[index]
    lower_hop_ips = [h["ip"] for h in hops[index + 1:] if not is_internal_ip(h["ip"])]
    return Origin(hop["ip"], hop["name"], hop["by"], lower_hop_ips[-1] if lower_hop_ips else None)


def _handoff_index(hops: list[dict]) -> int | None:
    # Walk down from the top. The receiving servers so far belong to your provider, so a
    # hop sent from one of their domains is still internal relaying. The first hop sent
    # from somewhere else is where the message entered the provider.
    provider = set()
    for i, hop in enumerate(hops):
        provider.add(base_domain(hop["by"]))
        if is_internal_ip(hop["ip"]) or base_domain(hop["name"]) in provider:
            continue
        return i
    return None


def received_warnings(parsed: ParsedEmail) -> list[str]:
    # A Received header with an IP in a format _read_hop doesn't know gets skipped. If it was
    # the provider's handoff, the origin is wrong, and the analyst is told to check it.
    # Headers with no IP at all are normal (Gmail's API submissions) and aren't reported.
    warnings = []
    for position, header in enumerate(parsed.received, 1):
        parts = _split_received(header)
        if parts and _read_hop(header) is None and has_ip(parts[0]):
            warnings.append(f"Received header {position} has an IP in a format the tool can't read, "
                            "so the origin may be wrong. Check that header by hand.")
    return warnings


def _read_hops(parsed: ParsedEmail) -> list[dict]:
    hops = []
    for header in parsed.received:
        hop = _read_hop(header)
        if hop:
            hops.append(hop)
    return hops


def _split_received(header: str) -> tuple[str, str] | None:
    # "from <who connected> by <who received>". One \s around the parts, not \s+, because
    # \s+ next to .*? takes minutes on a header with a long run of spaces.
    m = re.match(r"\s*from\s(.*?)\sby\s+(\S+)", header, re.I)
    if not m:
        return None
    return m.group(1).strip(), m.group(2).rstrip(";")


def _read_hop(header: str) -> dict | None:
    # One Received header as {"ip", "name", "by"}, or None if it has no IP to read
    parts = _split_received(header)
    if not parts:
        return None
    from_part, by = parts
    # Gmail/Postfix write "helo (rdns [ip])". The helo is the sender's claim and can be
    # an IP itself ("[8.8.8.8] (unknown [203.0.113.5])"), so the IP is taken from the
    # receiver's part in parentheses. The last match is used because the receiver
    # writes its part after the helo. qmail's "(HELO [8.8.8.8])" is also the helo and is skipped.
    receiver_part = re.findall(r"\((?!helo\s)([\w.-]*?)\.?\s*\[(?:IPv6:)?([0-9a-fA-F:.]+)\]", from_part, re.I)
    # Microsoft and qmail write "name (ip)"
    plain_ips = re.findall(r"\((?:IPv6:)?([0-9a-fA-F:.]+)\)", from_part)
    # Exim with no verified name writes "[ip] (helo=...)". Checked last, because in the
    # other formats a leading [ip] is the sender's helo.
    leading_ip = re.match(r"\[(?:IPv6:)?([0-9a-fA-F:.]+)\]", from_part)
    if receiver_part:
        # Use the name the receiver looked up, never the sender's claim.
        # "unknown" means the lookup failed, and the claimed name could be anything.
        rdns, ip_text = receiver_part[-1]
        if not rdns and "helo=" in from_part:
            # Exim writes "rdns ([ip]:port helo=...)", with its verified name first
            rdns = from_part.split()[0]
        name = rdns or "unknown"
    elif plain_ips:
        # Microsoft only has the name as given. qmail's first word is its lookup, or "unknown".
        ip_text = plain_ips[-1]
        name = from_part.split()[0].strip("[]")
    elif leading_ip:
        ip_text = leading_ip.group(1)
        name = "unknown"
    else:
        return None
    try:
        ip = ipaddress.ip_address(ip_text)
    except ValueError:
        return None
    # Some servers write IPv4 as IPv6 (::ffff:203.0.113.5). Lookups need the plain IPv4.
    if ip.version == 6 and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return {"ip": str(ip), "name": name, "by": by}
