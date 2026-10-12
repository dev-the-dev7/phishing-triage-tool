"""Runs every check on a parsed email. The report gets its list from here."""

from .headers import check_authentication, check_free_email, check_reply_to, check_return_path
from .impersonation import check_brand_joined, check_display_name, check_lookalike
from .links import check_link_mismatch
from .models import Check, ParsedEmail


def run_checks(parsed: ParsedEmail) -> list[Check]:
    return [
        *check_authentication(parsed),
        check_reply_to(parsed),
        check_return_path(parsed),
        check_display_name(parsed),
        check_free_email(parsed),
        check_lookalike(parsed),
        check_brand_joined(parsed),
        check_link_mismatch(parsed),
    ]
