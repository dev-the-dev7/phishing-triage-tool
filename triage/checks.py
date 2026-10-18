"""Runs every check that needs only the email. The two that need the lookups are in enrich.py."""

from .content import check_css_added_text, check_hidden_text, check_image_only
from .headers import (check_ambiguous_from, check_dkim, check_dmarc, check_free_email, check_reply_to,
                      check_return_path, check_spf)
from .impersonation import check_brand_joined, check_display_name, check_lookalike
from .links import check_google_redirect, check_link_mismatch, check_link_type
from .models import Check, ParsedEmail


def run_checks(parsed: ParsedEmail) -> list[Check]:
    return [
        check_spf(parsed),
        check_dkim(parsed),
        check_dmarc(parsed),
        check_reply_to(parsed),
        check_return_path(parsed),
        check_display_name(parsed),
        check_free_email(parsed),
        check_lookalike(parsed),
        check_brand_joined(parsed),
        check_link_mismatch(parsed),
        check_link_type(parsed),
        # Only listed when they find something
        *check_ambiguous_from(parsed),
        *check_google_redirect(parsed),
        *check_hidden_text(parsed),
        *check_image_only(parsed),
        *check_css_added_text(parsed),
    ]
