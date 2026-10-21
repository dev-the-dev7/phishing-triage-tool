"""Gathers evidence from reported phishing emails so an analyst can make the call."""

import sys

# Older versions aren't tested. On 3.11.0 an address header can't be read, and a check passes without it.
if sys.version_info < (3, 14):
    raise SystemExit(f"error: the tool needs Python 3.14 or newer, not {sys.version_info[0]}.{sys.version_info[1]}")
