"""What the checks compare against that's yours to change. The first part is about your
organization and ships empty: fill it in. The rest comes filled in with what turns up in most
mail: add to it, or take out what doesn't fit yours. Then run python -m pytest
tests/test_settings.py to check your changes."""

# === Your organization ===
# Empty as shipped, so these checks do nothing until you fill them in.

# Your organization's names and every domain you own. Lookalikes get flagged, and so does a
# display name using one of the names from another domain. Use names attackers would write,
# not common words. The names need OWN_DOMAINS filled in.
OWN_NAMES: set[str] = set()   # e.g. {"contoso", "contoso health"}
# A list, not a set, because the first one is your main domain and is named in the evidence
OWN_DOMAINS: list[str] = []   # e.g. ["contoso.com", "contoso-health.org"]

# The server name your provider writes at the start of Authentication-Results. Empty trusts
# the topmost header, which is right when your provider always adds one. If it might not,
# fill this in, and only headers from these servers count.
TRUSTED_AUTHSERV_IDS: set[str] = set()   # e.g. {"mx.google.com"}

# Names attackers are likely to impersonate (CEO, CFO, anyone who approves payments).
# Mail using one of these names from outside OWN_DOMAINS gets flagged, so without
# OWN_DOMAINS their own mail is flagged too.
EXECUTIVES: set[str] = set()


# === Filled in for you ===
# Add to these, or take out what doesn't fit your organization.

MICROSOFT_DOMAINS = ["microsoft.com", "office.com", "office365.com", "microsoft365.com",
                     "microsoftonline.com", "microsoftonline-p.com"]

# Facebook's notification emails come from facebookmail.com
META_DOMAINS = ["facebook.com", "facebookmail.com", "fb.com", "fbcdn.net", "meta.com",
                "instagram.com", "whatsapp.com", "messenger.com"]

# Brands often impersonated at work, and the domains their real mail uses, images and tracking
# included. The first is the main domain, and names sharing a list are one company. A starting
# point, not a complete list: add your suppliers and partners too.
BRANDS: dict[str, list[str]] = {
    "paypal": ["paypal.com", "paypalobjects.com"],
    "microsoft": MICROSOFT_DOMAINS,
    "office 365": MICROSOFT_DOMAINS,
    "apple": ["apple.com", "apple.news"],
    "amazon": ["amazon.com", "amazon.co.uk", "amazon.ca", "amazon.de", "amazon.fr",
               "amazon.it", "amazon.es", "amazon.co.jp", "amazon.in", "amazon.com.au",
               "amazon.com.mx", "media-amazon.com", "ssl-images-amazon.com"],
    "google": ["google.com", "google-analytics.com"],
    "docusign": ["docusign.com", "docusign.net"],
    "netflix": ["netflix.com"],
    "fedex": ["fedex.com"],
    "chase": ["chase.com"],
    "wells fargo": ["wellsfargo.com"],
    "bank of america": ["bankofamerica.com"],
    # Job offers and messages for LinkedIn, and "your page will be deleted" or "Meta
    # Verified" for Meta, aimed at whoever runs the company's social accounts
    "linkedin": ["linkedin.com", "licdn.com", "lnkd.in"],
    "facebook": META_DOMAINS,
    "instagram": META_DOMAINS,
    "whatsapp": META_DOMAINS,
    "meta": META_DOMAINS,
}

# Words phishers join to a short brand name (appleid.com, chaseonline.com), which get the
# joined name flagged. Taking one out leaves those inconclusive for every brand, so to stop
# one false alarm, add the name to ALLOWED_NAMES instead.
JOIN_WORDS: set[str] = {
    "id", "login", "logon", "signin", "account", "accounts", "verify", "verification", "secure", "security",
    "support", "help", "helpdesk", "service", "services", "update", "billing", "pay", "payment", "bank",
    "online", "alert", "alerts", "notice", "delivery", "track", "tracking", "parcel", "shipping", "my",
    "auth", "recovery", "unlock", "reset", "confirm", "team", "care", "customer", "portal", "access",
}

# Words that pass when they're one letter from a short brand name or hold one, instead of
# being flagged or left for the analyst: newer words the English word list lacks (mega for
# meta), and ones like them from your own mail (metaverse). A supplier you get mail from
# goes in BRANDS instead, with its domains, so someone posing as them is flagged too.
ALLOWED_NAMES: set[str] = {"mega", "metadata"}

# Free webmail providers. The common ones, not a complete list. A provider missing
# from here is treated like a company domain by the Reply-To and webmail checks.
FREE_EMAIL_DOMAINS: set[str] = {
    # US and global
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com", "msn.com",
    "yahoo.com", "aol.com", "icloud.com", "me.com", "mail.com", "zoho.com",
    # Country versions
    "yahoo.co.uk", "yahoo.co.jp", "hotmail.co.uk",
    # Europe, Russia, Asia
    "gmx.com", "gmx.de", "web.de", "yandex.com", "yandex.ru", "mail.ru",
    "qq.com", "163.com", "naver.com",
    # Privacy-focused
    "proton.me", "protonmail.com", "tuta.com", "tutanota.com", "fastmail.com",
}
