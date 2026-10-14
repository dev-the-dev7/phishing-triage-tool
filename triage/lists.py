"""Lists the checks compare against. Edit these for your own organization."""

MICROSOFT_DOMAINS = ["microsoft.com", "office.com", "office365.com", "microsoft365.com",
                     "microsoftonline.com", "microsoftonline-p.com"]

# Facebook's notification emails come from facebookmail.com
META_DOMAINS = ["facebook.com", "facebookmail.com", "fb.com", "fbcdn.net", "meta.com",
                "instagram.com", "whatsapp.com", "messenger.com"]

# Brands commonly impersonated in work email and the domains they actually use, including
# the image and tracking domains their real mail links to. The first one is the main domain.
# Names sharing one list are one company, reported once.
# Kept short on purpose: it's a starting point, not a complete list.
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

# Your organization: the names people call it and every domain you own. Any of these
# domains is legitimate for any of these names. Lookalikes of them get flagged, and so
# does a display name using a name from outside these domains ("Contoso IT Support").
# Use the names attackers would write, not common words that show up everywhere.
# The names only work once OWN_DOMAINS is filled in, since there's nothing to compare to.
OWN_NAMES: set[str] = set()   # e.g. {"contoso", "contoso health"}
# A list, not a set, because the first one is your main domain and is named in the evidence
OWN_DOMAINS: list[str] = []   # e.g. ["contoso.com", "contoso-health.org"]

# The server name your provider writes at the start of its Authentication-Results header,
# like "mx.google.com" for Gmail. Empty means the topmost header is trusted, which is right
# when your provider always adds one, since it goes on top of anything the sender wrote.
# Fill this in if it might not: then only headers from these servers count.
TRUSTED_AUTHSERV_IDS: set[str] = set()   # e.g. {"mx.google.com"}

# Names attackers are likely to impersonate (CEO, CFO, anyone who approves payments).
# Mail using one of these names from outside OWN_DOMAINS gets flagged.
EXECUTIVES: set[str] = set()

# Hosting services where every customer gets their own subdomain, so
# paypal-login.github.io and my-blog.github.io belong to different people.
# Phishers use these because they're free and come with valid HTTPS. The Public Suffix
# List has most of them too. These are all added to it, which covers the few it doesn't.
SHARED_HOSTING: set[str] = {
    "github.io", "web.app", "firebaseapp.com", "pages.dev", "workers.dev",
    "netlify.app", "vercel.app", "herokuapp.com", "azurewebsites.net", "amazonaws.com",
    "blogspot.com", "wixsite.com", "weebly.com", "glitch.me",
    # Cloud hosting, storage and tunnels: Google App Engine, Azure storage, Cloudflare R2
    # and Cloudflare's free tunnels
    "appspot.com", "blob.core.windows.net", "web.core.windows.net", "r2.dev", "trycloudflare.com",
    # Microsoft 365 tenants. Attackers sign up for free trials to send from these.
    "onmicrosoft.com", "sharepoint.com",
}

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
