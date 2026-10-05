"""Cookie names shared across the app.

The prefix matches the service name so cookies from sibling apps under the same
host (app.wsj.se) never collide.
"""

COOKIE_PREFIX = "wsj27-auth_"

ACCESS_TOKEN = f"{COOKIE_PREFIX}access-token"
REFRESH_TOKEN = f"{COOKIE_PREFIX}refresh-token"
ID_TOKEN = f"{COOKIE_PREFIX}id-token"
EXPIRES_AT = f"{COOKIE_PREFIX}expires-at"
REFRESH_EXPIRES_AT = f"{COOKIE_PREFIX}refresh-expires-at"
OIDC_CODE_VERIFIER = f"{COOKIE_PREFIX}oidc-code-verifier"
OIDC_STATE = f"{COOKIE_PREFIX}oidc-state"
OIDC_NONCE = f"{COOKIE_PREFIX}oidc-nonce"
REDIRECT_URI = f"{COOKIE_PREFIX}redirect-uri"

# Every cookie this app sets. Logout and the failure paths clear all of them.
ALL_COOKIES = (
    ACCESS_TOKEN,
    REFRESH_TOKEN,
    ID_TOKEN,
    EXPIRES_AT,
    REFRESH_EXPIRES_AT,
    OIDC_CODE_VERIFIER,
    OIDC_STATE,
    OIDC_NONCE,
    REDIRECT_URI,
)

# Cookies that only exist for the duration of one login round-trip.
TRANSIENT_COOKIES = (OIDC_CODE_VERIFIER, OIDC_STATE, OIDC_NONCE, REDIRECT_URI)

# Lifetime of the transient login cookies.
LOGIN_FLOW_TTL_SECONDS = 30 * 60

# Browsers commonly cap a single cookie around 4 KiB. Warn before we get there.
COOKIE_SIZE_WARNING_THRESHOLD = 4000

OIDC_SCOPE = "openid profile email"
