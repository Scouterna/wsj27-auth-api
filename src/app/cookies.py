"""Setting and clearing the auth cookies.

Path is set explicitly to "/" on every cookie, on both set and delete. Omitting
it would leave the browser defaulting the path to the directory of the request
URI (/auth), so sibling apps elsewhere on the host would read these cookies only
incidentally. Since the entire point is cross-app cookies under one host, we
state the path we mean.

The same attributes must be present when deleting: a browser matches the deletion
against name + domain + path, so a delete without Path=/ would leave the real
cookie in place.
"""

import logging
import time

from fastapi import Response

from . import constants
from .config import get_settings

logger = logging.getLogger(__name__)

settings = get_settings()

COOKIE_PATH = "/"
SAME_SITE = "lax"


def _secure() -> bool:
    return not settings.INSECURE_COOKIES


def set_cookie(response: Response, name: str, value: str, *, max_age: int, http_only: bool = True) -> None:
    if len(value) > constants.COOKIE_SIZE_WARNING_THRESHOLD:
        logger.warning(
            "Cookie %s is %d bytes, above the ~%d-byte size browsers reliably accept",
            name,
            len(value),
            constants.COOKIE_SIZE_WARNING_THRESHOLD,
        )

    response.set_cookie(
        key=name,
        value=value,
        max_age=max_age,
        path=COOKIE_PATH,
        httponly=http_only,
        secure=_secure(),
        samesite=SAME_SITE,
    )


def delete_cookie(response: Response, name: str) -> None:
    response.delete_cookie(
        key=name,
        path=COOKIE_PATH,
        httponly=True,
        secure=_secure(),
        samesite=SAME_SITE,
    )


def clear_auth_cookies(response: Response) -> None:
    """Remove every cookie this app sets."""
    for name in constants.ALL_COOKIES:
        delete_cookie(response, name)


def clear_transient_cookies(response: Response) -> None:
    """Remove the one-round-trip login cookies.

    Clearing them once the code has been redeemed keeps the browser tidy and
    stops a stale verifier being replayed against a later callback.
    """
    for name in constants.TRANSIENT_COOKIES:
        delete_cookie(response, name)


def set_login_flow_cookies(
    response: Response, *, code_verifier: str, state: str, nonce: str, redirect_uri: str
) -> None:
    """Carry the PKCE verifier, CSRF state, nonce and destination across the redirect.

    This is the only "session" the service has — there is no server-side store,
    which is what keeps it stateless and horizontally scalable.
    """
    ttl = constants.LOGIN_FLOW_TTL_SECONDS
    set_cookie(response, constants.OIDC_CODE_VERIFIER, code_verifier, max_age=ttl)
    set_cookie(response, constants.OIDC_STATE, state, max_age=ttl)
    set_cookie(response, constants.OIDC_NONCE, nonce, max_age=ttl)
    set_cookie(response, constants.REDIRECT_URI, redirect_uri, max_age=ttl)


def set_session_cookies(
    response: Response,
    *,
    access_token: str,
    expires_in: int,
    refresh_token: str | None,
    id_token: str | None,
    refresh_expires_in: int,
) -> None:
    """Set the cookies that represent a logged-in session.

    access_token is *our* re-signed token; refresh_token and id_token are
    Keycloak's, kept so we can re-mint later and so logout can pass an
    id_token_hint.
    """
    now_ms = int(time.time() * 1000)

    set_cookie(response, constants.ACCESS_TOKEN, access_token, max_age=expires_in)

    if refresh_token:
        set_cookie(response, constants.REFRESH_TOKEN, refresh_token, max_age=refresh_expires_in)
        set_cookie(
            response,
            constants.REFRESH_EXPIRES_AT,
            str(now_ms + refresh_expires_in * 1000),
            max_age=refresh_expires_in,
        )

    if id_token:
        # Tied to the refresh lifetime, not the access lifetime: it is needed at
        # logout, and an expired id_token is still a valid id_token_hint.
        set_cookie(response, constants.ID_TOKEN, id_token, max_age=refresh_expires_in)

    # Readable by JavaScript on purpose — refresh.js schedules the next refresh
    # from it. It carries no secret, just an expiry timestamp.
    set_cookie(
        response,
        constants.EXPIRES_AT,
        str(now_ms + expires_in * 1000),
        max_age=expires_in,
        http_only=False,
    )
