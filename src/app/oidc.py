"""Talking to the upstream Keycloak.

Deliberately no OIDC client library. The two grants we need are plain form POSTs,
and rolling them by hand avoids a redirect_uri-reconstruction problem: such
libraries typically re-verify that redirect_uri matches the URL the request
arrived on, which does not hold behind an ingress that strips /auth, forcing the
app to rebuild its own URL from X-Forwarded-* headers. We simply send the same
PUBLIC_URL-derived redirect_uri in both calls.
"""

import asyncio
import base64
import hashlib
import logging
import secrets
import time
from typing import Any
from urllib.parse import urlencode, urljoin

import httpx
from joserfc import jwt
from joserfc.errors import InvalidKeyIdError
from joserfc.jwk import KeySet

from .config import get_settings
from .constants import OIDC_SCOPE

logger = logging.getLogger(__name__)

settings = get_settings()

HTTP_TIMEOUT = 10.0

# Minimum gap between JWKS reloads. A reload is triggered by a token whose kid
# we do not know, and anyone can present one of those, so without a floor a
# stream of junk tokens would turn into a stream of requests to Keycloak.
JWKS_RELOAD_COOLDOWN_SECONDS = 60.0

_metadata: dict[str, Any] = {}
_jwks: KeySet | None = None
# Monotonic time of the last JWKS fetch *attempt*, successful or not, so a
# Keycloak outage is rate-limited by the cooldown too.
_jwks_fetched_at = 0.0
_jwks_lock = asyncio.Lock()


class OIDCError(Exception):
    """An upstream OIDC call failed."""

    def __init__(self, message: str, error: str | None = None) -> None:
        super().__init__(message)
        # The OAuth error code, e.g. "invalid_grant" or "login_required". The
        # callers branch on this, so it is kept separate from the message.
        self.error = error


async def init_oidc() -> None:
    """Fetch Keycloak's discovery document and JWKS. Call once at startup."""
    global _metadata

    discovery_url = settings.OIDC_SERVER.rstrip("/") + "/.well-known/openid-configuration"

    async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as client:
        response = await client.get(discovery_url)
        response.raise_for_status()
        _metadata = response.json()

    if not _metadata.get("jwks_uri"):
        raise OIDCError(f"Discovery document at {discovery_url} has no jwks_uri")

    await _fetch_jwks()

    logger.info("Discovered upstream OIDC issuer %s", _metadata.get("issuer"))


async def _fetch_jwks() -> None:
    global _jwks, _jwks_fetched_at

    _jwks_fetched_at = time.monotonic()
    async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as client:
        response = await client.get(_metadata["jwks_uri"])
        response.raise_for_status()
        _jwks = KeySet.import_key_set(response.json())


async def _reload_jwks() -> None:
    """Re-fetch Keycloak's JWKS after meeting a kid we do not have.

    Keycloak rotates by adding a new active key and signing with it from then
    on. With the key set loaded only at startup, every login and refresh would
    fail from that moment until the pod restarted.

    The lock collapses a burst of concurrent misses into one fetch; the others
    find the cooldown not yet elapsed and retry against the freshly loaded set.
    """
    async with _jwks_lock:
        if time.monotonic() - _jwks_fetched_at < JWKS_RELOAD_COOLDOWN_SECONDS:
            return
        logger.info("Unknown upstream signing key; reloading JWKS from %s", _metadata.get("jwks_uri"))
        await _fetch_jwks()


def metadata() -> dict[str, Any]:
    return _metadata


def end_session_endpoint() -> str | None:
    return _metadata.get("end_session_endpoint")


def callback_url() -> str:
    """The redirect_uri we register with Keycloak.

    Derived from PUBLIC_URL so it is identical in the authorization request and
    the token request — Keycloak rejects the exchange if they differ by a byte.
    """
    return urljoin(settings.PUBLIC_URL, "callback")


def generate_pkce_pair() -> tuple[str, str]:
    """Return (code_verifier, code_challenge) for the S256 method."""
    verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return verifier, challenge


def generate_state() -> str:
    return secrets.token_urlsafe(32)


def generate_nonce() -> str:
    return secrets.token_urlsafe(32)


def build_authorization_url(
    *,
    code_challenge: str,
    state: str,
    nonce: str,
    silent: bool = False,
    locale: str | None = None,
) -> str:
    endpoint = _metadata.get("authorization_endpoint")
    if not endpoint:
        raise OIDCError("Upstream metadata has no authorization_endpoint")

    params = {
        "client_id": settings.OIDC_CLIENT_ID,
        "response_type": "code",
        "redirect_uri": callback_url(),
        "scope": OIDC_SCOPE,
        "state": state,
        # Binds the id_token to this browser's login attempt. PKCE and state
        # already cover code injection; this is a cheap second lock on the
        # token itself.
        "nonce": nonce,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }

    if silent:
        # Ask Keycloak to answer from an existing session or fail immediately,
        # rather than showing a login form.
        params["prompt"] = "none"

    if locale:
        params["ui_locales"] = locale

    separator = "&" if "?" in endpoint else "?"
    return f"{endpoint}{separator}{urlencode(params)}"


def build_end_session_url(*, post_logout_redirect_uri: str, id_token: str) -> str | None:
    endpoint = end_session_endpoint()
    if not endpoint:
        return None

    params = {
        "post_logout_redirect_uri": post_logout_redirect_uri,
        # Without the hint Keycloak cannot validate the post-logout redirect and
        # strands the user on a confirmation page instead of returning them.
        "id_token_hint": id_token,
        "client_id": settings.OIDC_CLIENT_ID,
    }

    separator = "&" if "?" in endpoint else "?"
    return f"{endpoint}{separator}{urlencode(params)}"


async def _token_request(data: dict[str, str]) -> dict[str, Any]:
    endpoint = _metadata.get("token_endpoint")
    if not endpoint:
        raise OIDCError("Upstream metadata has no token_endpoint")

    async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as client:
        response = await client.post(
            endpoint,
            data=data,
            # client_secret_basic: the client id and secret go in the
            # Authorization header, which is Keycloak's default for a
            # confidential client.
            auth=(settings.OIDC_CLIENT_ID, settings.OIDC_CLIENT_SECRET),
            headers={"Accept": "application/json"},
        )

    if response.status_code >= 400:
        error_code = None
        description = response.text
        try:
            body = response.json()
            error_code = body.get("error")
            description = body.get("error_description", description)
        except ValueError:
            pass
        raise OIDCError(f"Token endpoint returned {response.status_code}: {description}", error=error_code)

    return response.json()


async def exchange_code(*, code: str, code_verifier: str) -> dict[str, Any]:
    return await _token_request(
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": callback_url(),
            "code_verifier": code_verifier,
            "client_id": settings.OIDC_CLIENT_ID,
        }
    )


async def refresh_tokens(refresh_token: str) -> dict[str, Any]:
    return await _token_request(
        {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "scope": OIDC_SCOPE,
            "client_id": settings.OIDC_CLIENT_ID,
        }
    )


async def decode_upstream_token(
    token: str,
    *,
    verify_audience: bool = False,
    nonce: str | None = None,
) -> dict[str, Any]:
    """Verify a Keycloak-issued token against Keycloak's JWKS.

    Used for the id_token (proof of authentication) and the access token (source
    of the identity claims we copy). Audience is only checked on the id_token:
    Keycloak's access token carries an `aud` of the resource servers, not our
    client id.

    `nonce` is checked only when given, which is only on the callback: an
    id_token from a refresh grant is not tied to a fresh authorization request,
    so there is no nonce of ours for it to echo.
    """
    if _jwks is None:
        raise OIDCError("Upstream JWKS not loaded")

    try:
        decoded = jwt.decode(token, _jwks)
    except InvalidKeyIdError:
        await _reload_jwks()
        decoded = jwt.decode(token, _jwks)

    claims_options: dict[str, Any] = {"iss": {"essential": True, "value": _metadata.get("issuer")}}
    if verify_audience:
        claims_options["aud"] = {"essential": True, "value": settings.OIDC_CLIENT_ID}
    if nonce is not None:
        claims_options["nonce"] = {"essential": True, "value": nonce}

    registry = jwt.JWTClaimsRegistry(leeway=30, **claims_options)
    registry.validate(decoded.claims)

    return dict(decoded.claims)
