"""The auth endpoints.

Routes are registered at the root; the /auth prefix is added by the ingress in
front of us. Every externally-visible URL is therefore derived from PUBLIC_URL
rather than from the incoming request path.

The contract is a conventional cookie-based OIDC front end: /login, /callback,
/refresh, /user, /logout, plus discovery and JWKS — and /token, which issues the
same kind of token to machine callers via the client-credentials grant.
"""

import base64
import binascii
import logging
import time
from typing import Any
from urllib.parse import urljoin, urlparse

from fastapi import APIRouter, Form, Query, Request
from fastapi.responses import JSONResponse, PlainTextResponse, RedirectResponse, Response
from pydantic import BaseModel, Field

from . import constants, cookies, oidc, roles, service_clients, tokens
from .config import get_settings
from .keys import get_jwks

logger = logging.getLogger(__name__)

settings = get_settings()

router = APIRouter()

# 302 throughout: these are browser navigations, and every redirect here is a
# GET-to-GET hop, so the method-rewriting nuance of 303/307 does not arise.
REDIRECT_STATUS = 302

# Stands in for Keycloak's refresh token while FAKE_USER_ID is set. Never sent
# anywhere: it only has to exist, so the session has the same shape as a real one.
FAKE_REFRESH_TOKEN = "fake-user"


def _redirect_uri_valid(uri: str | None) -> bool:
    """Allow only hosts on the configured allowlist.

    Host-only matching: the port is part of the comparison (so "localhost:5173"
    is distinct from "localhost"), but scheme and path are not checked, since
    apps redirect back to arbitrary in-app paths.
    """
    if not uri:
        return False

    try:
        parsed = urlparse(uri)
    except ValueError:
        return False

    if not parsed.netloc:
        return False

    return parsed.netloc in settings.ALLOWED_REDIRECT_DOMAINS


def _unauthorized() -> JSONResponse:
    return JSONResponse({"error": "Unauthorized"}, status_code=401)


def _end_session() -> JSONResponse:
    """A 401 that also clears the session, so the client stops retrying."""
    response = _unauthorized()
    cookies.clear_auth_cookies(response)
    return response


@router.get(
    "/login",
    tags=["public"],
    summary="Start the login flow",
    description=(
        "Redirect the user here to log them in. They come back to `redirect_uri` "
        "with the session cookies set.\n\n"
        "Navigate the browser to this endpoint — do not fetch it with XHR, since "
        "it redirects to the identity provider."
    ),
    # This endpoint never returns 200; status_code sets the documented default
    # so FastAPI does not add one.
    status_code=302,
    responses={
        302: {"description": "Redirect to the identity provider."},
        400: {"description": "`redirect_uri` is missing or its host is not allowed."},
    },
)
async def login(
    redirect_uri: str = Query(..., description="Where to send the user once they are logged in."),
    silent: str | None = Query(None, description='If "true", do not prompt; fail silently when no session exists.'),
    locale: str | None = Query(None, description='UI language passed to the IdP, e.g. "sv" or "en".'),
) -> Response:
    if not _redirect_uri_valid(redirect_uri):
        return PlainTextResponse("Invalid redirect URI", status_code=400)

    if settings.FAKE_USER_ID:
        # No IdP round-trip, so no PKCE or state to carry across it: the session
        # is established here and the browser goes straight back to the app.
        logger.warning("FAKE_USER_ID is set: signing in without the identity provider")
        return _apply_fake_session(RedirectResponse(redirect_uri, status_code=REDIRECT_STATUS))

    code_verifier, code_challenge = oidc.generate_pkce_pair()
    state = oidc.generate_state()

    authorization_url = oidc.build_authorization_url(
        code_challenge=code_challenge,
        state=state,
        silent=silent == "true",
        locale=locale,
    )

    response = RedirectResponse(authorization_url, status_code=REDIRECT_STATUS)
    cookies.set_login_flow_cookies(
        response,
        code_verifier=code_verifier,
        state=state,
        redirect_uri=redirect_uri,
    )
    return response


@router.get(
    "/callback",
    tags=["internal"],
    summary="Handle the redirect back from the IdP",
    description=(
        "The identity provider redirects here after login. Not called directly — "
        "it needs the cookies `/login` set, and it is the URL registered on the "
        "IdP client."
    ),
    status_code=302,
    responses={
        302: {"description": "Session established; redirect back to the app."},
        400: {"description": "Missing or mismatched login-flow state."},
        502: {"description": "The identity provider rejected the code exchange."},
    },
)
async def callback(request: Request) -> Response:
    final_redirect_uri = request.cookies.get(constants.REDIRECT_URI)
    if not _redirect_uri_valid(final_redirect_uri):
        return PlainTextResponse("Invalid redirect URI", status_code=400)

    # Narrowed by _redirect_uri_valid above.
    assert final_redirect_uri is not None

    error = request.query_params.get("error")
    if error:
        # prompt=none with no active session: expected, not a failure. Return the
        # user to the app logged out rather than showing them an error.
        if error == "login_required":
            response = RedirectResponse(final_redirect_uri, status_code=REDIRECT_STATUS)
            cookies.clear_auth_cookies(response)
            return response

        logger.warning("IdP returned error=%s: %s", error, request.query_params.get("error_description"))
        return PlainTextResponse(f"Authentication failed: {error}", status_code=400)

    code_verifier = request.cookies.get(constants.OIDC_CODE_VERIFIER)
    if not code_verifier:
        return PlainTextResponse("Missing code verifier", status_code=400)

    expected_state = request.cookies.get(constants.OIDC_STATE)
    received_state = request.query_params.get("state")
    if not expected_state or received_state != expected_state:
        # Verifying state closes a CSRF hole where an attacker feeds the victim
        # their own authorization code, logging them into the attacker's account.
        logger.warning("State mismatch on callback")
        return PlainTextResponse("Invalid state", status_code=400)

    code = request.query_params.get("code")
    if not code:
        return PlainTextResponse("Missing authorization code", status_code=400)

    try:
        upstream = await oidc.exchange_code(code=code, code_verifier=code_verifier)
    except oidc.OIDCError as exc:
        if exc.error == "login_required":
            response = RedirectResponse(final_redirect_uri, status_code=REDIRECT_STATUS)
            cookies.clear_auth_cookies(response)
            return response
        logger.error("Authorization code exchange failed: %s", exc)
        return PlainTextResponse("Authentication failed", status_code=502)

    try:
        response = _apply_session(RedirectResponse(final_redirect_uri, status_code=REDIRECT_STATUS), upstream)
    except _SessionError as exc:
        logger.error("Could not establish session: %s", exc)
        return PlainTextResponse("Authentication failed", status_code=502)

    # The login-flow cookies are spent; drop them rather than leaving them to
    # expire on their own.
    cookies.clear_transient_cookies(response)
    return response


@router.get(
    "/refresh",
    tags=["public"],
    summary="Refresh the access token",
    description=(
        "Issues a new access token from the refresh cookie. Call this with "
        "`fetch` shortly before the token expires — `static/refresh.js` does it "
        "for you.\n\n"
        "Roles are recomputed here, so a role change takes effect within one "
        "token lifetime rather than requiring a fresh login.\n\n"
        "A `401` means the session is over: stop retrying and send the user to "
        "`/login`."
    ),
    responses={
        200: {"description": "Refreshed; new cookies set.", "content": {"application/json": {"example": {}}}},
        401: {"description": "No refresh cookie, or the session has ended."},
        502: {"description": "The identity provider could not be reached."},
    },
)
async def refresh(request: Request) -> Response:
    refresh_token = request.cookies.get(constants.REFRESH_TOKEN)
    if not refresh_token:
        return _unauthorized()

    # Checked before everything else, FAKE_USER_ID included: an impersonated
    # session has no Keycloak session behind it, and the fake-user branch would
    # quietly replace it with the fake user.
    try:
        impersonation = tokens.verify_impersonation_token(refresh_token)
    except tokens.TokenError as exc:
        logger.info("Impersonated session ended: %s", exc)
        return _end_session()

    if impersonation is not None:
        if not settings.ALLOW_IMPERSONATION:
            # Switching the flag off ends live impersonations at their next
            # refresh, rather than letting them run out their lifetime.
            logger.warning("Impersonation is disabled; ending impersonated session")
            return _end_session()

        # The same refresh token goes back out unchanged, so its expiry never moves.
        access_token, expires_in = _mint_impersonated_access_token(
            impersonation["identity"], impersonation["member_no"], impersonation["exp"]
        )
        return _set_impersonated_session(
            JSONResponse({}), access_token, expires_in, refresh_token, impersonation["exp"]
        )

    if settings.FAKE_USER_ID:
        # Re-mint from the same claims. Roles are looked up again, so a role
        # change still lands within one token lifetime as it does for real users.
        return _apply_fake_session(JSONResponse({}))

    try:
        upstream = await oidc.refresh_tokens(refresh_token)
    except oidc.OIDCError as exc:
        if exc.error == "invalid_grant":
            # The session is genuinely over; clear it so the client stops retrying.
            return _end_session()
        logger.error("Token refresh failed: %s", exc)
        return JSONResponse({"error": "Upstream error"}, status_code=502)

    try:
        # Roles are recomputed here, so a role change takes effect within one
        # access-token lifetime instead of requiring a fresh login.
        return _apply_session(JSONResponse({}), upstream)
    except _SessionError as exc:
        logger.error("Could not refresh session: %s", exc)
        return JSONResponse({"error": "Upstream error"}, status_code=502)


@router.get(
    "/user",
    tags=["public"],
    summary="Get the current user",
    description=(
        "The signed-in user and their roles, read from the access-token cookie.\n\n"
        "Convenient for a frontend that just wants to show who is logged in. A "
        "backend should verify the cookie itself against `certs` rather than "
        "calling this on every request."
    ),
    responses={
        200: {
            "description": "The current user.",
            "content": {
                "application/json": {
                    "example": {
                        "user": {
                            "name": "Test Testsson",
                            "preferredUsername": "scoutnet|1234567",
                            "givenName": "Test",
                            "familyName": "Testsson",
                            "email": "test@example.se",
                            "picture": "https://example.se/avatars/1234567.jpg",
                            "memberNo": "1234567",
                            "roles": ["wsj27-app:admin", "wsj27-participant"],
                        }
                    }
                }
            },
        },
        401: {"description": "No cookie, or the token is expired or invalid."},
    },
)
async def user(request: Request) -> Response:
    access_token = request.cookies.get(constants.ACCESS_TOKEN)
    if not access_token:
        return _unauthorized()

    try:
        claims = tokens.verify_access_token(access_token)
    except tokens.TokenError as exc:
        # An expired or malformed token is an ordinary, expected condition, not
        # a server fault: answer 401 rather than letting the error surface as 500.
        logger.info("Rejected access token: %s", exc)
        return _unauthorized()

    return JSONResponse(_user_body(claims))


def _user_body(claims: dict[str, Any]) -> dict[str, Any]:
    """The /user response for a set of verified access-token claims."""
    return {
        "user": {
            "name": claims.get("name"),
            "preferredUsername": claims.get("preferred_username"),
            "givenName": claims.get("given_name"),
            "familyName": claims.get("family_name"),
            "email": claims.get("email"),
            "picture": claims.get("picture"),
            "memberNo": claims.get("member_no"),
            "roles": tokens.extract_roles(claims),
        }
    }


def _oauth_error(error: str, description: str, status_code: int = 400) -> JSONResponse:
    """An OAuth 2.0 error response (RFC 6749 section 5.2)."""
    response = JSONResponse({"error": error, "error_description": description}, status_code=status_code)
    if status_code == 401:
        # Required by RFC 6749 when the request used the Authorization header.
        response.headers["WWW-Authenticate"] = 'Basic realm="wsj27-auth-api"'
    return response


def _basic_auth_credentials(request: Request) -> tuple[str, str] | None:
    """Read client credentials from an HTTP Basic Authorization header."""
    header = request.headers.get("Authorization", "")
    if not header.startswith("Basic "):
        return None

    try:
        decoded = base64.b64decode(header[len("Basic ") :], validate=True).decode("utf-8")
    except binascii.Error, UnicodeDecodeError, ValueError:
        return None

    client_id, separator, client_secret = decoded.partition(":")
    if not separator:
        return None

    return client_id, client_secret


@router.post(
    "/token",
    tags=["public"],
    summary="Get a service-account token",
    description=(
        "Issues an access token to a machine caller using the OAuth 2.0 "
        "client-credentials grant. For server-to-server calls — a browser "
        "session comes from `login` instead.\n\n"
        "The token is the same kind a logged-in user gets: same key, same "
        "issuer, same role claims. A resource server verifies it identically "
        "and does not need to know which sort of caller it came from.\n\n"
        "Credentials are configured on this service, not on the upstream "
        "identity provider. Send them as HTTP Basic auth or as form fields.\n\n"
        "No refresh token is issued — request another when this one expires."
    ),
    responses={
        200: {
            "description": "A token.",
            "content": {
                "application/json": {
                    "example": {
                        "access_token": "eyJhbGciOiJSUzI1NiIs...",
                        "token_type": "Bearer",
                        "expires_in": 3600,
                    }
                }
            },
        },
        400: {"description": "Malformed request, or an unsupported grant type."},
        401: {"description": "Unknown client, or wrong secret."},
    },
)
async def token(
    request: Request,
    grant_type: str = Form(..., description="Must be `client_credentials`."),
    client_id: str | None = Form(None, description="Ignored when HTTP Basic auth is used."),
    client_secret: str | None = Form(None, description="Ignored when HTTP Basic auth is used."),
) -> Response:
    if grant_type != "client_credentials":
        return _oauth_error(
            "unsupported_grant_type",
            f"This endpoint only supports client_credentials, not {grant_type!r}.",
        )

    # Basic auth wins over the form fields, as in RFC 6749 section 2.3.1.
    credentials = _basic_auth_credentials(request)
    if credentials is None:
        if not client_id or not client_secret:
            return _oauth_error(
                "invalid_request",
                "Provide client credentials via HTTP Basic auth or the client_id/client_secret fields.",
            )
        credentials = (client_id, client_secret)

    requested_client_id, requested_secret = credentials

    granted_roles = service_clients.authenticate(requested_client_id, requested_secret)
    if granted_roles is None:
        # Deliberately does not say whether the client or the secret was wrong.
        return _oauth_error("invalid_client", "Client authentication failed.", status_code=401)

    access_token, expires_in = tokens.mint_service_token(requested_client_id, granted_roles)

    logger.info(
        "Issued service token for %s (%d role(s), %ds)",
        requested_client_id,
        len(granted_roles),
        expires_in,
    )

    return JSONResponse(
        {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": expires_in,
        }
    )


@router.get(
    "/logout",
    tags=["public"],
    summary="Log out",
    description=(
        "Clears the session cookies and ends the identity provider's session too, "
        "then returns the user to `redirect_uri`.\n\n"
        "Navigate the browser here — clearing only our cookies would leave the "
        "IdP session intact, and the next login would silently sign the same user "
        "straight back in."
    ),
    status_code=302,
    responses={
        302: {"description": "Logged out; redirect onward."},
        400: {"description": "`redirect_uri` is missing or its host is not allowed."},
    },
)
async def logout(
    request: Request,
    redirect_uri: str = Query(..., description="Where to send the user once they are logged out."),
) -> Response:
    if not _redirect_uri_valid(redirect_uri):
        return PlainTextResponse("Invalid redirect URI", status_code=400)

    # Read before clearing — it is the hint the IdP needs below.
    id_token = request.cookies.get(constants.ID_TOKEN)

    target = redirect_uri
    if id_token:
        # Clearing our cookies only ends the local session; without this the IdP
        # session survives and silently logs the user straight back in.
        try:
            end_session_url = oidc.build_end_session_url(
                post_logout_redirect_uri=redirect_uri,
                id_token=id_token,
            )
            if end_session_url:
                target = end_session_url
        except Exception:
            # Never strand the user on an error page once their session is gone.
            logger.exception("Could not build end-session URL; falling back to a local logout")

    response = RedirectResponse(target, status_code=REDIRECT_STATUS)
    cookies.clear_auth_cookies(response)
    return response


@router.get(
    "/certs",
    tags=["public"],
    summary="JSON Web Key Set",
    description=(
        "The public keys access tokens are signed with. Discover this URL from "
        "`.well-known/openid-configuration` (`jwks_uri`) rather than hardcoding "
        "it, so key rotation needs no change on your side.\n\n"
        "More than one key appears during a rotation: match on the token's `kid`."
    ),
    responses={200: {"description": "The key set."}},
)
async def certs() -> Response:
    """Our public signing keys.

    We sign the tokens ourselves, so this is the real key source — consumers
    verify against these, not against the IdP's keys.
    """
    return JSONResponse(get_jwks())


@router.get(
    "/.well-known/openid-configuration",
    tags=["public"],
    summary="OpenID configuration",
    description=(
        "Standard OIDC discovery. Start here: read `jwks_uri` from this document "
        "to find the verification keys, instead of hardcoding anything about this "
        "service or the upstream identity provider."
    ),
    responses={200: {"description": "The discovery document."}},
)
async def openid_configuration() -> Response:
    """Our own discovery document.

    Not a proxy of the IdP's: since we re-sign every token, the document must
    advertise our keys and our endpoints, so it describes this service
    throughout. Consumers follow jwks_uri from here and need know nothing about
    the upstream IdP.
    """
    base = settings.PUBLIC_URL
    return JSONResponse(
        {
            "issuer": settings.issuer,
            "authorization_endpoint": urljoin(base, "login"),
            "token_endpoint": urljoin(base, "token"),
            "end_session_endpoint": urljoin(base, "logout"),
            "userinfo_endpoint": urljoin(base, "user"),
            "jwks_uri": urljoin(base, "certs"),
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token", "client_credentials"],
            # Only the client-credentials grant uses the token endpoint; the
            # browser flow is driven by this service, not by the client.
            "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
            "scopes_supported": ["openid", "profile", "email"],
            "claims_supported": [
                "sub",
                "iss",
                "aud",
                "exp",
                "iat",
                "name",
                "preferred_username",
                "given_name",
                "family_name",
                "email",
                "picture",
                "member_no",
                "realm_access",
                "resource_access",
            ],
            "code_challenge_methods_supported": ["S256"],
        }
    )


class _SessionError(Exception):
    """The upstream token response could not be turned into a session."""


def _apply_session(response: Response, upstream: dict[str, Any]) -> Response:
    """Mint our token from an upstream token response and set the cookies."""
    logger.debug(
        "Upstream token response from %s: %s",
        settings.OIDC_SERVER,
        {k: upstream.get(k) for k in ("expires_in", "refresh_expires_in", "token_type", "scope")},
    )
    access_token = upstream.get("access_token")
    if not access_token:
        raise _SessionError("Upstream response contained no access_token")

    id_token = upstream.get("id_token")

    # Prefer the id_token as the identity source and verify its audience: it is
    # the token OIDC defines as proof of authentication. Fall back to the access
    # token for realms that do not return one on refresh.
    try:
        if id_token:
            source_claims = oidc.decode_upstream_token(id_token, verify_audience=True)
        else:
            source_claims = oidc.decode_upstream_token(access_token)
    except Exception as exc:
        raise _SessionError(f"Could not verify upstream token: {exc}") from exc

    if id_token:
        # The access token often carries claims the id_token lacks (member_no
        # among them, depending on realm mappers). Fill in without overriding.
        try:
            for name, value in oidc.decode_upstream_token(access_token).items():
                source_claims.setdefault(name, value)
        except Exception as exc:
            # Not fatal: the id_token already established identity.
            logger.debug("Could not decode upstream access token for extra claims: %s", exc)

    # Keycloak sends refresh_expires_in, but it is not a standard OIDC field, so
    # treat it as optional rather than failing the login without it.
    refresh_expires_in = upstream.get("refresh_expires_in")
    if not isinstance(refresh_expires_in, int) or refresh_expires_in <= 0:
        refresh_expires_in = settings.DEFAULT_REFRESH_EXPIRES_IN

    return _establish_session(
        response,
        source_claims,
        refresh_token=upstream.get("refresh_token"),
        id_token=id_token,
        refresh_expires_in=refresh_expires_in,
    )


def _establish_session(
    response: Response,
    source_claims: dict[str, Any],
    *,
    refresh_token: str | None,
    id_token: str | None,
    refresh_expires_in: int,
) -> Response:
    """Mint our token from a set of identity claims and set the session cookies."""
    member_no = roles.member_no_from_claims(source_claims)
    user_roles = roles.get_roles(member_no, source_claims)

    our_token, expires_in = tokens.mint_access_token(source_claims, user_roles, member_no)

    cookies.set_session_cookies(
        response,
        access_token=our_token,
        expires_in=expires_in,
        refresh_token=refresh_token,
        id_token=id_token,
        refresh_expires_in=refresh_expires_in,
    )

    logger.info(
        "Session established for %s (member_no=%s, %d role(s))",
        source_claims.get("preferred_username") or source_claims.get("sub"),
        member_no,
        len(user_roles),
    )

    return response


def _apply_fake_session(response: Response) -> Response:
    """Establish a session from FAKE_USER_ID, with no identity provider involved.

    The claims stand in for the ones the IdP would have returned, so everything
    downstream — member number, role lookup, the minted token, the cookies — is
    the ordinary path and behaves identically. Only the authentication is skipped.

    No id_token is set: we have no IdP-issued one to set, and its absence is what
    makes /logout fall through to a purely local logout instead of trying to end
    a session that was never started.
    """
    claims = dict(settings.FAKE_USER_ID)
    # Every real token has a subject; the validator guarantees one of the two.
    claims.setdefault("sub", claims.get("preferred_username"))

    return _establish_session(
        response,
        claims,
        # A placeholder, but a real cookie: /refresh keeps requiring it, so a
        # fake session still ends at /logout rather than reviving itself.
        refresh_token=FAKE_REFRESH_TOKEN,
        id_token=None,
        refresh_expires_in=settings.DEFAULT_REFRESH_EXPIRES_IN,
    )


# --- Impersonation (dev only) -------------------------------------------------
#
# For testing and demonstrating what another member can see. The session is
# replaced outright rather than annotated: consumers get an ordinary token for
# the impersonated member and cannot tell the difference, which is the point.
# Logging out is the only way back.


class ImpersonateRequest(BaseModel):
    member_no: str = Field(..., min_length=1, description="The member to become.", examples=["1234567"])


async def impersonate(request: Request, body: ImpersonateRequest) -> Response:
    # CSRF: SameSite=Lax keeps our cookies off cross-site POSTs already, and
    # FastAPI only parses this body from a JSON content type, which a plain
    # HTML form cannot send. Origin is checked too, when the browser sends one.
    origin = request.headers.get("origin")
    if origin is not None and not _redirect_uri_valid(origin):
        return JSONResponse({"error": "Origin not allowed"}, status_code=403)

    access_token = request.cookies.get(constants.ACCESS_TOKEN)
    if not access_token:
        return _unauthorized()

    try:
        claims = tokens.verify_access_token(access_token)
    except tokens.TokenError as exc:
        logger.info("Rejected access token: %s", exc)
        return _unauthorized()

    # Read from the token, so a caller already impersonating holds the target's
    # roles: switching on requires the target to hold this role as well.
    if settings.IMPERSONATOR_ROLE not in tokens.extract_roles(claims):
        return JSONResponse({"error": "Forbidden"}, status_code=403)

    target = body.member_no.strip()

    if not roles.cache_loaded():
        return JSONResponse({"error": "Roles are not loaded yet"}, status_code=503)

    # Only members the upstream lists: anyone else would get DEFAULT_ROLES, and
    # a mistyped number would pass that off as the member's own view.
    if roles.lookup(target) is None:
        return JSONResponse({"error": "Unknown member"}, status_code=404)

    identity = _impersonated_identity(claims, target)
    expires_at = int(time.time()) + settings.IMPERSONATION_TTL_SECONDS

    new_access_token, expires_in = _mint_impersonated_access_token(identity, target, expires_at)
    refresh_token = tokens.mint_impersonation_token(identity, target, expires_at)

    # WARNING, not INFO: whatever is done from here on is attributed to the
    # target member, and this line is the only record of who was really behind it.
    logger.warning(
        "%s (sub=%s, member_no=%s) is now impersonating member %s for %ds",
        claims.get("name"),
        claims.get("sub"),
        claims.get("member_no"),
        target,
        settings.IMPERSONATION_TTL_SECONDS,
    )

    response = JSONResponse(_user_body(tokens.verify_access_token(new_access_token)))
    return _set_impersonated_session(response, new_access_token, expires_in, refresh_token, expires_at)


def _impersonated_identity(claims: dict[str, Any], target: str) -> dict[str, Any]:
    """The caller's identity claims, adjusted to belong to `target`.

    Name and email stay the caller's; the member number is what consumers look a
    user's own data up by, and that is set to the target's when minting.

    `picture` is dropped because consumers write it back to the member record
    keyed by member number — keeping it would put the caller's avatar on the
    target's record.

    `preferred_username` follows the member number when it ends with it, so a
    consumer parsing the number out of the username agrees with `member_no`. A
    plain suffix match, so the IdP's username format is never hardcoded here.
    """
    identity = {name: claims[name] for name in tokens.IDENTITY_CLAIMS if name in claims and name != "picture"}

    current = claims.get("member_no")
    username = identity.get("preferred_username")
    if isinstance(current, str) and current and isinstance(username, str) and username.endswith(current):
        prefix = username.removesuffix(current)
        # "scoutnet|1234567" ends with "4567" too; only a whole number counts.
        if not prefix or not prefix[-1].isdigit():
            identity["preferred_username"] = prefix + target

    return identity


def _mint_impersonated_access_token(identity: dict[str, Any], member_no: str, expires_at: int) -> tuple[str, int]:
    """Mint the access token of an impersonated session.

    Roles are looked up afresh on every refresh, so a change upstream lands
    within one token lifetime, as it does for a real session. The token never
    outlives the impersonation itself.
    """
    remaining = max(1, expires_at - int(time.time()))
    return tokens.mint_access_token(identity, roles.get_roles(member_no), member_no, expires_in=remaining)


def _set_impersonated_session(
    response: Response, access_token: str, expires_in: int, refresh_token: str, expires_at: int
) -> Response:
    """Set the cookies of an impersonated session."""
    cookies.set_session_cookies(
        response,
        access_token=access_token,
        expires_in=expires_in,
        refresh_token=refresh_token,
        id_token=None,
        refresh_expires_in=max(1, expires_at - int(time.time())),
    )
    # Keycloak's id_token is the real user's. Without it /logout ends only our
    # session and leaves Keycloak's alive, so the next /login silently signs the
    # real user back in — which is what makes logout the way back.
    cookies.delete_cookie(response, constants.ID_TOKEN)
    return response


# Registered only when enabled, so a deployment without it has no such route at
# all: a plain 404, and nothing in the OpenAPI document to suggest otherwise.
if settings.ALLOW_IMPERSONATION:
    router.post(
        "/impersonate",
        tags=["public"],
        summary="Become another member (dev only)",
        description=(
            "Replaces the current session with one for another member: their "
            "member number and their roles. Name and email stay the caller's; "
            "`picture` is dropped. Consumers receive an ordinary token.\n\n"
            "Requires the configured impersonator role. Lasts a fixed time that "
            "refreshing does not extend; logging out is the only way back.\n\n"
            "Call with `fetch` and a JSON body. Only enabled in test environments."
        ),
        responses={
            200: {"description": "Now impersonating; new cookies set. Returns the new `user`."},
            401: {"description": "No valid session."},
            403: {"description": "Not permitted, or the request came from a disallowed origin."},
            404: {"description": "The member has no roles in this project."},
            503: {"description": "Roles have not been loaded yet."},
        },
    )(impersonate)
