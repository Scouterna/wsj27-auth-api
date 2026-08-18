"""Minting and verifying our own access tokens.

The whole point of this service: Keycloak authenticates the user, but its tokens
do not carry the roles WSJ27 needs. So we take Keycloak's identity claims, attach
roles computed from Scoutnet data, and sign the result with our own key.

Consumers only ever see our token — they discover our JWKS through our
/.well-known/openid-configuration and never learn Keycloak exists.

Roles are emitted in Keycloak's own claim shape (`realm_access.roles` and
`resource_access.<client>.roles`) rather than a bespoke one, so that any consumer
able to read a standard Keycloak token can read ours: realm roles bare, client
roles namespaced as "client:role".
"""

import logging
import time
import uuid
from typing import Any

from joserfc import jwt
from joserfc.errors import JoseError

from .config import get_settings
from .keys import ALGORITHM, get_signing_key, get_verification_key_set

logger = logging.getLogger(__name__)

settings = get_settings()

# Identity claims copied from the IdP's token into ours. Everything else it
# sends (session state, allowed origins, its own realm_access, ...) is dropped:
# it is not useful to our consumers and it makes the cookie bigger.
IDENTITY_CLAIMS = (
    "sub",
    "name",
    "preferred_username",
    "given_name",
    "family_name",
    "email",
    "email_verified",
    "locale",
)


class TokenError(Exception):
    """Raised when an access token cannot be verified."""


def _sign(claims: dict[str, Any], expires_in: int) -> tuple[str, int]:
    """Add the registered claims and sign. Returns (token, expires_in_seconds)."""
    now = int(time.time())

    claims = {
        "iss": settings.issuer,
        "aud": settings.AUDIENCE,
        "iat": now,
        "nbf": now,
        "exp": now + expires_in,
        "jti": str(uuid.uuid4()),
        "typ": "Bearer",
        **claims,
    }

    key = get_signing_key()
    header = {"alg": ALGORITHM, "kid": key.kid, "typ": "JWT"}

    return jwt.encode(header, claims, key), expires_in


def mint_access_token(
    source_claims: dict[str, Any],
    roles: list[str],
    member_no: str | None = None,
) -> tuple[str, int]:
    """Build and sign a user's access token, from the IdP's claims plus roles.

    `member_no` is passed in already resolved (the caller needs it anyway, to
    look up the roles). It is emitted under that one name whatever the IdP calls
    it — ScoutID uses `scoutnet_member_no` — so consumers read a stable claim
    and are insulated from the realm's naming.
    """
    claims: dict[str, Any] = {}

    for name in IDENTITY_CLAIMS:
        value = source_claims.get(name)
        if value is not None:
            claims[name] = value

    if member_no is not None:
        claims["member_no"] = member_no

    claims.update(_role_claims(roles))

    return _sign(claims, settings.ACCESS_TOKEN_TTL_SECONDS)


def mint_service_token(client_id: str, roles: list[str]) -> tuple[str, int]:
    """Build and sign a service account's access token.

    Deliberately the same token type as a user's — same key, issuer and role
    claims — so a resource server verifies both with one code path and does not
    need to care which kind of caller it is talking to.

    `preferred_username` is set even though no person is involved: consumers
    commonly model it as a required field, and omitting it turns an ordinary
    request into a confusing 500. The `service-account-<client_id>` spelling is
    Keycloak's own convention, so logs and attribution read sensibly.
    """
    username = f"service-account-{client_id}"

    claims: dict[str, Any] = {
        "sub": username,
        "preferred_username": username,
        "name": username,
        # azp is the standard "authorized party" claim; client_id is included
        # because it is what most tooling looks for.
        "azp": client_id,
        "client_id": client_id,
    }

    claims.update(_role_claims(roles))

    return _sign(claims, settings.SERVICE_TOKEN_TTL_SECONDS)


def _role_claims(roles: list[str]) -> dict[str, Any]:
    """Split roles into Keycloak's realm/resource shape.

    A role containing a colon ("wsj27-app:admin") is a client role and goes under
    resource_access for that client; anything else is a realm role. This mirrors
    how consumers flatten them back out, so the round-trip is lossless.

    The split is on the **first** colon only, which is what makes WSJ27's
    three-part roles work: "wsj27:ledare:43" becomes resource_access["wsj27"] =
    ["ledare:43"] and reassembles exactly. Splitting on every colon would
    corrupt them, so keep partition() rather than switching to split().
    """
    realm_roles: list[str] = []
    resource_roles: dict[str, list[str]] = {}

    for role in roles:
        client, separator, name = role.partition(":")
        if separator and client and name:
            resource_roles.setdefault(client, []).append(name)
        else:
            realm_roles.append(role)

    claims: dict[str, Any] = {"realm_access": {"roles": realm_roles}}

    if resource_roles:
        claims["resource_access"] = {client: {"roles": names} for client, names in resource_roles.items()}

    return claims


def verify_access_token(token: str) -> dict[str, Any]:
    """Verify one of our own tokens. Raises TokenError if it is not valid."""
    try:
        decoded = jwt.decode(token, get_verification_key_set(), algorithms=[ALGORITHM])
        registry = jwt.JWTClaimsRegistry(
            leeway=30,
            iss={"essential": True, "value": settings.issuer},
            aud={"essential": True, "value": settings.AUDIENCE},
        )
        registry.validate(decoded.claims)
    except (JoseError, ValueError) as exc:
        raise TokenError(str(exc)) from exc

    return dict(decoded.claims)


def extract_roles(claims: dict[str, Any]) -> list[str]:
    """Flatten our role claims back into a single list.

    Same rules as the consumer-side helper: realm roles bare, client roles
    namespaced "client:role".
    """
    roles: set[str] = set()

    realm_access = claims.get("realm_access") or {}
    for role in realm_access.get("roles") or []:
        if isinstance(role, str):
            roles.add(role)

    resource_access = claims.get("resource_access") or {}
    for client, resource in resource_access.items():
        if not isinstance(resource, dict):
            continue
        for role in resource.get("roles") or []:
            if isinstance(role, str):
                roles.add(f"{client}:{role}")

    return sorted(roles)
