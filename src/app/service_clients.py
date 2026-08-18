"""Service accounts — machine-to-machine callers of the WSJ27 APIs.

The upstream ScoutID Keycloak is a generic platform for authenticating scout
members and deliberately carries nothing project-specific, so it cannot hold
WSJ27 service accounts any more than it can hold WSJ27 roles. This app is
already the authority for those roles, so it is the authority for these clients
too.

Credentials and roles come from configuration: roles from the ConfigMap (plain
config, reviewable in git) and secrets from the Secret. Both are expected to
change rarely; `envFrom` does not hot-reload, so adding or rotating a client
needs a pod restart.
"""

import hmac
import logging

from .config import get_settings

logger = logging.getLogger(__name__)

settings = get_settings()

# Compared against when the client id is unknown, so that an unknown client and
# a wrong secret take the same time and cannot be told apart by timing.
_DUMMY_SECRET = "no-such-client-secret-placeholder-value"


def init_service_clients() -> None:
    """Log a summary and warn about half-configured clients. Call at startup.

    A client with a secret but no roles authenticates and can then do nothing,
    and one with roles but no secret can never authenticate. Both are almost
    always a typo in one of the two config keys, and both are invisible at
    runtime until someone reports a puzzling 401 or 403 — so say so at boot.
    """
    with_secrets = set(settings.SERVICE_CLIENT_SECRETS)
    with_roles = set(settings.SERVICE_CLIENT_ROLES)

    if not with_secrets and not with_roles:
        logger.info("No service accounts configured")
        return

    for client_id in sorted(with_secrets - with_roles):
        logger.warning("Service account %r has a secret but no roles; it will be able to do nothing", client_id)

    # Our own outbound client is minted internally rather than via /token, so it
    # deliberately has no secret. Warning about it would point at a non-problem —
    # and having no secret is what stops anyone else claiming its roles.
    internal = {settings.PROJECT_API_CLIENT_ID}
    for client_id in sorted(with_roles - with_secrets - internal):
        logger.warning("Service account %r has roles but no secret; it can never authenticate", client_id)

    usable = sorted(with_secrets & with_roles)
    logger.info(
        "Service accounts configured: %s (internal: %s)",
        ", ".join(usable) if usable else "none",
        ", ".join(sorted(with_roles & internal)) or "none",
    )


def authenticate(client_id: str, client_secret: str) -> list[str] | None:
    """Check machine credentials.

    Returns the client's roles on success, or None if the id is unknown or the
    secret is wrong — the caller must not distinguish the two.
    """
    expected = settings.SERVICE_CLIENT_SECRETS.get(client_id)

    # Run the comparison even when the client is unknown, so both failures cost
    # the same. compare_digest needs bytes to be safe for non-ASCII secrets.
    secret_matches = hmac.compare_digest(
        (expected or _DUMMY_SECRET).encode("utf-8"),
        client_secret.encode("utf-8"),
    )

    if expected is None or not secret_matches:
        logger.warning("Rejected service-account credentials for client_id=%r", client_id)
        return None

    roles = settings.SERVICE_CLIENT_ROLES.get(client_id)
    if not roles:
        # Authentication succeeded, so this is a config gap rather than an
        # attack; init_service_clients() already warned about it at startup.
        logger.warning("Service account %r authenticated but has no roles configured", client_id)
        return []

    return list(roles)
