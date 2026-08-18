"""Our own RSA signing key, and the JWKS we publish for it.

This is what makes wsj27-auth-api different from a plain OIDC proxy: consumers
verify tokens against *our* key, not Keycloak's, because we re-sign every token
after adding the roles Keycloak does not carry.

The key comes from the environment (a k8s secret in production) rather than being
generated at startup, for two reasons: restarts must not invalidate live cookies,
and every replica must sign with the same key.

SIGNING_KEY_PREVIOUS is verify-only. Publishing it in the JWKS alongside the
active key means a rotation does not invalidate tokens already in the wild:
promote the new key to SIGNING_KEY, move the old one to SIGNING_KEY_PREVIOUS, and
drop it once the longest access-token lifetime has elapsed.
"""

import logging

from joserfc.jwk import KeySet, RSAKey

from .config import get_settings

logger = logging.getLogger(__name__)

settings = get_settings()

ALGORITHM = "RS256"

_signing_key: RSAKey | None = None
_key_set: KeySet | None = None


class SigningKeyError(RuntimeError):
    """Raised when the configured signing key is missing or unusable."""


def _import_key(pem: str, label: str) -> RSAKey:
    # Env vars carrying PEM data often arrive with literal "\n" instead of real
    # newlines (docker --env, some CI secret stores). Repair that transparently.
    if "\\n" in pem and "\n" not in pem:
        pem = pem.replace("\\n", "\n")

    try:
        key = RSAKey.import_key(pem.strip())
    except Exception as exc:
        raise SigningKeyError(f"Could not parse {label} as an RSA private key: {exc}") from exc

    # A public key would import fine but fail at signing time with a far more
    # confusing error, so reject it here where the message can be useful.
    if not key.is_private:
        raise SigningKeyError(f"{label} is a public key; an RSA *private* key is required")

    # Give the key a stable, deterministic kid (RFC 7638 thumbprint) so the JWKS
    # `kid` survives restarts and matches across replicas.
    if not key.kid:
        key.ensure_kid()

    return key


def init_keys() -> None:
    """Load the signing keys. Call once at startup; raises if unusable."""
    global _signing_key, _key_set

    if not settings.SIGNING_KEY:
        raise SigningKeyError(
            "SIGNING_KEY is not set. Generate one with:\n  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048"
        )

    signing_key = _import_key(settings.SIGNING_KEY, "SIGNING_KEY")
    keys = [signing_key]

    if settings.SIGNING_KEY_PREVIOUS:
        previous = _import_key(settings.SIGNING_KEY_PREVIOUS, "SIGNING_KEY_PREVIOUS")
        if previous.kid == signing_key.kid:
            logger.warning("SIGNING_KEY_PREVIOUS is the same key as SIGNING_KEY; ignoring it")
        else:
            keys.append(previous)
            logger.info("Accepting tokens signed by previous key kid=%s", previous.kid)

    _signing_key = signing_key
    _key_set = KeySet(keys)

    logger.info("Signing key loaded, kid=%s alg=%s", signing_key.kid, ALGORITHM)


def get_signing_key() -> RSAKey:
    """The key new tokens are signed with."""
    if _signing_key is None:
        raise SigningKeyError("Signing key not initialised; init_keys() was not called")
    return _signing_key


def get_verification_key_set() -> KeySet:
    """Active key plus any previous key, for verifying incoming tokens."""
    if _key_set is None:
        raise SigningKeyError("Signing key not initialised; init_keys() was not called")
    return _key_set


def get_jwks() -> dict:
    """The public JWKS document served at /certs.

    `private=False` is what keeps the private material out of the response.
    """
    key_set = get_verification_key_set()
    jwks = key_set.as_dict(private=False)

    for key in jwks.get("keys", []):
        key.setdefault("use", "sig")
        key.setdefault("alg", ALGORITHM)

    return jwks
