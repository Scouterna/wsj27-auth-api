"""Application settings, read from the environment (and a local .env file).

`env_file=".env"` resolves relative to the working directory, so run the app from
`src/` — as start.py's launch config and the container CMD both do.
"""

from functools import lru_cache
from typing import Annotated, Any

from pydantic import field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict


class Settings(BaseSettings):
    # --- Public identity of this service ---
    # External base URL including the base path, e.g. https://app.wsj.se/auth
    # Normalized to exactly one trailing slash so urljoin() behaves predictably.
    PUBLIC_URL: str
    # Comma-separated allowlist of hosts (with port, if non-default) that
    # /login and /logout will redirect back to.
    # NoDecode stops pydantic-settings JSON-decoding the env value, so the
    # plain "a,b,c" spelling reaches the validator below.
    ALLOWED_REDIRECT_DOMAINS: Annotated[list[str], NoDecode] = []

    # --- Upstream Keycloak (the identity source, invisible to our consumers) ---
    OIDC_SERVER: str
    OIDC_CLIENT_ID: str
    OIDC_CLIENT_SECRET: str

    # --- Our own token signing ---
    # RSA private key in PEM form. Required: without it we cannot mint tokens.
    SIGNING_KEY: str = ""
    # Optional verify-only key, published in the JWKS so tokens signed by the
    # previous key stay valid across a rotation. Never used to sign.
    SIGNING_KEY_PREVIOUS: str = ""
    AUDIENCE: str = "wsj27"
    ACCESS_TOKEN_TTL_SECONDS: int = 300
    # Keycloak's refresh_expires_in is non-standard; fall back to this if absent.
    DEFAULT_REFRESH_EXPIRES_IN: int = 1800

    # --- Roles (from wsj27-project-api) ---
    ROLE_SYNC_INTERVAL_MINUTES: int = 60
    # Base URL of wsj27-project-api. In-cluster this is a Service DNS name; the
    # bulk endpoint is private, so it is never reached through the ingress.
    PROJECT_API_URL: str = ""
    PROJECT_API_TIMEOUT: float = 15.0
    # Which of our own service-account clients to mint a token as when calling
    # project-api. Must have an entry in SERVICE_CLIENT_ROLES granting the role
    # project-api requires.
    PROJECT_API_CLIENT_ID: str = "wsj27-auth"
    # Dev-only: seed the role cache from a JSON file of {member_no: [roles]},
    # bypassing project-api entirely.
    STUB_ROLES_FILE: str = ""
    # Roles granted to any authenticated user with no cache entry of their own.
    DEFAULT_ROLES: Annotated[list[str], NoDecode] = []
    # Client id used for the resource_access block of the minted token.
    ROLE_CLIENT_ID: str = "wsj27-app"

    # --- Service accounts (machine-to-machine callers) ---
    # Both are JSON objects. Split by sensitivity: roles are reviewable config
    # and belong in the ConfigMap, secrets belong in the Secret.
    #   SERVICE_CLIENT_ROLES:   {"client-id": ["role", ...], ...}
    #   SERVICE_CLIENT_SECRETS: {"client-id": "secret", ...}
    # envFrom does not hot-reload, so changing either needs a pod restart.
    SERVICE_CLIENT_ROLES: dict[str, list[str]] = {}
    SERVICE_CLIENT_SECRETS: dict[str, str] = {}
    # Longer than the browser TTL: there is no refresh loop behind these, the
    # client simply asks for another token.
    SERVICE_TOKEN_TTL_SECONDS: int = 3600

    # --- Dev-only: bypass the identity provider ---
    # A JSON object of identity claims, as the IdP would have returned them.
    # When set, /login and /refresh mint a session from it and no call is made
    # to the IdP at all — not even discovery at startup. Anyone who reaches
    # /login is signed in as this user, so it belongs in local testing only.
    FAKE_USER_ID: dict[str, Any] = {}

    # --- Serving ---
    ROOT_PATH: str = ""
    PORT: int = 8000
    DEBUG: bool = False
    # Drop the Secure attribute so cookies work over plain HTTP locally.
    INSECURE_COOKIES: bool = False

    model_config = SettingsConfigDict(env_file=".env")

    @field_validator("PUBLIC_URL")
    @classmethod
    def _normalize_public_url(cls, value: str) -> str:
        return value.rstrip("/") + "/"

    @field_validator("ALLOWED_REDIRECT_DOMAINS", "DEFAULT_ROLES", mode="before")
    @classmethod
    def _split_csv(cls, value: object) -> object:
        """Accept a comma-separated string as well as a real list.

        pydantic-settings would otherwise try to JSON-decode the env value for a
        list field, which makes the natural `A,B,C` spelling an error.
        """
        if isinstance(value, str):
            return [item.strip() for item in value.split(",") if item.strip()]
        return value

    @field_validator("FAKE_USER_ID")
    @classmethod
    def _require_identity(cls, value: dict[str, Any]) -> dict[str, Any]:
        """Reject a fake user we could not derive a subject for.

        Without one of these the minted token has no `sub` and no member number,
        so roles silently come out empty — exactly the sort of quiet wrongness
        that makes a test look like a bug in the app under test.
        """
        if value and not (value.get("sub") or value.get("preferred_username")):
            raise ValueError("FAKE_USER_ID needs a 'sub' or 'preferred_username' claim")
        return value

    @property
    def issuer(self) -> str:
        """Our `iss` claim: PUBLIC_URL without the trailing slash."""
        return self.PUBLIC_URL.rstrip("/")


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
