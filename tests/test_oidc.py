"""Verifying upstream tokens, and where we let the browser go afterwards.

Keycloak's tokens are signed here with throwaway RSA keys, and its JWKS endpoint
is a stubbed HTTP response. That keeps the reload path honest: the code under
test does the real fetch-and-import, only the network is fake.
"""

import time

import pytest
from joserfc import jwt
from joserfc.errors import InvalidClaimError, InvalidKeyIdError, MissingClaimError
from joserfc.jwk import KeySet, RSAKey

from app import oidc, routes

ISSUER = "https://idp.example.test/realms/test"
JWKS_URI = f"{ISSUER}/protocol/openid-connect/certs"


def _key(kid):
    return RSAKey.generate_key(2048, parameters={"kid": kid})


def _sign(key, **claims):
    now = int(time.time())
    payload = {"iss": ISSUER, "aud": oidc.settings.OIDC_CLIENT_ID, "sub": "u1", "iat": now, "exp": now + 300}
    payload.update(claims)
    return jwt.encode({"alg": "RS256", "kid": key.kid}, payload, key)


class _JWKSResponse:
    """The parts of httpx.Response that _fetch_jwks touches."""

    def __init__(self, keys):
        self._body = KeySet(keys).as_dict(private=False)

    def raise_for_status(self):
        pass

    def json(self):
        return self._body


@pytest.fixture
def upstream(monkeypatch):
    """Keycloak as seen from here: an old key we loaded at startup, and a JWKS
    endpoint that may since have started serving something else.

    Returns a dict whose "keys" a test can change to rotate, and whose "fetches"
    counts how often the endpoint was actually hit.
    """
    old = _key("old")
    state = {"old": old, "keys": [old], "fetches": 0}

    async def fake_get(self, url, headers=None):
        assert url == JWKS_URI
        state["fetches"] += 1
        return _JWKSResponse(state["keys"])

    monkeypatch.setattr(oidc.httpx.AsyncClient, "get", fake_get)
    monkeypatch.setattr(oidc, "_metadata", {"issuer": ISSUER, "jwks_uri": JWKS_URI})
    monkeypatch.setattr(oidc, "_jwks", KeySet([old]))
    # Long enough ago that the cooldown does not block the first reload.
    monkeypatch.setattr(oidc, "_jwks_fetched_at", time.monotonic() - oidc.JWKS_RELOAD_COOLDOWN_SECONDS - 1)
    return state


# --- JWKS reload ----------------------------------------------------------------


@pytest.mark.asyncio
async def test_known_key_does_not_refetch(upstream):
    claims = await oidc.decode_upstream_token(_sign(upstream["old"]))

    assert claims["sub"] == "u1"
    assert upstream["fetches"] == 0


@pytest.mark.asyncio
async def test_rotated_key_is_picked_up_without_a_restart(upstream):
    """The bug this guards against: a Keycloak rotation broke every login and
    refresh until the pod restarted."""
    new = _key("new")
    upstream["keys"] = [new, upstream["old"]]

    claims = await oidc.decode_upstream_token(_sign(new))

    assert claims["sub"] == "u1"
    assert upstream["fetches"] == 1


@pytest.mark.asyncio
async def test_unknown_kids_cannot_hammer_keycloak(upstream):
    """Anyone can present a token with a made-up kid, so reloads are rate-limited."""
    stranger = _key("stranger")

    for _ in range(5):
        with pytest.raises(InvalidKeyIdError):
            await oidc.decode_upstream_token(_sign(stranger))

    assert upstream["fetches"] == 1


@pytest.mark.asyncio
async def test_reload_waits_out_the_cooldown(upstream, monkeypatch):
    monkeypatch.setattr(oidc, "_jwks_fetched_at", time.monotonic())
    new = _key("new")
    upstream["keys"] = [new]

    with pytest.raises(InvalidKeyIdError):
        await oidc.decode_upstream_token(_sign(new))
    assert upstream["fetches"] == 0


# --- Nonce ----------------------------------------------------------------------


@pytest.mark.asyncio
async def test_matching_nonce_is_accepted(upstream):
    claims = await oidc.decode_upstream_token(_sign(upstream["old"], nonce="n1"), verify_audience=True, nonce="n1")
    assert claims["nonce"] == "n1"


@pytest.mark.asyncio
async def test_mismatched_nonce_is_rejected(upstream):
    with pytest.raises(InvalidClaimError):
        await oidc.decode_upstream_token(_sign(upstream["old"], nonce="theirs"), nonce="ours")


@pytest.mark.asyncio
async def test_missing_nonce_is_rejected_when_one_is_expected(upstream):
    with pytest.raises(MissingClaimError):
        await oidc.decode_upstream_token(_sign(upstream["old"]), nonce="ours")


@pytest.mark.asyncio
async def test_nonce_is_not_checked_unless_asked(upstream):
    """Refresh-grant id_tokens are not answering an authorization request of ours."""
    await oidc.decode_upstream_token(_sign(upstream["old"], nonce="whatever"))


def test_authorization_url_carries_the_nonce(upstream, monkeypatch):
    monkeypatch.setitem(oidc._metadata, "authorization_endpoint", f"{ISSUER}/auth")

    url = oidc.build_authorization_url(code_challenge="c", state="s", nonce="n1")

    assert "nonce=n1" in url


# --- Redirect validation ----------------------------------------------------------


@pytest.fixture
def allowed(monkeypatch):
    monkeypatch.setattr(routes.settings, "ALLOWED_REDIRECT_DOMAINS", ["app.example.test", "localhost:5173"])


@pytest.mark.parametrize(
    "uri",
    [
        "https://app.example.test/",
        "https://app.example.test/some/deep/path?x=1",
        "http://localhost:5173/",
    ],
)
def test_redirect_accepted(allowed, uri):
    assert routes._redirect_uri_valid(uri)


@pytest.mark.parametrize(
    "uri",
    [
        # The downgrade this guards against.
        "http://app.example.test/",
        "javascript://app.example.test/%0aalert(1)",
        "ftp://app.example.test/",
        "//app.example.test/",
        # Host matching, which the scheme check must not loosen.
        "https://evil.example.test/",
        "https://user@app.example.test/",
        "https://app.example.test:8443/",
        "https://localhost/",
        "",
        None,
    ],
)
def test_redirect_rejected(allowed, uri):
    assert not routes._redirect_uri_valid(uri)
