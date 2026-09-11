# wsj27-auth-api

Handles the login flow for the WSJ27 apps and sets the cookies they read.

Deployed at `https://app.wsj.se/auth`, alongside the other apps on that host. A
user logs in once; every app under `app.wsj.se` sees the session, because the
cookies are set with `Path=/`.

## How it works

The service is an OIDC front end for browsers: it runs the authorization-code
flow against Keycloak and turns the result into cookies, so the apps behind it
never handle the login flow themselves.

It does **not** hand Keycloak's tokens to the browser. The ScoutID Keycloak realm
available to WSJ27 **does not carry the roles this project needs**, so instead
this service:

1. authenticates the user against Keycloak as usual,
2. looks up their roles, which the project API derives from Scoutnet data,
3. mints a **new** token containing Keycloak's identity claims plus those roles,
4. signs it with **its own key**, and
5. publishes **its own** JWKS and discovery document.

Consumers therefore trust this service, not Keycloak. Keycloak is an
implementation detail they never see.

Keycloak's refresh token is still kept (httpOnly) so `/refresh` can re-mint, and
its ID token is kept as the `id_token_hint` for RP-initiated logout.

## Endpoints

| Endpoint | Purpose |
|---|---|
| `GET /login?redirect_uri=…` | Start the login flow. Optional `silent=true` (no prompt) and `locale=sv\|en`. Redirects to Keycloak. |
| `GET /callback` | Keycloak redirects here. Mints our token, sets cookies, returns the user to `redirect_uri`. |
| `GET /refresh` | Re-mints the access token from the refresh cookie. `200 {}` on success, `401` when the session is over. **Roles are recomputed here.** |
| `GET /user` | The current user and their roles. `401` if not logged in. |
| `GET /logout?redirect_uri=…` | Clears cookies and ends the Keycloak session too. |
| `GET /certs` | Our JWKS — the public half of the signing key. |
| `GET /.well-known/openid-configuration` | Our discovery document. |
| `GET /static/refresh.js` | Client-side auto-refresh loop for consumer apps to embed. |
| `POST /token` | Service-account token via the client-credentials grant. For machine callers. |
| `GET /docs` | Swagger UI (also `/redoc`, `/openapi.json`). |
| `GET /` | Health check. |

`redirect_uri` must be on a host in `ALLOWED_REDIRECT_DOMAINS`, or the request is
rejected with `400`.

## Cookies

Prefix `wsj27-auth_`, all `Path=/`, `SameSite=Lax`, `Secure` unless
`INSECURE_COOKIES=true`.

| Cookie | Contents | httpOnly |
|---|---|---|
| `access-token` | **our** re-signed JWT | yes |
| `refresh-token` | Keycloak's refresh token | yes |
| `id-token` | Keycloak's ID token (logout hint) | yes |
| `refresh-expires-at` | ms epoch | yes |
| `expires-at` | ms epoch | **no** — `refresh.js` reads it |
| `oidc-code-verifier`, `oidc-state`, `redirect-uri` | login round-trip only, 30 min | yes |

## Consuming the session

Verify the `wsj27-auth_access-token` cookie as a normal JWT: fetch
`auth/.well-known/openid-configuration` relative to your own base URL, follow
`jwks_uri`, and validate. Do not hardcode the key or the IdP location.

Any library that validates a standard Keycloak token will validate ours, since
the claim shape is the same.

Roles arrive in Keycloak's claim shape, so the usual extraction works:

```jsonc
{
  "realm_access":    { "roles": ["wsj27-participant"] },
  "resource_access": { "wsj27-app": { "roles": ["admin"] } }
}
```
Realm roles are read bare (`wsj27-participant`); client roles are conventionally
namespaced as `wsj27-app:admin`.

Embed the refresh script so sessions do not lapse while someone is using the app:

```html
<script src="/auth/static/refresh.js"></script>
```

## Machine callers

A backend calling a WSJ27 API on its own behalf gets a token from `/token`:

```bash
curl -u <client-id>:<secret> -d grant_type=client_credentials \
  https://app.wsj.se/auth/token
# {"access_token": "...", "token_type": "Bearer", "expires_in": 3600}
```

then sends it as `Authorization: Bearer <token>`.

These credentials belong to this service, not to the identity provider: ScoutID
authenticates scout members and holds nothing project-specific, so WSJ27's
service accounts live in `SERVICE_CLIENT_ROLES` / `SERVICE_CLIENT_SECRETS` here.

The token is deliberately the same kind a user gets — same key, issuer and role
claims — so a resource server verifies user and machine callers with one code
path. Read the cookie or the `Authorization` header, whichever is present:

```python
token = request.cookies.get("wsj27-auth_access-token")
if not token:
    header = request.headers.get("Authorization", "")
    if header.startswith("Bearer "):
        token = header.removeprefix("Bearer ")
```

Service tokens carry `preferred_username` = `service-account-<client-id>` and no
`member_no`.

## Roles

**This service does not decide who holds which role.** The project API is the
authority: it derives roles from Scoutnet project data and serves a finished
`member_no -> roles` map at `PROJECT_API_URL`. We fetch that map on a timer,
cache it, and look users up in it.

That split is deliberate. Nothing project-specific lives here — no member types,
no role names, no namespace — so reusing this service for another project means
pointing `PROJECT_API_URL` somewhere else, not editing code. It also keeps the
definition of a role next to the API that enforces it, rather than splitting
producer and consumer across two repositories.

The map is refreshed every `ROLE_SYNC_INTERVAL_MINUTES`, using `If-None-Match`
so an unchanged upstream costs a 304 with no body. Lookups never block on that
fetch: if the cache is cold or the project API is down, users get `DEFAULT_ROLES`
and login still works.

Users are looked up by the `member_no` claim, falling back to `sub`.

Set `STUB_ROLES_FILE` to a JSON file of `{"member_no": ["role", ...]}` to
exercise role-dependent code without the project API running.

## Running locally

```bash
uv sync
cp .env.example src/.env      # then fill in OIDC_CLIENT_SECRET and SIGNING_KEY
cd src && uv run python start.py
```

From VSCode, press <kbd>F5</kbd> and pick **wsj27-auth-api** (or
**wsj27-auth-api (debug logging)** to step into library code and see the token
and role machinery in detail). Both run `src/start.py` with `src/` as the working
directory, which is where `.env` is read from.

`uv sync` must have been run first: F5 needs `debugpy` from the dev dependency
group, and without it the debugger fails to start before the app logs anything.
The launch configs pin the interpreter to `.venv/bin/python`, so they work
regardless of which interpreter the editor has selected.

Generate a signing key:

```bash
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048
```

Quote it in `.env`, since it spans several lines:

```bash
printf 'SIGNING_KEY="%s"\n' "$(cat key.pem)" >> src/.env
```

For local HTTP set `INSECURE_COOKIES=true`, otherwise the browser will drop the
cookies. See `.env.example` for every setting.

### Testing apps without the identity provider

Set `FAKE_USER_ID` to a JSON object of identity claims and `/login` signs that
user straight in, while `/refresh` re-mints for them. The identity provider is
never contacted — not even for discovery at startup — so the apps can be driven
without a working Keycloak client:

```bash
FAKE_USER_ID={"name": "Test Testsson", "preferred_username": "scoutnet|1234567", "email": "test@example.se"}
```

Everything downstream is the real path: the member number is read from these
claims (`scoutnet|1234567` → `1234567`), roles are looked up for it as usual,
and the same cookies are set — so pair it with `STUB_ROLES_FILE` or a running
project-api to test a role. `/logout` ends the session normally.

Anyone who reaches `/login` is signed in as this user, so it is for local
testing only. The service logs a warning at startup and on every login while it
is set.

### With docker-compose

```bash
cp .env.example src/.env      # then fill in OIDC_CLIENT_SECRET and SIGNING_KEY
podman compose up --build
```

`docker-compose.yml` loads `src/.env` directly, so it's the same config file
used to run the app without a container. Not used in production — there the
image is built via the `Dockerfile` and configured from a k8s ConfigMap and
Secret instead.

## Key rotation

`SIGNING_KEY` signs; `SIGNING_KEY_PREVIOUS` is published in the JWKS but never
signs. To rotate without invalidating live sessions: move the current key to
`SIGNING_KEY_PREVIOUS`, put the new one in `SIGNING_KEY`, redeploy, then drop
`SIGNING_KEY_PREVIOUS` once `ACCESS_TOKEN_TTL_SECONDS` has elapsed.

The `kid` is the key's RFC 7638 thumbprint, so it is stable across restarts and
identical on every replica.

## Deployment notes

- The app serves its routes at the root; the ingress adds and strips `/auth`.
  All externally-visible URLs are built from `PUBLIC_URL`, so that must include
  the base path (`https://app.wsj.se/auth`).
- `SIGNING_KEY` must come from a secret, and must be the same for every replica.
  There is no in-process state otherwise, so the service scales horizontally.
- Every host in `ALLOWED_REDIRECT_DOMAINS` must also be registered as a valid
  post-logout redirect URI on the Keycloak client, or logout will strand users.
- Not yet written: CI and a test suite.
