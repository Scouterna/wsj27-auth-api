# wsj27-auth-api

Handles the browser login flow for the WSJ27 apps and sets the cookies they
read. Mounted under `/auth` on the host the apps share.

`README.md` covers usage and running it; this file covers the decisions behind
the code, so that changes don't accidentally undo them.

## The one thing to understand first

This service does **not** hand the identity provider's tokens to the browser.

The upstream Keycloak (ScoutID) is a generic platform for authenticating scout
members, and deliberately carries nothing project-specific — so it cannot hold
WSJ27's roles, and WSJ27 cannot add them there. Instead this service:

1. authenticates the user against Keycloak as usual,
2. looks up their roles, which the project API derives from Scoutnet data,
3. mints a **new** token with Keycloak's identity claims plus those roles,
4. signs it with **its own** key, and
5. publishes **its own** JWKS and discovery document.

Consumers therefore trust this service, not Keycloak. Keycloak is an
implementation detail they never see, and swapping it out does not invalidate a
single issued token.

Almost every non-obvious choice below follows from that.

## Invariants

Break these and things fail in ways that are hard to trace.

**One issuer, one JWKS, one verification path.** Browser sessions and machine
callers (`POST /token`, client-credentials) get the *same kind* of token — same
key, same issuer, same claim shape. A resource server verifies both with one
code path and needn't know which it is serving. Don't introduce a second token
type or a second issuer.

**Roles are emitted in Keycloak's claim shape** — `realm_access.roles` (bare)
and `resource_access.<client>.roles` (read as `client:role`) — even though we
mint the token ourselves. That's what lets any standard Keycloak-token consumer
read it unchanged. A bespoke `roles` claim would break every consumer.

**Nothing project-specific lives in this service.** We carry roles, we do not
define them: the project API serves a finished `member_no -> roles` map and this
service caches it. No member type, role name, or namespace string belongs in
this codebase — reusing it for another project must be a matter of pointing
`PROJECT_API_URL` elsewhere, not of editing code. Role *definitions* also belong
next to the API that enforces them; they lived here once, while project-api
matched them with hardcoded literals, and a namespace change here would silently
have changed who could read health data there.

**The signing key comes from configuration, never generated at startup.**
Restarts must not invalidate live cookies, and every replica must sign
identically. `SIGNING_KEY_PREVIOUS` is verify-only, so rotation doesn't log
everyone out. The `kid` is the RFC 7638 thumbprint, so it is stable and
identical across replicas.

**Every externally visible URL is built from `PUBLIC_URL`**, never from the
incoming request path. An ingress strips the `/auth` prefix before requests
arrive, so the app cannot see its own public path. In particular the
`redirect_uri` sent to the IdP must be byte-identical between `/login` and
`/callback`, which is why both derive it the same way.

`ROOT_PATH` is a *different* thing: it only affects generated links (OpenAPI /
Swagger UI). Conflating the two is a real trap — it looks like it should fix
redirect URLs and doesn't.

**Machine tokens still carry `preferred_username`** (`service-account-<id>`).
Consumers commonly model that field as required; a token without it produces a
confusing 500 rather than a clean 401.

**Service-account credentials live in this service's own config**, not in the
IdP — same reason as the roles. `SERVICE_CLIENT_ROLES` is ordinary config;
`SERVICE_CLIENT_SECRETS` is secret. A client needs an entry in both.

**Cookies set `Path=/` explicitly**, on both set and delete. The apps share one
host and read each other's cookies; without an explicit path the browser scopes
them to `/auth` and cross-app reads work only by accident.

## Shared-host deployment

One frontend app-shell owns the base host; the other apps mount under path
prefixes of it. This service is one of those.

**Only the app-shell's ingress may declare `tls:`/`secretName` for that host.**
Every other ingress on it must omit the `tls:` block and contribute only `host`
+ `path` rules — two ingresses ordering a certificate for one host fight over
it. Where no shell exists yet, reuse an existing cert secret rather than
issuing a competing one.

Prefix stripping differs by ingress controller: nginx uses a `rewrite-target`
annotation with a regex path; Traefik needs a `stripPrefix` Middleware.

## Code conventions

- **Python 3.14, FastAPI, `uv`.** `src/` layout with no `__init__.py` and no
  build backend — the app is run, not packaged. `PYTHONPATH=src`.
- **Read config through the `Settings` object, never `os.getenv`.** Values set
  only in `.env` are invisible to `os.getenv`, so a bare call silently ignores
  them. This applies in `start.py` too.
- **Error messages must hold in every environment.** The same code runs locally
  and in a container; a hint that assumes one (e.g. "create a `.env`") is
  actively misleading in the other. Report what is actually known — pydantic's
  own missing-field list — rather than guessing a cause.
- **Fail loudly at startup** for anything that would otherwise fail obscurely
  later: an unusable signing key, unreachable discovery, a half-configured
  service account.
- Comments explain *why*, not what. Several decisions here look wrong until you
  know the reason, which is what this file and those comments are for.
- Line length 120, ruff for lint and format.

## Do not reference J26

This service's client-facing behaviour was originally modelled on the earlier
J26 project's auth app, which is now EOL. WSJ27 stands alone: justify decisions
on their own terms, and don't add "like j26-auth does" comparisons in code,
comments, or docs. They will only age badly.

## Testing

There is no committed test suite yet. Changes to the token, cookie, or login
paths should at minimum be exercised end to end — the login round-trip, a
refresh, a machine-token grant, and verifying an issued token against the
published JWKS the way a consumer would.

## Git workflow

Same `dev`/`main` model as wsj27-project-api. No PRs yet (deliberately
deferred — see "Later" below; don't assume they're in place).

### Branch model

- **`main`** — production line. Only receives code that's been decided ready
  for prod: a deliberate `dev` → `main` promotion, or a `hotfix/...` branch cut
  directly from `main`. Every push to `main` triggers CI
  (`.github/workflows/build-and-publish.yml`), which publishes
  `ghcr.io/scouterna/wsj27-auth-api:latest` and `:<short-sha>`.
- **`dev`** — integration branch. All feature branches merge here first and
  accumulate, so multiple in-progress features can be tested together. Every
  push to `dev` triggers CI too, publishing `:dev`. The dev k8s environment
  (`wsj27-infra/envs/dev/wsj27-auth-api.yaml`) tracks `:dev`.
- **`feat/...`** — cut from `dev`, merged back into `dev` with a local
  `git merge` (no PR yet) once ready to test alongside whatever else is there.
- **`hotfix/...`** — cut from `main`, for changes that must reach prod without
  waiting on whatever untested work currently sits in `dev`. Merged into
  `main`, then merged *forward* into `dev` so the fix isn't lost or
  reintroduced by the next promotion.

The only two things that ever affect prod: pushing to `main` (produces a new
candidate image), and manually bumping the SHA pin in
`wsj27-infra/envs/prod/wsj27-auth-api.yaml` + applying it. Pushing to `dev`
never touches prod.

This retires the old per-cluster `k8s/` overlays (homelab/wstest/scoutweb,
each with its own registry and manual `podman build`/`push`) in favor of the
single scoutweb cluster managed through `wsj27-infra`, matching how
wsj27-project-api is deployed. `k8s/` is gitignored locally and going away.

### Recipes

**Start a feature:**
```bash
git checkout dev && git pull
git checkout -b feat/whatever
# ...commit...
```

**Bring it into dev for testing:**
```bash
git checkout dev && git pull
git merge feat/whatever
git push origin dev
```
CI publishes `:dev`. Like `:latest`, this is a moving tag — after a push,
`kubectl -n proj-wsj27-dev rollout restart deployment/wsj27-auth-api` is
needed to actually repull it; `apply` alone won't.

**Promote to prod** (once you've decided what's in `dev` is ready):
```bash
git log main..dev --oneline      # check exactly what you're about to ship
git checkout main && git pull
git merge dev
git push origin main
```
Watch CI (`gh run list` / `gh run watch`), get the new short SHA
(`git rev-parse --short HEAD`), bump the image tag in
`wsj27-infra/envs/prod/wsj27-auth-api.yaml` to that SHA, apply, and
`rollout restart` in the `proj-wsj27-prod` namespace.

**Hotfix straight to prod, bypassing untested `dev` work:**
```bash
git checkout main && git pull
git checkout -b hotfix/auth-thing
# ...commit...
git checkout main
git merge hotfix/auth-thing
git push origin main
```
Bump prod's SHA pin as above, then sync the fix back into `dev`:
```bash
git checkout dev
git merge main
git push origin dev
```

### Later (not yet in place)

- Switch `feat/... → dev` and `dev → main` merges to GitHub PRs once things
  stabilize — no CI change needed, `pull_request` builds already run.
- Start tagging releases (`v1.2.3`) on `main` instead of pinning prod to a raw
  SHA — the CI trigger for `v*.*.*` tags already exists and needs nothing
  further.
