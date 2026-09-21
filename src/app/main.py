"""FastAPI application for wsj27-auth-api."""

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
from prometheus_fastapi_instrumentator import Instrumentator, metrics

from . import oidc, roles
from .config import get_settings
from .keys import init_keys
from .routes import router
from .service_clients import init_service_clients

# --- Create instrumentor, settings and logger objects ---
instrumentator = Instrumentator(
    excluded_handlers=["/metrics"],
    should_instrument_requests_inprogress=True,
    inprogress_name="http_requests_inprogress",
    inprogress_labels=True,
)
instrumentator.add(
    metrics.default(
        latency_lowr_buckets=(0.005, 0.01, 0.025, 0.05, 0.075, 0.1, 0.25, 0.5, 1.0, float("inf")),
    )
)

logger = logging.getLogger(__name__)

settings = get_settings()

# <repo>/static, from <repo>/src/app/main.py
STATIC_DIR = Path(__file__).resolve().parents[2] / "static"


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Must succeed before we can serve a single request: without a signing key we
    # cannot mint tokens. Failing here stops the pod rather than serving a broken
    # service.
    init_keys()

    # Same for discovery — except with a fake user, where the IdP is never called
    # at all, so requiring it to be reachable would defeat the setting. start.py
    # logs the warning about running that way.
    if not settings.FAKE_USER_ID:
        await oidc.init_oidc()

    # Not fatal — a half-configured service account only affects that client.
    init_service_clients()

    # The first role fetch must NOT happen here. It calls project-api, which
    # verifies our token by fetching our own JWKS — so blocking on it before we
    # are serving deadlocks the two services against each other. Starting the
    # loop as a task defers the fetch until the event loop is free, which is
    # after this lifespan yields and uvicorn is accepting connections.
    roles.start()

    logger.info("wsj27-auth-api started and is accepting connections")

    try:
        yield  # FastAPI runs here!
    finally:
        await roles.shutdown()


DESCRIPTION = """
Handles the login flow for the WSJ27 apps and sets the cookies they read.

All apps on this host share these cookies, so a user logs in once and every app
sees the session.

### Tokens

This service does **not** hand the identity provider's tokens to the browser.
The IdP does not carry the roles WSJ27 needs, so we authenticate against it,
compute roles, then mint and sign our **own** token. Consumers verify against
our keys, published at `certs`.

### Machine callers

A backend that needs to call a WSJ27 API on its own behalf gets a token from
`token` using the client-credentials grant. It is the same kind of token, so a
resource server verifies user and machine callers with one code path.

### Consuming the session

Read the `wsj27-auth_access-token` cookie — or an `Authorization: Bearer` header
for machine callers — and verify it as a normal JWT: fetch
`.well-known/openid-configuration` relative to your base URL, follow `jwks_uri`,
and validate. Do not hardcode the key or the IdP location.

Roles arrive in the standard Keycloak claim shape — `realm_access.roles` (bare)
and `resource_access.<client>.roles` (conventionally read as `client:role`).

Embed `static/refresh.js` to keep sessions alive while a user is active.
"""

app = FastAPI(
    title="wsj27-auth-api",
    version="0.3.0",
    description=DESCRIPTION,
    lifespan=lifespan,
    # Set when an ingress strips a base path (e.g. /auth) before the request
    # reaches us: without it the docs page requests a spec URL that 404s, and
    # the OpenAPI servers block points at the wrong origin.
    root_path=settings.ROOT_PATH,
)


@app.middleware("http")
async def no_cache_headers(request: Request, call_next):
    """Auth responses carry session state; never let a proxy or browser reuse them."""
    response = await call_next(request)
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


# --- Add metrics API ---
instrumentator.instrument(app)
instrumentator.expose(app)

# --- Include the API routers ---
app.include_router(router)


@app.get("/static/refresh.js", include_in_schema=False)
async def refresh_script() -> FileResponse:
    """The client-side auto-refresh loop that consumer apps embed."""
    return FileResponse(
        STATIC_DIR / "refresh.js",
        media_type="application/javascript",
        headers={"Cache-Control": "public, max-age=300"},
    )


@app.get("/", include_in_schema=False)
async def health() -> JSONResponse:
    return JSONResponse({"status": "ok", "service": "wsj27-auth-api", "roles": roles.cache_status()})
