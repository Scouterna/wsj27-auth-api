"""Role lookup for the token we mint.

The identity provider we authenticate against carries no project roles, so we
attach them ourselves. We do not *decide* them: the project API is the authority
on what roles exist and who holds them, and serves a finished `member_no -> roles`
map. This module caches that map and answers lookups during login.

Keeping the interpretation upstream is deliberate. It leaves nothing
project-specific in this service — no member types, no role names, no namespace —
so pointing `PROJECT_API_URL` at a different project's API is the only change
needed to reuse it. It also puts the definition of a role next to the code that
enforces it, instead of splitting producer and consumer across two repositories.

The map is fetched in bulk on a timer and held in memory, so lookups during login
are synchronous and never block on that service — a login still succeeds if the
cache is cold or the project API is down, and the user gets `DEFAULT_ROLES` until
it recovers.

Anyone the upstream does not list gets `DEFAULT_ROLES` too: authentication
succeeds and confers only whatever those grant, which is the intended behaviour
rather than an error. `DEFAULT_ROLES` is empty unless configured, so by default
that means no roles at all — but it is a setting, not a guarantee, and a
deployment that sets it grants those roles during an outage as well.
"""

import asyncio
import json
import logging
import time
from pathlib import Path
from typing import Any

import httpx

from .config import get_settings

logger = logging.getLogger(__name__)

settings = get_settings()

# member_no -> roles
_cache: dict[str, list[str]] = {}
_last_refresh: float | None = None
_task: asyncio.Task | None = None

# Set from the last response so the next poll can ask "has this changed?" and
# get a 304 with no body when it has not.
_etag: str | None = None

# How long to wait before retrying while the cache has never loaded. Short,
# because the usual cause is project-api still starting up alongside us.
STARTUP_RETRY_SECONDS = 30


class RoleFetchError(Exception):
    """Could not get the role map from the project API.

    Its own message says what went wrong, so callers log it without a traceback:
    that service being down or misconfigured is an operational condition, not a
    fault in this service.
    """


async def _fetch_member_roles() -> dict[str, list[str]] | None:
    """Fetch the member-to-roles map from the project API at `PROJECT_API_URL`.

    Returns None when the data is unchanged (HTTP 304), so the caller can keep
    the cache it already has instead of rebuilding an identical one.

    `STUB_ROLES_FILE` short-circuits this for local development, so role-gated
    behaviour can be exercised without the project API running.
    """
    stub = _load_stub_roles()
    if stub is not None:
        return stub

    if not settings.PROJECT_API_URL:
        logger.warning("PROJECT_API_URL is not set; no roles will be assigned")
        return {}

    global _etag

    url = settings.PROJECT_API_URL.rstrip("/") + "/participants/roles"
    headers = {"Accept": "application/json"}

    token = await _service_token()
    if token:
        headers["Authorization"] = f"Bearer {token}"

    if _etag:
        headers["If-None-Match"] = _etag

    try:
        async with httpx.AsyncClient(timeout=settings.PROJECT_API_TIMEOUT) as client:
            response = await client.get(url, headers=headers)
    except httpx.HTTPError as exc:
        # Unreachable, refused, timed out, DNS failure: all expected at times,
        # and none of them our bug. Report the cause, not a traceback.
        raise RoleFetchError(f"Could not reach project-api at {url}: {type(exc).__name__}: {exc}") from exc

    if response.status_code == 304:
        logger.debug("Participant data unchanged (304); keeping the current cache")
        return None

    if response.status_code >= 400:
        # 401/404 usually mean our service-account role is wrong — a permanent
        # failure that retrying will not fix, so name it clearly.
        raise RoleFetchError(f"project-api returned {response.status_code} for {url}: {response.text[:200]}")

    _etag = response.headers.get("ETag")

    try:
        participants = response.json().get("participants") or {}
    except ValueError as exc:
        raise RoleFetchError(f"project-api returned a non-JSON body for {url}") from exc

    if not isinstance(participants, dict):
        raise RoleFetchError(f"{url} returned {type(participants).__name__} participants, expected an object")

    # The upstream defines what a role is; we only carry it. Anything that is not
    # a list of strings is a contract violation, so drop it and say so rather
    # than minting tokens with malformed roles in them.
    #
    # An empty list is dropped too, and that is a decision rather than tidying:
    # get_roles() distinguishes "absent" (fall back to DEFAULT_ROLES) from
    # "present and empty" (exactly no roles). Upstreams are not expected to know
    # that, and the two ways of saying "this member has no roles of their own"
    # must not mean different things here. Absent is the one we keep, because it
    # is what an upstream that omits unroled members already sends.
    roles: dict[str, list[str]] = {}
    malformed = 0
    for member_no, member_roles in participants.items():
        if isinstance(member_roles, list) and all(isinstance(role, str) for role in member_roles):
            if member_roles:
                roles[str(member_no)] = member_roles
        else:
            malformed += 1

    if malformed:
        # Counted, not named: this runs over every participant, so one bad
        # upstream deploy would otherwise put thousands of member numbers in the
        # log. The count is enough to notice; project-api's own logs say who.
        logger.warning("Ignored %d member(s) whose roles were not a list of strings", malformed)

    logger.info("Fetched roles for %d members", len(roles))
    return roles


async def _service_token() -> str | None:
    """Get a token for calling project-api, using our own client-credentials grant.

    We are the issuer, so this mints locally rather than making an HTTP call to
    ourselves — fewer moving parts, and it works before the server is accepting
    connections (the first refresh runs during startup).
    """
    client_id = settings.PROJECT_API_CLIENT_ID
    if not client_id:
        return None

    # Imported here rather than at module scope: tokens imports nothing from
    # this module, but keeping the dependency local makes the direction obvious.
    from . import tokens

    roles = settings.SERVICE_CLIENT_ROLES.get(client_id)
    if not roles:
        logger.warning("PROJECT_API_CLIENT_ID=%r has no entry in SERVICE_CLIENT_ROLES", client_id)
        return None

    token, _ = tokens.mint_service_token(client_id, list(roles))
    return token


def _load_stub_roles() -> dict[str, list[str]] | None:
    """Dev-only role source: a JSON file of {member_no: [roles]}.

    Returns None when not configured, so the caller falls through to the real
    fetch.
    """
    stub_file = settings.STUB_ROLES_FILE
    if not stub_file:
        return None

    path = Path(stub_file)
    if not path.is_file():
        logger.warning("STUB_ROLES_FILE %s does not exist; no roles loaded", path)
        return {}

    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        logger.warning("STUB_ROLES_FILE %s must contain a JSON object of {member_no: [roles]}", path)
        return {}

    parsed: dict[str, list[str]] = {}
    for member_no, roles in raw.items():
        if isinstance(roles, list):
            parsed[str(member_no)] = [str(role) for role in roles]
        else:
            logger.warning("Ignoring roles for member %s: expected a list", member_no)

    logger.info("Loaded stub roles for %d members from %s", len(parsed), path)
    return parsed


async def refresh_cache() -> None:
    """Replace the cache with a freshly fetched copy.

    The swap is atomic (rebind, not mutate) so lookups never observe a
    half-populated cache.
    """
    global _cache, _last_refresh

    started = time.perf_counter()
    roles = await _fetch_member_roles()
    elapsed_ms = (time.perf_counter() - started) * 1000

    if roles is None:
        # Unchanged upstream; keep the cache but record that we did check, so
        # cache_status() does not make it look stale.
        _last_refresh = time.time()
        logger.info("Role cache unchanged: %d members, %.0fms", len(_cache), elapsed_ms)
        return

    _cache = roles
    _last_refresh = time.time()

    logger.info("Role cache refreshed: %d members with roles, %.0fms", len(roles), elapsed_ms)


def member_no_from_claims(claims: dict[str, Any]) -> str | None:
    """Pull the Scoutnet member number out of the identity provider's claims.

    ScoutID emits it as `scoutnet_member_no` (a mapper on the default `profile`
    scope, so it needs no extra scope on the client). The other spellings are
    accepted because they are the obvious names a differently-configured realm
    might use, and getting this wrong fails silently — see below.

    Falls back to `preferred_username`, then to `sub`. `sub` is a Keycloak UUID
    rather than a member number, so it will never match the role cache; it
    exists only so the lookup key is stable for logging and for realms with no
    Scoutnet data.
    """
    for name in ("scoutnet_member_no", "member_no", "memberNo", "member_number"):
        value = claims.get(name)
        if value is not None:
            return str(value)

    # ScoutID usernames were "scoutnet|3073781" and are now "3073781@scoutnet".
    # Accept both, so an older ScoutID deployment still resolves. Only digits
    # count: anything else could never match the role cache, and falling through
    # to the warning below is more useful than returning it.
    username = claims.get("preferred_username")
    if isinstance(username, str):
        member_no = username.removesuffix("@scoutnet") if username.endswith("@scoutnet") else None
        if member_no is None and username.startswith("scoutnet|"):
            member_no = username.removeprefix("scoutnet|")
        if member_no and member_no.isdigit():
            return member_no

    subject = claims.get("sub")
    if subject is not None:
        # Worth saying out loud: this means no usable member number was found,
        # so the user cannot match a Scoutnet-derived role cache and will get
        # DEFAULT_ROLES. Without this the misconfiguration is invisible — every
        # login succeeds, just with the wrong roles.
        logger.warning(
            "No Scoutnet member number in the token; falling back to sub=%s. Available claims: %s",
            subject,
            ", ".join(sorted(claims)),
        )
        return str(subject)

    return None


def get_roles(member_no: str | None, claims: dict[str, Any] | None = None) -> list[str]:
    """Roles for one user. Synchronous and non-blocking by design."""
    if member_no is not None:
        roles = _cache.get(member_no)
        if roles is not None:
            return list(roles)

        if _cache:
            # The cache has data but not for this member — a real "not a
            # participant" answer, distinct from the cache being empty.
            logger.info("No roles for member %s; using defaults", member_no)

    return list(settings.DEFAULT_ROLES)


def cache_status() -> dict[str, Any]:
    """Cache state, for the health endpoint."""
    return {
        "members": len(_cache),
        "last_refresh": _last_refresh,
        "stale": _last_refresh is None,
    }


async def _run_periodically() -> None:
    interval = settings.ROLE_SYNC_INTERVAL_MINUTES * 60

    while True:
        delay = interval

        try:
            await refresh_cache()
        except asyncio.CancelledError:
            return
        except RoleFetchError as exc:
            # Expected: project-api down, restarting, or misconfigured. Any
            # cache we already have stays in place, so logins keep working.
            #
            # Retry soon while we have never loaded anything — that is usually
            # project-api still starting alongside us, and waiting a whole
            # interval would leave everyone role-less for an hour over a few
            # seconds of startup skew.
            delay = STARTUP_RETRY_SECONDS if _last_refresh is None else interval
            logger.warning(
                "Role refresh failed, retrying in %ds (%d members cached): %s",
                delay,
                len(_cache),
                exc,
            )
        except Exception:
            # Anything else is unexpected and worth a traceback.
            delay = STARTUP_RETRY_SECONDS if _last_refresh is None else interval
            logger.exception("Unexpected error refreshing the role cache; retrying in %ds", delay)

        try:
            await asyncio.sleep(delay)
        except asyncio.CancelledError:
            return


def start() -> None:
    """Start the refresh loop. Call once at startup.

    Returns immediately: the loop's first fetch runs as a task, once the event
    loop is free. That is deliberate — the fetch calls project-api, which
    verifies our token against our own JWKS, so it cannot succeed until we are
    serving. Awaiting it during startup deadlocks the two services.
    """
    global _task
    if _task is None:
        _task = asyncio.create_task(_run_periodically())


async def shutdown() -> None:
    """Stop the refresh loop."""
    global _task
    if _task is not None:
        _task.cancel()
        _task = None
