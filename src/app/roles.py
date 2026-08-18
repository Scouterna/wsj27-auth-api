"""Role assignment, derived from WSJ27 project membership.

The identity provider we authenticate against carries no WSJ27 roles, so we
compute them here and attach them to the token we mint.

Project membership comes from wsj27-project-api, fetched in bulk on a timer and
held in memory. Lookups during login are therefore synchronous and never block
on that service — a login still succeeds if the cache is cold or project-api is
down, the user simply gets no roles until it recovers.

Only registered project members get roles at all. Everyone else authenticates
successfully and can do nothing, which is the intended behaviour rather than an
error.
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

# --- Role model ---------------------------------------------------------------
#
# Roles have two or three colon-separated parts, e.g. "wsj27:cmt:admin". A
# consumer can grant on the whole namespace ("wsj27:*") or require one exact
# role. The first part is always the wsj27 namespace.
ROLE_NAMESPACE = "wsj27"
ROLE_LEADER = "ledare"
ROLE_CMT = "cmt"
ROLE_ACCESS = "access"


# How long to wait before retrying while the cache has never loaded. Short,
# because the usual cause is project-api still starting up alongside us.
STARTUP_RETRY_SECONDS = 30


class RoleFetchError(Exception):
    """Could not get participant data from project-api.

    Its own message says what went wrong, so callers log it without a traceback:
    project-api being down or misconfigured is an operational condition, not a
    fault in this service.
    """


# Only these member types get roles at all.
MEMBER_TYPE_LEADER = "Avdelningsledare"
MEMBER_TYPE_CMT = "Kontingentledning"

# access_level values that mean "no access role", alongside a blank value.
NO_ACCESS_LEVELS = {"ingen", ""}


def roles_for_participant(info: dict[str, Any]) -> list[str]:
    """Map one participant's project fields to WSJ27 roles.

    The rules, as of 2026-08-16:

      * Only `Avdelningsledare` and `Kontingentledning` get roles at all.
        Everyone else is a registered participant with no permissions.
      * `Avdelningsledare` gets `wsj27:ledare:<troop>` — the troop is part of
        the role because a leader's authority is scoped to their own troop.
      * `Kontingentledning` gets `wsj27:cmt`.
      * `access_level` becomes `wsj27:access:<level>` unless it is "Ingen" or
        blank, so the absence of access is expressed by the absence of a role
        rather than by a role meaning "nothing".

    Kept as a pure function of one participant record: it is the piece most
    likely to change, and this way it can be reasoned about and tested without
    the cache or the network.
    """
    member_type = str(info.get("member_type") or "").strip()
    roles: list[str] = []

    if member_type == MEMBER_TYPE_LEADER:
        troop = str(info.get("troop") or "").strip()
        if troop:
            roles.append(f"{ROLE_NAMESPACE}:{ROLE_LEADER}:{troop}")
        else:
            # A leader with no troop cannot be granted troop-scoped authority;
            # say so, because it is a data problem rather than a normal state.
            logger.warning("Participant is %s but has no troop; granting no leader role", MEMBER_TYPE_LEADER)
    elif member_type == MEMBER_TYPE_CMT:
        roles.append(f"{ROLE_NAMESPACE}:{ROLE_CMT}")
    else:
        # Not a role-bearing member type: no roles, and no access role either.
        return []

    access_level = str(info.get("access_level") or "").strip()
    if access_level.lower() not in NO_ACCESS_LEVELS:
        roles.append(f"{ROLE_NAMESPACE}:{ROLE_ACCESS}:{access_level}")

    return roles


async def _fetch_participant_roles() -> dict[str, list[str]] | None:
    """Fetch project members from wsj27-project-api and map them to roles.

    Returns None when the data is unchanged (HTTP 304), so the caller can keep
    the cache it already has instead of rebuilding an identical one.

    `STUB_ROLES_FILE` short-circuits this for local development, so role-gated
    behaviour can be exercised without project-api running.
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
        raise RoleFetchError(f"project-api returned {type(participants).__name__} participants, expected an object")

    roles: dict[str, list[str]] = {}
    for member_no, info in participants.items():
        if not isinstance(info, dict):
            continue
        member_roles = roles_for_participant(info)
        if member_roles:
            roles[str(member_no)] = member_roles

    logger.info("Fetched %d participants, %d with roles", len(participants), len(roles))
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
    roles = await _fetch_participant_roles()
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

    # ScoutID usernames are "scoutnet|3073781" today and are expected to become
    # "scoutnet@3073781" before production, so accept either separator rather
    # than breaking silently on the day that changes.
    username = claims.get("preferred_username")
    if isinstance(username, str):
        for separator in ("|", "@"):
            prefix = f"scoutnet{separator}"
            if username.startswith(prefix):
                member_no = username.removeprefix(prefix)
                if member_no:
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
