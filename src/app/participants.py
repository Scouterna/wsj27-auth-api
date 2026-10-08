"""Looking up a member's display name in the project API, for impersonation.

Impersonating someone should look like being them, so the minted token carries
the target's name rather than the impersonator's. The role map has no names, so
this asks the project API's participant endpoint — once, when impersonation
starts; the name then travels in the impersonation token.

The request carries the *impersonator's* token, not our service account's. The
endpoint answers only callers with access to that participant, and borrowing the
caller's own access means we read nothing they could not read themselves, and our
service account needs no grant to every participant's data.
"""

import logging

import httpx

from .config import get_settings

logger = logging.getLogger(__name__)

settings = get_settings()


async def fetch_name(member_no: str, caller_token: str) -> str | None:
    """The member's display name, or None if it could not be had.

    None is an ordinary outcome — no project API configured, the caller may not
    read this member, the service is down — and the caller falls back to keeping
    its own name, so every failure is logged and swallowed rather than raised.
    """
    if not settings.PROJECT_API_URL or settings.STUB_ROLES_FILE:
        return None

    url = settings.PROJECT_API_URL.rstrip("/") + f"/participants/individual/{member_no}"

    try:
        async with httpx.AsyncClient(timeout=settings.PROJECT_API_TIMEOUT) as client:
            response = await client.get(
                url,
                params={"infolevel": "name"},
                headers={"Authorization": f"Bearer {caller_token}", "Accept": "application/json"},
            )
    except httpx.HTTPError as exc:
        logger.warning("Could not reach project-api for member %s's name: %s: %s", member_no, type(exc).__name__, exc)
        return None

    if response.status_code != 200:
        # A 404 usually means the caller has no access to this member, which the
        # endpoint deliberately does not distinguish from "no such member".
        logger.warning("project-api returned %d for member %s's name", response.status_code, member_no)
        return None

    try:
        name = response.json().get("name")
    except ValueError, AttributeError:
        name = None

    if not isinstance(name, str) or not name.strip():
        logger.warning("project-api returned no usable name for member %s", member_no)
        return None

    return name.strip()
