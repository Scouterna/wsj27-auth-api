"""The upstream role-map contract.

This service takes roles on trust from the project API but not on faith: a
malformed body must not reach a minted token, and it must not silently change
who has access. These tests pin that boundary.

`_fetch_member_roles` is exercised through a stubbed HTTP response rather than
by calling the parsing loop directly — the parsing is only meaningful together
with the status-code and JSON handling around it, and testing them as one is
what catches a regression in either.
"""

import json

import httpx
import pytest

from app import roles


class _FakeResponse:
    """The parts of httpx.Response that _fetch_member_roles touches."""

    def __init__(self, payload, *, status_code=200, etag=None):
        self._payload = payload
        self.status_code = status_code
        self.headers = {"ETag": etag} if etag else {}
        self.text = payload if isinstance(payload, str) else json.dumps(payload)

    def json(self):
        if isinstance(self._payload, str):
            # Mimic httpx: a non-JSON body raises when decoded, it does not
            # return a string. ValueError specifically — that is what httpx
            # raises and what the code under test catches, so TRY004's
            # suggestion of TypeError would make this stub wrong.
            raise ValueError("not JSON")  # noqa: TRY004
        return self._payload


@pytest.fixture(autouse=True)
def _isolate_module_state(monkeypatch):
    """Keep the module's globals from leaking between tests.

    `_etag` in particular would otherwise make one test send an If-None-Match
    that another test's fake response never accounted for.
    """
    monkeypatch.setattr(roles, "_etag", None)
    monkeypatch.setattr(roles, "_cache", {})
    monkeypatch.setattr(roles.settings, "PROJECT_API_URL", "https://project.example.test")
    monkeypatch.setattr(roles.settings, "STUB_ROLES_FILE", "")
    # The token mint is a separate concern with its own key requirements.
    monkeypatch.setattr(roles, "_service_token", _no_token)


async def _no_token():
    return None


def _respond_with(monkeypatch, response):
    """Make the next fetch return `response` instead of making a request."""

    async def fake_get(self, url, headers=None):
        return response

    monkeypatch.setattr(httpx.AsyncClient, "get", fake_get)


async def _fetch(monkeypatch, payload, **kwargs):
    _respond_with(monkeypatch, _FakeResponse(payload, **kwargs))
    return await roles._fetch_member_roles()


# --- The happy path -----------------------------------------------------------


@pytest.mark.asyncio
async def test_roles_are_carried_through_verbatim(monkeypatch):
    """We are not the authority: whatever the upstream says is what we cache."""
    result = await _fetch(
        monkeypatch,
        {"participants": {"12345": ["wsj27:cmt", "wsj27:access:Hälsa plus intern information"]}},
    )
    assert result == {"12345": ["wsj27:cmt", "wsj27:access:Hälsa plus intern information"]}


@pytest.mark.asyncio
async def test_member_numbers_are_stringified(monkeypatch):
    """JSON object keys are strings, but a stub file or future upstream may not be.

    get_roles() looks up by the `member_no` claim, which is always a string, so a
    numeric key would simply never match.
    """
    result = await _fetch(monkeypatch, {"participants": {12345: ["wsj27:cmt"]}})
    assert result == {"12345": ["wsj27:cmt"]}


# --- Empty lists: the case that changes authorization -------------------------


@pytest.mark.asyncio
async def test_empty_role_list_is_dropped_not_stored(monkeypatch):
    """An empty list must not become a cache entry.

    get_roles() distinguishes absent (fall back to DEFAULT_ROLES) from present
    and empty (exactly no roles). An upstream saying "this member has no roles"
    means the former, whichever way it spells it — storing [] would silently
    strip DEFAULT_ROLES from that member.
    """
    result = await _fetch(monkeypatch, {"participants": {"111": [], "222": ["wsj27:cmt"]}})
    assert result == {"222": ["wsj27:cmt"]}
    assert "111" not in result


@pytest.mark.asyncio
async def test_empty_and_absent_yield_the_same_roles(monkeypatch):
    """The two spellings must be indistinguishable to a caller.

    This is the property the test above protects, stated end to end: it fails if
    anyone reintroduces empty-list entries, however the parsing is refactored.
    """
    monkeypatch.setattr(roles.settings, "DEFAULT_ROLES", ["wsj27:deltagare"])

    roles._cache = await _fetch(monkeypatch, {"participants": {"111": [], "999": ["wsj27:cmt"]}})

    sent_as_empty = roles.get_roles("111")
    never_mentioned = roles.get_roles("333")
    assert sent_as_empty == never_mentioned == ["wsj27:deltagare"]


# --- Malformed payloads -------------------------------------------------------


@pytest.mark.asyncio
async def test_non_list_roles_are_ignored(monkeypatch):
    """The pre-move body shape is the likeliest malformed payload in practice.

    Deploying project-api's old version against this one sends raw participant
    fields; those members must be dropped, not mistaken for roles.
    """
    result = await _fetch(
        monkeypatch,
        {"participants": {"111": {"member_type": "Avdelningsledare"}, "222": ["wsj27:cmt"]}},
    )
    assert result == {"222": ["wsj27:cmt"]}


@pytest.mark.asyncio
async def test_list_with_non_strings_is_ignored_entirely(monkeypatch):
    """A partly-valid list is dropped whole rather than filtered.

    Half a role set is not a safe guess at what the upstream meant, and silently
    granting the string half could grant more than it should.
    """
    result = await _fetch(monkeypatch, {"participants": {"111": ["wsj27:cmt", 42], "222": ["wsj27:cmt"]}})
    assert result == {"222": ["wsj27:cmt"]}


@pytest.mark.asyncio
async def test_malformed_members_are_logged_once_by_count(monkeypatch, caplog):
    """Not one line per member: this loop runs over every participant."""
    bad = {str(n): {"member_type": "Avdelningsledare"} for n in range(50)}
    with caplog.at_level("WARNING"):
        result = await _fetch(monkeypatch, {"participants": bad})

    assert result == {}
    warnings = [r for r in caplog.records if r.levelname == "WARNING"]
    assert len(warnings) == 1
    assert "50" in warnings[0].getMessage()


@pytest.mark.asyncio
async def test_non_object_participants_is_an_error(monkeypatch):
    """A list where an object belongs is a contract breach, not a missing member.

    Raising keeps the previous cache, which is the safer failure: an empty map
    would log everyone out of their roles at once.
    """
    with pytest.raises(roles.RoleFetchError, match="expected an object"):
        await _fetch(monkeypatch, {"participants": [1, 2, 3]})


@pytest.mark.asyncio
async def test_non_json_body_is_an_error(monkeypatch):
    with pytest.raises(roles.RoleFetchError, match="non-JSON"):
        await _fetch(monkeypatch, "<html>gateway timeout</html>")


@pytest.mark.asyncio
async def test_http_error_is_an_error(monkeypatch):
    """401 here means our service-account role is wrong — permanent, so name it."""
    with pytest.raises(roles.RoleFetchError, match="401"):
        await _fetch(monkeypatch, {"detail": "Not Found"}, status_code=401)


@pytest.mark.asyncio
async def test_missing_participants_key_yields_no_roles(monkeypatch):
    """`or {}` in the fetch: a body without the key is empty, not a crash."""
    assert await _fetch(monkeypatch, {}) == {}


# --- 304, the normal case between refreshes -----------------------------------


@pytest.mark.asyncio
async def test_unchanged_returns_none_so_the_cache_is_kept(monkeypatch):
    """None and {} must stay distinct: one keeps the cache, the other clears it."""
    assert await _fetch(monkeypatch, {}, status_code=304) is None


@pytest.mark.asyncio
async def test_etag_from_the_response_is_sent_on_the_next_fetch(monkeypatch):
    sent = {}

    async def capture(self, url, headers=None):
        sent.update(headers or {})
        return _FakeResponse({"participants": {}}, etag='"abc123"')

    monkeypatch.setattr(httpx.AsyncClient, "get", capture)

    await roles._fetch_member_roles()
    assert "If-None-Match" not in sent  # nothing cached yet

    await roles._fetch_member_roles()
    assert sent["If-None-Match"] == '"abc123"'
