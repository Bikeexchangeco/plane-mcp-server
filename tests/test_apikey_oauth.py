"""The API-key OAuth mode: this server as its own authorization server.

Replays what claude.ai does — register, authorize, sign in, exchange, call,
refresh — against the real app wiring, with Plane's two checks stubbed.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import re
import secrets
import time
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from fastmcp import FastMCP
from key_value.aio.stores.memory import MemoryStore
from starlette.applications import Starlette
from starlette.routing import Mount
from starlette.testclient import TestClient

import plane_mcp.client as client_module
from plane_mcp.auth import PlaneApiKeyAccessToken, PlaneApiKeyOAuthProvider
from plane_mcp.server import get_allowed_client_redirect_uris

GOOD_KEY = "plane_api_goodkey_0123456789abcdef"
OTHER_WS_KEY = "plane_api_otherws_0123456789abcdef"
REDIRECT = "https://claude.ai/api/mcp/auth_callback"
SECRET = "x" * 48


class FakePlane:
    """Stands in for plane.ideum.co's two endpoints the provider calls."""

    def __init__(self):
        self.revoked: set[str] = set()
        self.down = False

    async def check_user(self, api_key):
        if self.down:
            return None
        if api_key in self.revoked or api_key not in (GOOD_KEY, OTHER_WS_KEY):
            return False
        return {"id": "user-1", "display_name": "angela", "email": "a@example.com"}

    async def check_workspace(self, api_key, slug):
        if self.down:
            return None
        return api_key == GOOD_KEY and slug == "colombian-coffees"


@pytest.fixture()
def store():
    return MemoryStore()


@pytest.fixture()
def plane():
    return FakePlane()


def _provider(store, plane, **kwargs) -> PlaneApiKeyOAuthProvider:
    provider = PlaneApiKeyOAuthProvider(
        base_url="https://mcp-plane.example.com/http",
        auth_secret=SECRET,
        plane_base_url="https://plane.example.com",
        client_storage=store,
        allowed_client_redirect_uris=get_allowed_client_redirect_uris(),
        **kwargs,
    )
    provider._check_user = plane.check_user
    provider._check_workspace = plane.check_workspace
    return provider


@pytest.fixture()
def provider(store, plane):
    return _provider(store, plane, default_workspace_slug="colombian-coffees")


@pytest.fixture()
def client(provider):
    """Same wiring as __main__.py: the OAuth app mounted at /http, well-known at the root."""
    mcp = FastMCP("Plane MCP Server", auth=provider)
    app = mcp.http_app(stateless_http=True)
    root = Starlette(
        routes=[*provider.get_well_known_routes(mcp_path="/mcp"), Mount("/http", app=app)],
        lifespan=lambda _: app.lifespan(app),
    )
    with TestClient(root, base_url="https://mcp-plane.example.com", follow_redirects=False) as c:
        yield c


def _pkce():
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    return verifier, challenge


def _register(client, redirect=REDIRECT, name="Claude"):
    r = client.post(
        "/http/register",
        json={
            "redirect_uris": [redirect],
            "client_name": name,
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none",
        },
    )
    assert r.status_code == 201, r.text
    return r.json()["client_id"]


def _authorize(client, client_id, challenge, redirect=REDIRECT):
    return client.get(
        "/http/authorize",
        params={
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": redirect,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "state": "st-123",
            "resource": "https://mcp-plane.example.com/http/mcp",
        },
    )


def _open_login(client, client_id, challenge):
    r = _authorize(client, client_id, challenge)
    assert r.status_code == 302, r.text
    login = urlparse(r.headers["location"])
    assert login.path == "/http/plane-login"
    page = client.get(f"{login.path}?{login.query}")
    assert page.status_code == 200
    txn = parse_qs(login.query)["txn"][0]
    csrf = re.search(r'name="csrf" value="([^"]+)"', page.text).group(1)
    return txn, csrf, page


def _submit(client, txn, csrf, key=GOOD_KEY, slug="colombian-coffees"):
    return client.post(
        "/http/plane-login",
        data={"txn": txn, "csrf": csrf, "api_key": key, "workspace_slug": slug},
    )


def _sign_in(client):
    client_id = _register(client)
    verifier, challenge = _pkce()
    txn, csrf, _ = _open_login(client, client_id, challenge)
    r = _submit(client, txn, csrf)
    assert r.status_code == 303, r.text
    target = urlparse(r.headers["location"])
    assert f"{target.scheme}://{target.netloc}{target.path}" == REDIRECT
    q = parse_qs(target.query)
    assert q["state"] == ["st-123"]
    return client_id, verifier, q["code"][0]


def _exchange(client, client_id, verifier, code):
    return client.post(
        "/http/token",
        data={
            "grant_type": "authorization_code",
            "client_id": client_id,
            "code": code,
            "code_verifier": verifier,
            "redirect_uri": REDIRECT,
        },
    )


def _initialize(client, access_token):
    return client.post(
        "/http/mcp",
        headers={
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
        },
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "test", "version": "1"},
            },
        },
    )


class TestDiscovery:
    def test_metadata_points_at_this_server(self, client):
        meta = client.get("/.well-known/oauth-authorization-server/http").json()
        assert meta["authorization_endpoint"] == "https://mcp-plane.example.com/http/authorize"
        assert meta["token_endpoint"] == "https://mcp-plane.example.com/http/token"
        assert meta["registration_endpoint"] == "https://mcp-plane.example.com/http/register"
        assert "plane.example.com/auth/o" not in json.dumps(meta)

    def test_unauthenticated_mcp_call_is_challenged(self, client):
        r = _initialize(client, "nope")
        assert r.status_code == 401
        assert "resource_metadata" in r.headers.get("www-authenticate", "")


class TestFullFlow:
    def test_sign_in_exchange_and_call(self, client, provider):
        client_id, verifier, code = _sign_in(client)
        tokens = _exchange(client, client_id, verifier, code)
        assert tokens.status_code == 200, tokens.text
        body = tokens.json()
        assert body["access_token"].startswith("pmcp_at_")
        assert body["refresh_token"].startswith("pmcp_rt_")
        assert GOOD_KEY not in tokens.text

        r = _initialize(client, body["access_token"])
        assert r.status_code == 200, r.text

    def test_access_token_resolves_to_plane_key_and_workspace(self, client, provider):
        client_id, verifier, code = _sign_in(client)
        at = _exchange(client, client_id, verifier, code).json()["access_token"]
        token = client.portal.call(provider.load_access_token, at)
        assert isinstance(token, PlaneApiKeyAccessToken)
        assert token.plane_api_key.get_secret_value() == GOOD_KEY
        assert token.claims["workspace_slug"] == "colombian-coffees"
        assert token.claims["auth_method"] == "api_key_oauth"
        assert token.claims["sub"] == "user-1"
        # never serialised or printed
        assert GOOD_KEY not in token.model_dump_json()
        assert GOOD_KEY not in repr(token)

    def test_plane_client_uses_the_bound_key(self, monkeypatch):
        token = PlaneApiKeyAccessToken(
            token="pmcp_at_x",
            client_id="c",
            scopes=["read", "write"],
            expires_at=int(time.time()) + 60,
            plane_api_key=GOOD_KEY,
            claims={"auth_method": "api_key_oauth", "workspace_slug": "colombian-coffees"},
        )
        monkeypatch.setattr(client_module, "get_access_token", lambda: token)
        ctx = client_module.get_plane_client_context()
        assert ctx.workspace_slug == "colombian-coffees"
        assert ctx.client.config.api_key == GOOD_KEY
        assert not ctx.client.config.access_token
        # The patch also asserted `client_module.current_workspace()`, a
        # diagnostics helper that exists in neither this fork nor upstream. The
        # three assertions above are what this test is named for, and
        # `auth_method` is covered by `test_access_token_carries_the_key`.

    def test_code_is_single_use(self, client):
        client_id, verifier, code = _sign_in(client)
        assert _exchange(client, client_id, verifier, code).status_code == 200
        again = _exchange(client, client_id, verifier, code)
        # FastMCP answers invalid_grant with 401, per the MCP spec
        assert again.status_code == 401
        assert again.json()["error"] == "invalid_grant"

    def test_code_requires_pkce_verifier(self, client):
        client_id, _, code = _sign_in(client)
        r = _exchange(client, client_id, "wrong-verifier-" + "a" * 40, code)
        assert r.status_code in (400, 401) and "access_token" not in r.text

    def test_code_bound_to_client(self, client):
        _, verifier, code = _sign_in(client)
        other = _register(client, name="Other")
        r = _exchange(client, other, verifier, code)
        assert r.status_code in (400, 401) and "access_token" not in r.text


class TestRefresh:
    def _tokens(self, client):
        client_id, verifier, code = _sign_in(client)
        return client_id, _exchange(client, client_id, verifier, code).json()

    def _refresh(self, client, client_id, rt):
        return client.post(
            "/http/token", data={"grant_type": "refresh_token", "client_id": client_id, "refresh_token": rt}
        )

    def test_rotation(self, client):
        client_id, first = self._tokens(client)
        r = self._refresh(client, client_id, first["refresh_token"])
        assert r.status_code == 200, r.text
        second = r.json()
        assert second["access_token"] != first["access_token"]
        # old pair is dead
        assert _initialize(client, first["access_token"]).status_code == 401
        reused = self._refresh(client, client_id, first["refresh_token"])
        assert reused.status_code == 401 and reused.json()["error"] == "invalid_grant"
        # new pair works
        assert _initialize(client, second["access_token"]).status_code == 200

    def test_key_revoked_in_plane_ends_the_connection(self, client, plane):
        client_id, tokens = self._tokens(client)
        plane.revoked.add(GOOD_KEY)
        r = self._refresh(client, client_id, tokens["refresh_token"])
        assert r.status_code == 401
        assert r.json()["error"] == "invalid_grant"

    def test_plane_unreachable_does_not_log_users_out(self, client, plane):
        client_id, tokens = self._tokens(client)
        plane.down = True
        assert self._refresh(client, client_id, tokens["refresh_token"]).status_code == 200

    def test_expired_access_token_rejected(self, store, plane):
        provider = _provider(store, plane, access_token_ttl=1)
        mcp = FastMCP("t", auth=provider)
        app = mcp.http_app(stateless_http=True)
        root = Starlette(routes=[Mount("/http", app=app)], lifespan=lambda _: app.lifespan(app))
        with TestClient(root, base_url="https://mcp-plane.example.com", follow_redirects=False) as c:
            client_id, verifier, code = _sign_in(c)
            at = _exchange(c, client_id, verifier, code).json()["access_token"]
            assert _initialize(c, at).status_code == 200
            time.sleep(1.2)
            assert _initialize(c, at).status_code == 401


class TestSignInPage:
    def test_wrong_key_shows_error_and_keeps_transaction(self, client):
        client_id = _register(client)
        verifier, challenge = _pkce()
        txn, csrf, _ = _open_login(client, client_id, challenge)
        bad = _submit(client, txn, csrf, key="nope")
        assert bad.status_code == 200
        assert "did not accept that API key" in bad.text
        assert _submit(client, txn, csrf).status_code == 303

    def test_workspace_the_key_cannot_read(self, client):
        client_id = _register(client)
        _, challenge = _pkce()
        txn, csrf, _ = _open_login(client, client_id, challenge)
        r = _submit(client, txn, csrf, key=OTHER_WS_KEY)
        assert "no access to this workspace" in r.text

    def test_invalid_slug(self, client):
        client_id = _register(client)
        _, challenge = _pkce()
        txn, csrf, _ = _open_login(client, client_id, challenge)
        r = _submit(client, txn, csrf, slug="../admin")
        assert "valid workspace slug" in r.text

    def test_workspace_allowlist(self, store, plane):
        provider = _provider(store, plane, allowed_workspace_slugs=["colombian-coffees"])
        mcp = FastMCP("t", auth=provider)
        app = mcp.http_app(stateless_http=True)
        root = Starlette(routes=[Mount("/http", app=app)], lifespan=lambda _: app.lifespan(app))
        with TestClient(root, base_url="https://mcp-plane.example.com", follow_redirects=False) as c:
            client_id = _register(c)
            _, challenge = _pkce()
            txn, csrf, page = _open_login(c, client_id, challenge)
            assert 'value="colombian-coffees"' in page.text and "readonly" in page.text
            assert "does not serve that workspace" in _submit(c, txn, csrf, slug="someone-else").text

    def test_too_many_attempts_kills_transaction(self, client):
        client_id = _register(client)
        _, challenge = _pkce()
        txn, csrf, _ = _open_login(client, client_id, challenge)
        for _ in range(5):
            r = _submit(client, txn, csrf, key="nope")
        assert r.status_code == 400
        assert _submit(client, txn, csrf).status_code == 400

    def test_transaction_is_single_use(self, client):
        client_id = _register(client)
        _, challenge = _pkce()
        txn, csrf, _ = _open_login(client, client_id, challenge)
        assert _submit(client, txn, csrf).status_code == 303
        assert _submit(client, txn, csrf).status_code == 400

    def test_csrf_cookie_required(self, client):
        client_id = _register(client)
        _, challenge = _pkce()
        txn, csrf, _ = _open_login(client, client_id, challenge)
        client.cookies.clear()
        r = _submit(client, txn, csrf)
        assert r.status_code == 200 and "could not be verified" in r.text

    def test_unknown_transaction(self, client):
        assert client.get("/http/plane-login?txn=made-up").status_code == 400

    def test_client_name_is_escaped(self, client):
        client_id = _register(client, name="<script>alert(1)</script>")
        _, challenge = _pkce()
        _, _, page = _open_login(client, client_id, challenge)
        assert "<script>alert(1)</script>" not in page.text
        assert "&lt;script&gt;" in page.text

    def test_security_headers(self, client):
        client_id = _register(client)
        _, challenge = _pkce()
        _, _, page = _open_login(client, client_id, challenge)
        assert page.headers["x-frame-options"] == "DENY"
        assert "frame-ancestors 'none'" in page.headers["content-security-policy"]
        assert page.headers["cache-control"] == "no-store"


class TestRedirectAllowlist:
    def test_unlisted_redirect_is_refused(self, client):
        client_id = _register(client, redirect="https://attacker.example/steal")
        _, challenge = _pkce()
        r = _authorize(client, client_id, challenge, redirect="https://attacker.example/steal")
        assert r.status_code == 400
        assert "attacker.example" not in r.headers.get("location", "")


class TestStorage:
    def test_plane_key_encrypted_at_rest(self, client, store):
        client_id, verifier, code = _sign_in(client)
        _exchange(client, client_id, verifier, code)

        async def dump():
            out = []
            for collection in ("plane-mcp-apikey-grants", "plane-mcp-apikey-access", "plane-mcp-apikey-refresh"):
                for key in await store.keys(collection=collection):
                    out.append(json.dumps(await store.get(key=key, collection=collection)))
            return out

        raw = client.portal.call(dump)
        assert raw, "expected stored records"
        assert all(GOOD_KEY not in r for r in raw)

    def test_secret_required(self, store):
        with pytest.raises(ValueError, match="PLANE_MCP_AUTH_SECRET"):
            PlaneApiKeyOAuthProvider(base_url="https://x", auth_secret="short", plane_base_url="https://p")


class TestPlaneChecks:
    """The real HTTP calls against a mocked Plane."""

    @pytest.fixture()
    def mocked(self, monkeypatch, store):
        seen = []

        def handler(request: httpx.Request):
            seen.append(request)
            key = request.headers.get("x-api-key")
            if request.url.path == "/api/v1/users/me/":
                if key == GOOD_KEY:
                    return httpx.Response(200, json={"id": "u1", "display_name": "a"})
                return httpx.Response(401, json={"detail": "bad"})
            if request.url.path == "/api/v1/workspaces/colombian-coffees/projects/":
                return httpx.Response(200 if key == GOOD_KEY else 403, json={"results": []})
            return httpx.Response(404)

        real = httpx.AsyncClient
        monkeypatch.setattr(httpx, "AsyncClient", lambda **kw: real(transport=httpx.MockTransport(handler), **kw))
        provider = PlaneApiKeyOAuthProvider(
            base_url="https://mcp/http",
            auth_secret=SECRET,
            plane_base_url="https://plane.example.com",
            plane_internal_base_url="http://plane-api:8000",
            client_storage=store,
        )
        return provider, seen

    def test_user_check(self, mocked):
        provider, seen = mocked
        assert asyncio.run(provider._check_user(GOOD_KEY))["id"] == "u1"
        assert asyncio.run(provider._check_user("bad")) is False
        assert seen[0].url.host == "plane-api"  # internal URL preferred
        assert "api_key" not in str(seen[0].url)  # key only ever in a header

    def test_workspace_check(self, mocked):
        provider, _ = mocked
        assert asyncio.run(provider._check_workspace(GOOD_KEY, "colombian-coffees")) is True
        assert asyncio.run(provider._check_workspace("bad", "colombian-coffees")) is False
        assert asyncio.run(provider._check_workspace(GOOD_KEY, "elsewhere")) is False
