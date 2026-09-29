"""OAuth for self-hosted Plane installs that have no OAuth apps.

Plane Community Edition does not ship ``/auth/o/authorize-app/`` or
``/auth/o/token/``, so ``PlaneOAuthProvider`` (which proxies to them) cannot
complete a sign-in there. Clients that can only speak OAuth — claude.ai custom
connectors, ChatGPT connectors, and the like — therefore had no way in.

This provider makes the MCP server its own OAuth 2.1 authorization server:

1. The client registers (DCR) and is sent to ``/authorize`` as usual.
2. ``/authorize`` redirects the user's browser to this server's own sign-in
   page, which asks for a Plane *personal access token* and a workspace slug.
3. The key is checked against Plane (``/api/v1/users/me/`` and the workspace's
   project list). On success the server issues an authorization code, and the
   client exchanges it for this server's own opaque access / refresh tokens.
4. On every MCP request the access token is looked up in storage and the
   Plane API key bound to it is used for the Plane calls.

The Plane key is never placed in a URL, never returned to the client, and is
stored Fernet-encrypted (key derived from ``PLANE_MCP_AUTH_SECRET``). Only
SHA-256 hashes of the issued tokens are used as storage keys.
"""

from __future__ import annotations

import hashlib
import hmac
import html
import re
import secrets
import time
from typing import Any
from urllib.parse import urlencode, urlparse

import httpx
from cryptography.fernet import Fernet
from fastmcp.server.auth.auth import AccessToken, ClientRegistrationOptions, OAuthProvider, RevocationOptions
from fastmcp.server.auth.jwt_issuer import derive_jwt_key
from fastmcp.server.auth.oauth_proxy.models import ProxyDCRClient
from fastmcp.utilities.logging import get_logger
from key_value.aio.adapters.pydantic import PydanticAdapter
from key_value.aio.protocols import AsyncKeyValue
from key_value.aio.stores.memory import MemoryStore
from key_value.aio.wrappers.encryption import FernetEncryptionWrapper
from mcp.server.auth.provider import (
    AuthorizationCode,
    AuthorizationParams,
    RefreshToken,
    TokenError,
    construct_redirect_uri,
)
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
from pydantic import AnyHttpUrl, AnyUrl, BaseModel, Field, SecretStr
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse, Response
from starlette.routing import Route

logger = get_logger(__name__)

AUTH_METHOD = "api_key_oauth"
LOGIN_PATH = "/plane-login"
SCOPES = ["read", "write"]

DEFAULT_ACCESS_TOKEN_TTL = 60 * 60  # 1 hour
DEFAULT_REFRESH_TOKEN_TTL = 90 * 24 * 60 * 60  # 90 days
LOGIN_TRANSACTION_TTL = 15 * 60
AUTH_CODE_TTL = 5 * 60
MAX_LOGIN_ATTEMPTS = 5

CSRF_COOKIE = "plane_mcp_login_csrf"
# Plane workspace slugs: lowercase letters, digits, hyphens and underscores.
WORKSPACE_SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,47}$")


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


# ---------------------------------------------------------------------------
# Stored records
# ---------------------------------------------------------------------------


class LoginTransaction(BaseModel):
    """An /authorize request waiting for the user to submit their Plane key."""

    client_id: str
    client_name: str | None = None
    redirect_uri: str
    redirect_uri_provided_explicitly: bool
    state: str | None = None
    code_challenge: str
    resource: str | None = None
    csrf: str
    attempts: int = 0
    created_at: float


class Grant(BaseModel):
    """One user's sign-in: the Plane key and the workspace it was validated for."""

    plane_api_key: str
    workspace_slug: str
    user_id: str
    display_name: str | None = None
    email: str | None = None
    created_at: float


class StoredCode(BaseModel):
    client_id: str
    grant_id: str
    redirect_uri: str
    redirect_uri_provided_explicitly: bool
    code_challenge: str
    scopes: list[str]
    resource: str | None = None
    expires_at: float


class StoredAccessToken(BaseModel):
    client_id: str
    grant_id: str
    scopes: list[str]
    resource: str | None = None
    expires_at: int
    refresh_hash: str | None = None


class StoredRefreshToken(BaseModel):
    client_id: str
    grant_id: str
    scopes: list[str]
    resource: str | None = None
    expires_at: int
    access_hash: str | None = None


class PlaneAuthorizationCode(AuthorizationCode):
    grant_id: str


class PlaneRefreshToken(RefreshToken):
    grant_id: str
    resource: str | None = None


class PlaneApiKeyAccessToken(AccessToken):
    """An access token that carries the Plane key it stands for.

    The key is excluded from serialization and repr so it cannot leak through a
    log line or a token snapshot; ``plane_mcp.client`` reads it directly.
    """

    plane_api_key: SecretStr = Field(exclude=True, repr=False)


# ---------------------------------------------------------------------------
# Provider
# ---------------------------------------------------------------------------


class PlaneApiKeyOAuthProvider(OAuthProvider):
    """OAuth 2.1 authorization server whose sign-in step asks for a Plane API key."""

    def __init__(
        self,
        *,
        base_url: AnyHttpUrl | str,
        auth_secret: str,
        plane_base_url: str,
        plane_internal_base_url: str | None = None,
        client_storage: AsyncKeyValue | None = None,
        allowed_client_redirect_uris: list[str] | None = None,
        allowed_workspace_slugs: list[str] | None = None,
        default_workspace_slug: str | None = None,
        access_token_ttl: int = DEFAULT_ACCESS_TOKEN_TTL,
        refresh_token_ttl: int = DEFAULT_REFRESH_TOKEN_TTL,
        revalidate_on_refresh: bool = True,
        timeout_seconds: int = 10,
        required_scopes: list[str] | None = None,
    ):
        if not auth_secret or len(auth_secret) < 32:
            raise ValueError("PLANE_MCP_AUTH_SECRET must be set to a random string of at least 32 characters")
        if not plane_base_url:
            raise ValueError("PLANE_BASE_URL is required")
        if access_token_ttl <= 0 or refresh_token_ttl <= access_token_ttl:
            raise ValueError("token lifetimes must be positive, and the refresh lifetime longer than the access one")

        super().__init__(
            base_url=base_url,
            client_registration_options=ClientRegistrationOptions(
                enabled=True, valid_scopes=SCOPES, default_scopes=SCOPES
            ),
            revocation_options=RevocationOptions(enabled=True),
            required_scopes=required_scopes or SCOPES,
        )

        self.plane_base_url = plane_base_url.rstrip("/")
        self.plane_api_url = (plane_internal_base_url or plane_base_url).rstrip("/")
        self.allowed_client_redirect_uris = allowed_client_redirect_uris
        self.allowed_workspace_slugs = [s.strip().lower() for s in (allowed_workspace_slugs or []) if s.strip()]
        self.default_workspace_slug = (default_workspace_slug or "").strip().lower() or (
            self.allowed_workspace_slugs[0] if len(self.allowed_workspace_slugs) == 1 else ""
        )
        self.access_token_ttl = access_token_ttl
        self.refresh_token_ttl = refresh_token_ttl
        self.revalidate_on_refresh = revalidate_on_refresh
        self.timeout_seconds = timeout_seconds
        self._secure_cookies = str(self.base_url).startswith("https://")

        # Everything this provider stores is encrypted at rest; the Plane key most of all.
        fernet = Fernet(derive_jwt_key(high_entropy_material=auth_secret, salt="plane-mcp-apikey-oauth-storage"))
        store = FernetEncryptionWrapper(
            key_value=client_storage if client_storage is not None else MemoryStore(),
            fernet=fernet,
            raise_on_decryption_error=False,  # a rotated secret reads as "not found": users sign in again
        )

        def adapter(model: type[BaseModel], collection: str) -> PydanticAdapter:
            return PydanticAdapter(key_value=store, pydantic_model=model, default_collection=collection)

        self._clients = adapter(ProxyDCRClient, "plane-mcp-apikey-clients")
        self._transactions = adapter(LoginTransaction, "plane-mcp-apikey-login")
        self._grants = adapter(Grant, "plane-mcp-apikey-grants")
        self._codes = adapter(StoredCode, "plane-mcp-apikey-codes")
        self._access = adapter(StoredAccessToken, "plane-mcp-apikey-access")
        self._refresh = adapter(StoredRefreshToken, "plane-mcp-apikey-refresh")

        logger.info(
            "Initialized Plane API-key OAuth provider (plane=%s, workspaces=%s)",
            self.plane_base_url,
            self.allowed_workspace_slugs or "any",
        )

    # -- client registration ------------------------------------------------

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        return await self._clients.get(key=client_id)

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        if client_info.client_id is None:
            raise ValueError("client_id is required for client registration")
        # Public client + PKCE, as in OAuthProxy: redirect URIs are checked against
        # the server's allowlist on every /authorize, not just at registration.
        client = ProxyDCRClient(
            client_id=client_info.client_id,
            client_secret=None,
            redirect_uris=client_info.redirect_uris or [AnyUrl("http://localhost")],
            grant_types=client_info.grant_types or ["authorization_code", "refresh_token"],
            scope=" ".join(SCOPES),
            token_endpoint_auth_method="none",
            allowed_redirect_uri_patterns=self.allowed_client_redirect_uris,
            client_name=getattr(client_info, "client_name", None),
        )
        await self._clients.put(key=client_info.client_id, value=client)

    # -- authorization ------------------------------------------------------

    async def authorize(self, client: OAuthClientInformationFull, params: AuthorizationParams) -> str:
        txn_id = secrets.token_urlsafe(32)
        await self._transactions.put(
            key=txn_id,
            value=LoginTransaction(
                client_id=client.client_id or "",
                client_name=getattr(client, "client_name", None),
                redirect_uri=str(params.redirect_uri),
                redirect_uri_provided_explicitly=params.redirect_uri_provided_explicitly,
                state=params.state,
                code_challenge=params.code_challenge,
                resource=params.resource,
                csrf=secrets.token_urlsafe(32),
                created_at=time.time(),
            ),
            ttl=LOGIN_TRANSACTION_TTL,
        )
        return f"{str(self.base_url).rstrip('/')}{LOGIN_PATH}?{urlencode({'txn': txn_id})}"

    async def load_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: str
    ) -> PlaneAuthorizationCode | None:
        stored = await self._codes.get(key=_hash(authorization_code))
        if stored is None or stored.client_id != client.client_id or stored.expires_at < time.time():
            return None
        return PlaneAuthorizationCode(
            code=authorization_code,
            client_id=stored.client_id,
            redirect_uri=AnyUrl(stored.redirect_uri),
            redirect_uri_provided_explicitly=stored.redirect_uri_provided_explicitly,
            code_challenge=stored.code_challenge,
            scopes=stored.scopes,
            resource=stored.resource,
            expires_at=stored.expires_at,
            grant_id=stored.grant_id,
        )

    async def exchange_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: AuthorizationCode
    ) -> OAuthToken:
        # Single use: whoever deletes the code first gets the tokens.
        if not await self._codes.delete(key=_hash(authorization_code.code)):
            raise TokenError(error="invalid_grant", error_description="authorization code already used")
        grant_id = getattr(authorization_code, "grant_id", None)
        if not grant_id or await self._grants.get(key=grant_id) is None:
            raise TokenError(error="invalid_grant", error_description="sign-in no longer valid")
        return await self._issue_tokens(
            client_id=client.client_id or "",
            grant_id=grant_id,
            scopes=authorization_code.scopes,
            resource=authorization_code.resource,
        )

    # -- refresh ------------------------------------------------------------

    async def load_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: str
    ) -> PlaneRefreshToken | None:
        stored = await self._refresh.get(key=_hash(refresh_token))
        if stored is None or stored.client_id != client.client_id or stored.expires_at < time.time():
            return None
        return PlaneRefreshToken(
            token=refresh_token,
            client_id=stored.client_id,
            scopes=stored.scopes,
            expires_at=stored.expires_at,
            grant_id=stored.grant_id,
            resource=stored.resource,
        )

    async def exchange_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: RefreshToken, scopes: list[str]
    ) -> OAuthToken:
        refresh_hash = _hash(refresh_token.token)
        stored = await self._refresh.get(key=refresh_hash)
        if stored is None or not await self._refresh.delete(key=refresh_hash):
            raise TokenError(error="invalid_grant", error_description="refresh token already used")
        if stored.access_hash:
            await self._access.delete(key=stored.access_hash)

        grant = await self._grants.get(key=stored.grant_id)
        if grant is None:
            raise TokenError(error="invalid_grant", error_description="sign-in no longer valid")

        # A key revoked in Plane should end the connection at the next refresh,
        # not linger until the refresh token expires.
        if self.revalidate_on_refresh:
            verdict = await self._check_user(grant.plane_api_key)
            if verdict is False:
                await self._grants.delete(key=stored.grant_id)
                raise TokenError(error="invalid_grant", error_description="Plane API key is no longer valid")

        return await self._issue_tokens(
            client_id=client.client_id or "",
            grant_id=stored.grant_id,
            scopes=scopes or stored.scopes,
            resource=stored.resource,
        )

    # -- access -------------------------------------------------------------

    async def load_access_token(self, token: str) -> PlaneApiKeyAccessToken | None:  # type: ignore[override]
        stored = await self._access.get(key=_hash(token))
        if stored is None or stored.expires_at < time.time():
            return None
        grant = await self._grants.get(key=stored.grant_id)
        if grant is None:
            return None
        return PlaneApiKeyAccessToken(
            token=token,
            client_id=stored.client_id,
            scopes=stored.scopes,
            expires_at=stored.expires_at,
            resource=stored.resource,
            plane_api_key=SecretStr(grant.plane_api_key),
            claims={
                "auth_method": AUTH_METHOD,
                "sub": grant.user_id,
                "display_name": grant.display_name,
                "email": grant.email,
                "workspace_slug": grant.workspace_slug,
                "workspace": {"slug": grant.workspace_slug},
            },
        )

    async def verify_token(self, token: str) -> PlaneApiKeyAccessToken | None:  # type: ignore[override]
        return await self.load_access_token(token)

    async def revoke_token(self, token: AccessToken | RefreshToken) -> None:  # type: ignore[override]
        token_hash = _hash(token.token)
        if isinstance(token, RefreshToken):
            stored = await self._refresh.get(key=token_hash)
            await self._refresh.delete(key=token_hash)
            if stored and stored.access_hash:
                await self._access.delete(key=stored.access_hash)
        else:
            stored_access = await self._access.get(key=token_hash)
            await self._access.delete(key=token_hash)
            if stored_access and stored_access.refresh_hash:
                await self._refresh.delete(key=stored_access.refresh_hash)

    async def _issue_tokens(
        self, *, client_id: str, grant_id: str, scopes: list[str], resource: str | None
    ) -> OAuthToken:
        scopes = scopes or list(SCOPES)
        access_token = f"pmcp_at_{secrets.token_urlsafe(32)}"
        refresh_token = f"pmcp_rt_{secrets.token_urlsafe(32)}"
        access_hash, refresh_hash = _hash(access_token), _hash(refresh_token)
        now = int(time.time())

        await self._access.put(
            key=access_hash,
            value=StoredAccessToken(
                client_id=client_id,
                grant_id=grant_id,
                scopes=scopes,
                resource=resource,
                expires_at=now + self.access_token_ttl,
                refresh_hash=refresh_hash,
            ),
            ttl=self.access_token_ttl,
        )
        await self._refresh.put(
            key=refresh_hash,
            value=StoredRefreshToken(
                client_id=client_id,
                grant_id=grant_id,
                scopes=scopes,
                resource=resource,
                expires_at=now + self.refresh_token_ttl,
                access_hash=access_hash,
            ),
            ttl=self.refresh_token_ttl,
        )
        # Keep the grant alive as long as the newest refresh token.
        grant = await self._grants.get(key=grant_id)
        if grant is not None:
            await self._grants.put(key=grant_id, value=grant, ttl=self.refresh_token_ttl)

        return OAuthToken(
            access_token=access_token,
            token_type="Bearer",
            expires_in=self.access_token_ttl,
            refresh_token=refresh_token,
            scope=" ".join(scopes),
        )

    # -- Plane checks -------------------------------------------------------

    async def _check_user(self, api_key: str) -> dict[str, Any] | bool | None:
        """``users/me`` for this key: the user dict, False if rejected, None if Plane is unreachable."""
        try:
            async with httpx.AsyncClient(timeout=self.timeout_seconds) as http:
                response = await http.get(f"{self.plane_api_url}/api/v1/users/me/", headers={"x-api-key": api_key})
        except httpx.RequestError as exc:
            logger.warning("Plane unreachable while checking an API key: %s", type(exc).__name__)
            return None
        if response.status_code in (401, 403):
            return False
        if response.status_code != 200:
            logger.warning("Unexpected status from Plane users/me: %s", response.status_code)
            return None
        try:
            return response.json()
        except ValueError:
            return None

    async def _check_workspace(self, api_key: str, slug: str) -> bool | None:
        """True if the key can read the workspace, False if not, None if Plane is unreachable."""
        try:
            async with httpx.AsyncClient(timeout=self.timeout_seconds) as http:
                response = await http.get(
                    f"{self.plane_api_url}/api/v1/workspaces/{slug}/projects/",
                    params={"per_page": 1},
                    headers={"x-api-key": api_key},
                )
        except httpx.RequestError as exc:
            logger.warning("Plane unreachable while checking workspace access: %s", type(exc).__name__)
            return None
        if response.status_code == 200:
            return True
        if response.status_code in (401, 403, 404):
            return False
        logger.warning("Unexpected status from Plane workspace check: %s", response.status_code)
        return None

    # -- sign-in page -------------------------------------------------------

    def get_routes(self, mcp_path: str | None = None) -> list[Route]:
        routes = super().get_routes(mcp_path)
        routes.append(Route(LOGIN_PATH, endpoint=self._login_page, methods=["GET", "POST"]))
        return routes

    async def _login_page(self, request: Request) -> Response:
        if request.method == "GET":
            txn_id = request.query_params.get("txn", "")
            txn = await self._transactions.get(key=txn_id) if txn_id else None
            if txn is None:
                return self._render_expired()
            return self._render_form(txn_id, txn)
        return await self._handle_login(request)

    async def _handle_login(self, request: Request) -> Response:
        form = await request.form()
        txn_id = str(form.get("txn", ""))
        txn = await self._transactions.get(key=txn_id) if txn_id else None
        if txn is None:
            return self._render_expired()

        csrf_form = str(form.get("csrf", ""))
        csrf_cookie = request.cookies.get(CSRF_COOKIE, "")
        if not (hmac.compare_digest(csrf_form, txn.csrf) and hmac.compare_digest(csrf_cookie, txn.csrf)):
            return self._render_form(txn_id, txn, error="Your session could not be verified. Please try again.")

        api_key = str(form.get("api_key", "")).strip()
        slug = str(form.get("workspace_slug", "")).strip().lower()

        error = None
        if not api_key:
            error = "Enter your Plane API key."
        elif not WORKSPACE_SLUG_RE.match(slug):
            error = "Enter a valid workspace slug (the part after the domain in your Plane URL)."
        elif self.allowed_workspace_slugs and slug not in self.allowed_workspace_slugs:
            error = "This server does not serve that workspace."

        user: dict[str, Any] | bool | None = None
        if error is None:
            user = await self._check_user(api_key)
            if user is None:
                error = "Plane could not be reached. Please try again in a moment."
            elif user is False or not isinstance(user, dict) or not user.get("id"):
                error = "Plane did not accept that API key."
        if error is None:
            workspace_ok = await self._check_workspace(api_key, slug)
            if workspace_ok is None:
                error = "Plane could not be reached. Please try again in a moment."
            elif workspace_ok is False:
                error = "That API key has no access to this workspace."

        if error is not None:
            txn.attempts += 1
            if txn.attempts >= MAX_LOGIN_ATTEMPTS:
                await self._transactions.delete(key=txn_id)
                return self._render_expired("Too many attempts. Start the connection again from your app.")
            await self._transactions.put(key=txn_id, value=txn, ttl=LOGIN_TRANSACTION_TTL)
            return self._render_form(txn_id, txn, error=error, workspace_slug=slug)

        # Consume the transaction before issuing anything, so it cannot be replayed.
        if not await self._transactions.delete(key=txn_id):
            return self._render_expired()

        assert isinstance(user, dict)
        grant_id = secrets.token_urlsafe(24)
        await self._grants.put(
            key=grant_id,
            value=Grant(
                plane_api_key=api_key,
                workspace_slug=slug,
                user_id=str(user.get("id")),
                display_name=user.get("display_name"),
                email=user.get("email"),
                created_at=time.time(),
            ),
            ttl=self.refresh_token_ttl,
        )
        code = secrets.token_urlsafe(32)
        await self._codes.put(
            key=_hash(code),
            value=StoredCode(
                client_id=txn.client_id,
                grant_id=grant_id,
                redirect_uri=txn.redirect_uri,
                redirect_uri_provided_explicitly=txn.redirect_uri_provided_explicitly,
                code_challenge=txn.code_challenge,
                scopes=list(SCOPES),
                resource=txn.resource,
                expires_at=time.time() + AUTH_CODE_TTL,
            ),
            ttl=AUTH_CODE_TTL,
        )
        logger.info("Plane API-key sign-in succeeded (user=%s, workspace=%s)", user.get("id"), slug)

        response = RedirectResponse(construct_redirect_uri(txn.redirect_uri, code=code, state=txn.state), 303)
        response.delete_cookie(CSRF_COOKIE, path=self._cookie_path())
        return response

    # -- HTML ---------------------------------------------------------------

    def _cookie_path(self) -> str:
        return (urlparse(str(self.base_url)).path.rstrip("/") or "") + LOGIN_PATH

    def _page(self, body: str, status: int = 200) -> HTMLResponse:
        doc = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>Connect Plane</title>
<style>
:root {{ color-scheme: light dark; --bg:#f6f7f9; --card:#fff; --fg:#1b1f24; --muted:#5f6b7a; --border:#d9dee5;
  --accent:#3f76ff; --accent-fg:#fff; --error-bg:#fdecec; --error-fg:#a61b1b; }}
@media (prefers-color-scheme: dark) {{ :root {{ --bg:#111418; --card:#1a1f25; --fg:#e8ebef; --muted:#9aa5b1;
  --border:#2c343d; --error-bg:#3a1c1c; --error-fg:#ffb4b4; }} }}
* {{ box-sizing:border-box }}
body {{ margin:0; min-height:100vh; display:flex; align-items:center; justify-content:center; padding:16px;
  background:var(--bg); color:var(--fg); font:15px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif }}
main {{ width:100%; max-width:420px; background:var(--card); border:1px solid var(--border); border-radius:12px;
  padding:28px }}
h1 {{ font-size:20px; margin:0 0 8px }}
p {{ margin:0 0 16px; color:var(--muted) }}
label {{ display:block; font-weight:600; margin:16px 0 6px }}
input {{ width:100%; padding:10px 12px; border:1px solid var(--border); border-radius:8px; font:inherit;
  background:transparent; color:inherit }}
input[readonly] {{ opacity:.75 }}
small {{ display:block; color:var(--muted); margin-top:6px }}
button {{ width:100%; margin-top:24px; padding:11px; border:0; border-radius:8px; background:var(--accent);
  color:var(--accent-fg); font:inherit; font-weight:600; cursor:pointer }}
.error {{ background:var(--error-bg); color:var(--error-fg); padding:10px 12px; border-radius:8px; margin:0 0 8px }}
a {{ color:var(--accent) }}
</style></head><body><main>{body}</main></body></html>"""
        response = HTMLResponse(doc, status_code=status)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'"
        )
        return response

    def _render_expired(self, message: str | None = None) -> HTMLResponse:
        text = html.escape(message or "This sign-in link has expired or was already used.")
        return self._page(
            f"<h1>Sign-in expired</h1><p>{text}</p><p>Go back to your app and start the connection again.</p>",
            status=400,
        )

    def _render_form(
        self,
        txn_id: str,
        txn: LoginTransaction,
        *,
        error: str | None = None,
        workspace_slug: str | None = None,
    ) -> HTMLResponse:
        esc = html.escape
        client_label = esc(txn.client_name or "An MCP client")
        redirect_host = esc(urlparse(txn.redirect_uri).netloc or txn.redirect_uri)
        slug_value = esc(workspace_slug or self.default_workspace_slug)
        slug_locked = len(self.allowed_workspace_slugs) == 1
        plane_url = esc(self.plane_base_url)
        error_html = f'<div class="error" role="alert">{esc(error)}</div>' if error else ""

        body = f"""
<h1>Connect Plane</h1>
<p><strong>{client_label}</strong> wants to read and change work in your Plane workspace at
{esc(urlparse(self.plane_base_url).netloc)}. After you continue you will be returned to
<strong>{redirect_host}</strong>.</p>
{error_html}
<form method="post" action="{esc(self._form_action())}" autocomplete="off">
<input type="hidden" name="txn" value="{esc(txn_id)}">
<input type="hidden" name="csrf" value="{esc(txn.csrf)}">
<label for="workspace_slug">Workspace slug</label>
<input id="workspace_slug" name="workspace_slug" value="{slug_value}" required
 pattern="[a-z0-9][a-z0-9_\\-]{{0,47}}" {"readonly" if slug_locked else ""}>
<small>The part after the domain in your Plane address, e.g. …/<em>my-team</em>/projects.</small>
<label for="api_key">Plane API key</label>
<input id="api_key" name="api_key" type="password" required autofocus spellcheck="false">
<small>Create a personal access token in <a href="{plane_url}" target="_blank"
 rel="noopener noreferrer">Plane</a> (profile or account settings → API tokens).
The key is stored encrypted on this server and never shown to {client_label}.</small>
<button type="submit">Connect</button>
</form>"""
        response = self._page(body)
        response.set_cookie(
            CSRF_COOKIE,
            txn.csrf,
            max_age=LOGIN_TRANSACTION_TTL,
            path=self._cookie_path(),
            secure=self._secure_cookies,
            httponly=True,
            samesite="lax",
        )
        return response

    def _form_action(self) -> str:
        return (urlparse(str(self.base_url)).path.rstrip("/") or "") + LOGIN_PATH
