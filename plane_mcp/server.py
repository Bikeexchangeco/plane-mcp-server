"""FastMCP server factories for the three supported transports."""

from __future__ import annotations

import os

from fastmcp import FastMCP
from mcp.types import Icon

from plane_mcp.auth import PlaneApiKeyOAuthProvider, PlaneHeaderAuthProvider, PlaneOAuthProvider
from plane_mcp.instructions import SERVER_INSTRUCTIONS
from plane_mcp.middleware import CoerceArguments, PlaneLoggingMiddleware, ValidateActionArguments
from plane_mcp.storage import build_token_store
from plane_mcp.tools import register_tools

# Baseline redirect URIs shipped with the server. Additional patterns can be
# supplied at runtime via PLANE_OAUTH_ALLOWED_REDIRECT_URIS (comma-separated) so
# onboarding a new MCP client needs only a config change, not a new release.
DEFAULT_ALLOWED_REDIRECT_URIS = [
    # Localhost only for http (dynamic ports from MCP clients)
    "http://localhost:*",
    "http://localhost:*/*",
    "http://127.0.0.1:*",
    "http://127.0.0.1:*/*",
    # Known MCP client custom protocol schemes
    "cursor://anysphere.cursor-mcp/oauth/*",
    "https://www.cursor.com/*",
    "https://vscode.dev/redirect",
    "https://insiders.vscode.dev/redirect",
    "https://antigravity.google/oauth-callback",
    # Claude.ai web client
    "https://claude.ai/*",
    # ChatGPT connectors — per-connector callback + legacy redirect
    "https://chatgpt.com/connector/oauth/*",
    "https://chatgpt.com/connector_platform_oauth_redirect",
]


def get_allowed_client_redirect_uris() -> list[str]:
    """Return the redirect URI allowlist: built-in defaults plus any extras
    from the PLANE_OAUTH_ALLOWED_REDIRECT_URIS env var (comma-separated)."""
    allowed = list(DEFAULT_ALLOWED_REDIRECT_URIS)
    extra = os.getenv("PLANE_OAUTH_ALLOWED_REDIRECT_URIS", "")
    for uri in extra.split(","):
        uri = uri.strip()
        if uri and uri not in allowed:
            allowed.append(uri)
    return allowed


def _configured(mcp: FastMCP) -> FastMCP:
    """The middleware stack and tools every transport shares."""
    mcp.add_middleware(PlaneLoggingMiddleware(include_payloads=True))
    mcp.add_middleware(CoerceArguments())
    mcp.add_middleware(ValidateActionArguments())
    register_tools(mcp)
    return mcp


def _csv_env(name: str) -> list[str]:
    return [v.strip() for v in os.getenv(name, "").split(",") if v.strip()]


def oauth_mode() -> str:
    """Which provider backs the OAuth endpoints.

    ``plane`` (default) proxies to Plane's own OAuth apps. ``api_key`` makes this
    server the authorization server and asks the user for a Plane API key —
    for self-hosted Plane editions that have no OAuth apps.
    """
    mode = os.getenv("PLANE_MCP_OAUTH_MODE", "plane").strip().lower()
    if mode not in ("plane", "api_key"):
        raise ValueError(f"PLANE_MCP_OAUTH_MODE must be 'plane' or 'api_key', got {mode!r}")
    return mode


def build_apikey_oauth_provider(base_path: str = "/") -> PlaneApiKeyOAuthProvider:
    return PlaneApiKeyOAuthProvider(
        base_url=f"{os.getenv('PLANE_OAUTH_PROVIDER_BASE_URL')}{base_path}",
        auth_secret=os.getenv("PLANE_MCP_AUTH_SECRET", ""),
        plane_base_url=os.getenv("PLANE_BASE_URL", ""),
        plane_internal_base_url=os.getenv("PLANE_INTERNAL_BASE_URL", ""),
        client_storage=build_token_store(),
        allowed_client_redirect_uris=get_allowed_client_redirect_uris(),
        allowed_workspace_slugs=_csv_env("PLANE_MCP_ALLOWED_WORKSPACES"),
        default_workspace_slug=os.getenv("PLANE_MCP_DEFAULT_WORKSPACE", ""),
        access_token_ttl=int(os.getenv("PLANE_MCP_ACCESS_TOKEN_TTL", "3600")),
        refresh_token_ttl=int(os.getenv("PLANE_MCP_REFRESH_TOKEN_TTL", str(90 * 24 * 3600))),
        required_scopes=["read", "write"],
    )


def get_oauth_mcp(base_path: str = "/") -> FastMCP:
    """Build the FastMCP instance for the OAuth HTTP / SSE transports."""
    if oauth_mode() == "api_key":
        auth = build_apikey_oauth_provider(base_path)
    else:
        auth = _build_plane_oauth_provider(base_path)
    oauth_mcp = FastMCP(
        "Plane MCP Server",
        instructions=SERVER_INSTRUCTIONS,
        icons=[Icon(src="https://plane.so/favicon.ico", alt="Plane MCP Server")],
        website_url="https://plane.so",
        auth=auth,
    )
    return _configured(oauth_mcp)


def _build_plane_oauth_provider(base_path: str) -> PlaneOAuthProvider:
    return PlaneOAuthProvider(
        client_id=os.getenv("PLANE_OAUTH_PROVIDER_CLIENT_ID", ""),
        client_secret=os.getenv("PLANE_OAUTH_PROVIDER_CLIENT_SECRET", ""),
        base_url=f"{os.getenv('PLANE_OAUTH_PROVIDER_BASE_URL')}{base_path}",
        plane_base_url=os.getenv("PLANE_BASE_URL", ""),
        plane_internal_base_url=os.getenv("PLANE_INTERNAL_BASE_URL", ""),
        enable_cimd=os.getenv("PLANE_OAUTH_PROVIDER_ENABLE_CIMD", "false").lower() == "true",
        client_storage=build_token_store(),
        required_scopes=["read", "write"],
        allowed_client_redirect_uris=get_allowed_client_redirect_uris(),
    )


def get_header_mcp():
    header_mcp = FastMCP(
        "Plane MCP Server (header-http)",
        instructions=SERVER_INSTRUCTIONS,
        auth=PlaneHeaderAuthProvider(
            required_scopes=["read", "write"],
        ),
    )
    return _configured(header_mcp)


def get_stdio_mcp():
    stdio_mcp = FastMCP(
        "Plane MCP Server (stdio)",
        instructions=SERVER_INSTRUCTIONS,
    )
    return _configured(stdio_mcp)
