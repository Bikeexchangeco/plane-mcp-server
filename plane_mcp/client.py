"""Plane client initialization for MCP server."""

import os
from typing import Annotated, NamedTuple

from fastmcp.server.auth.auth import AccessToken
from fastmcp.server.dependencies import get_access_token
from fastmcp.utilities.logging import get_logger
from plane import PlaneClient
from pydantic import Field

logger = get_logger(__name__)

#: Shared parameter type for the optional per-call workspace override. One
#: definition so its description cannot drift across the 28 tools that accept
#: it; see `get_plane_client_context`. `middleware.CROSS_CUTTING_ARGUMENTS`
#: exempts the name `workspace` from each action's own accepted-parameter
#: check, the same way `action` itself is exempt -- it is not part of any
#: resource's field set.
WorkspaceOverride = Annotated[
    str,
    Field(
        default="",
        description=(
            "Override this connection's default Plane workspace for this call only. "
            "Pass a workspace slug to reach a different workspace than the one this "
            "connection was configured for, as long as the same credential can see it. "
            "Omit to use the connection's configured workspace."
        ),
    ),
]


class PlaneClientContext(NamedTuple):
    """Context containing Plane client and workspace information."""

    client: PlaneClient
    workspace_slug: str


def get_plane_client_context(workspace_slug: str = "") -> PlaneClientContext:
    """
    Initialize and return a PlaneClient instance with workspace context.

    Authentication is handled by the PlaneOAuthProvider, which supports:
    1. Environment variables (PLANE_API_KEY + PLANE_WORKSPACE_SLUG)
    2. HTTP headers (x-api-key + x-workspace-slug)
    3. OAuth access token

    Environment variables:
    - PLANE_INTERNAL_BASE_URL: Internal URL for Plane API (preferred for server-to-server calls)
    - PLANE_BASE_URL: Base URL for Plane API (fallback, default: https://api.plane.so)

    Args:
        workspace_slug: Optional per-call override. When supplied (non-empty), this
            wins over the connection's header/env/OAuth-derived workspace slug --
            lets a single MCP connection reach multiple workspaces one call at a
            time, as long as the same credential can see all of them. Leave empty
            to keep the existing single-workspace-per-connection behavior.

    Returns:
        PlaneClientContext containing configured PlaneClient instance and workspace slug

    Raises:
        ConfigurationError: If access token is not available or workspace slug is missing
    """
    base_url = os.getenv("PLANE_INTERNAL_BASE_URL") or os.getenv("PLANE_BASE_URL", "https://api.plane.so")
    workspace_slug_override = workspace_slug
    workspace_slug = os.getenv("PLANE_WORKSPACE_SLUG", "")

    api_key = os.getenv("PLANE_API_KEY", "")
    access_token = None

    # Get access token from the OAuth provider (which handles all auth methods)
    stored_access_token: AccessToken | None = get_access_token()
    if stored_access_token:
        # Determine authentication method to use appropriate PlaneClient constructor
        auth_method = stored_access_token.claims.get("auth_method", "oauth")
        token = stored_access_token.token
        workspace_slug = stored_access_token.claims.get("workspace_slug", "")

        # For API key auth methods, use api_key parameter; for OAuth, use access_token
        if auth_method in ("api_key_env", "api_key_header"):
            api_key = token
        else:
            access_token = token

    if access_token:
        client = PlaneClient(
            base_url=base_url,
            access_token=access_token,
        )
    else:
        client = PlaneClient(
            base_url=base_url,
            api_key=api_key,
        )

    return PlaneClientContext(
        client=client,
        workspace_slug=workspace_slug_override or workspace_slug,
    )
