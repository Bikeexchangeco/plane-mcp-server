# Using this server as a claude.ai / ChatGPT custom connector

This covers the `api_key` OAuth mode added in `feature/apikey-oauth` — the piece that lets
clients that only speak OAuth (claude.ai custom connectors, ChatGPT connectors) sign in to
a self-hosted Plane instance that has no OAuth apps of its own.

Live reference deployment: `mcp-plane.ideum.co` (LXC 201, `plane.ideum.co`), deployed and
verified 2026-09-29 — see `revisions/2026-09-28-...` in the infra-proxmox mdBook and
`DEPLOY_WORKSPACE_OVERRIDE.md` in this repo for the deploy runbook this was layered onto.

## How a person connects

1. In claude.ai: **Settings → Customize → Connectors → Add → Add custom connector** (or
   ChatGPT's equivalent "Add connector" flow).
2. **URL**: `https://<your-mcp-host>/http/mcp` — for the iDeum deployment, that's
   `https://mcp-plane.ideum.co/http/mcp`. Do not use `/oauth/mcp` (a stale value in this
   repo's own `CLAUDE.md`) or `/mcp` bare — see "Path reference" below.
3. Claude registers itself as an OAuth client and redirects the person's browser to this
   server's own sign-in page (`/plane-login`), not to Plane itself.
4. That page asks for two things:
   - **Workspace slug** — the part of their Plane URL after the domain (e.g. `.../colombian-coffees/projects` → `colombian-coffees`). If the server is scoped to exactly one workspace this field is pre-filled and locked; with more than one, it's a required, editable field, and each person types their own.
   - **Plane API key** — a personal access token they generate themselves in Plane (profile/account settings → API tokens). It is never shown back to the client and is stored Fernet-encrypted server-side.
5. The server validates both against the live Plane API (`users/me`, then that workspace's
   project list) before issuing anything. A bad key or a workspace the key can't see are
   both rejected with a plain-language error on the same page — nothing is silently
   accepted.
6. Once connected, every tool call runs as that person's own Plane account, scoped to the
   workspace they signed in with (see "Isolation model" below for what "scoped" actually
   means).

## Path reference (the one thing that's easy to get wrong)

The server mounts three transports side by side; `CLAUDE.md`'s own summary of the OAuth
path (`/oauth/mcp`) is stale — the real mount, from `__main__.py`, is:

| Path | Auth | Use |
|---|---|---|
| `/http/mcp` | **This OAuth mode** | claude.ai / ChatGPT custom connectors |
| `/http/api-key/mcp` | Static header (`Authorization: Bearer <PAT>`, `X-Workspace-slug: <slug>`) | Scripts, other MCP clients that support static headers, service integrations (this is what the existing MarketIQ/AttributionOS/Voce configs use) |
| `/sse` | Same OAuth provider, legacy SSE transport | Older MCP clients that predate Streamable HTTP |

`/.well-known/oauth-authorization-server` and `/.well-known/oauth-protected-resource` are
served automatically for the OAuth mount and are what tells claude.ai this is a valid OAuth
server in the first place — no manual configuration needed beyond the URL above.

## Isolation model — what actually stops one client reaching another's data

Two independent layers, and only one of them is configuration:

1. **`PLANE_MCP_ALLOWED_WORKSPACES`** (server config) — a coarse, server-wide gate on which
   workspace slugs the sign-in page will even attempt. It is not per-user. Its only job is
   keeping a workspace off this connector entirely (e.g. excluding an internal workspace
   from a connector meant for external clients).
2. **Plane's own membership/RBAC** (not this server's code) — the real enforcement. Every
   sign-in and every tool call goes through Plane's live API using *that specific person's*
   API key, so a client whose account has no membership in a workspace gets a clean
   `403 Forbidden` from Plane itself the moment they try — whether they try at sign-in
   (`workspace_slug` field) or later via the `workspace` argument any tool accepts to
   override the connection's default for one call. **Verified 2026-09-29** against
   production: a client PAT scoped to one workspace got real data on its own workspace and
   a clean 403 on three others it tried to override into.

The practical consequence: if you need tighter separation than "whatever Plane says this
API key can see," that's a Plane membership/role change for that person's account, not an
MCP setting. Conversely, an internal/shared service account that legitimately belongs to
several workspaces in Plane will legitimately be able to reach all of them through this
connector too — that's expected, not a bug, and worth remembering when deciding which
accounts' API keys get handed to whom.

## Tool catalog (28 tools, 183 actions)

One action-dispatch tool per Plane resource — call the tool, pass an `action` argument
naming the operation, plus that action's own parameters. Every tool also accepts an
optional `workspace` argument to override the connection's default workspace for that one
call (see isolation model above for what that can and can't reach).

| Tool | Actions | Notes |
|---|---|---|
| `project` | list, retrieve, create, update, delete, archive, unarchive, worklog_summary, get_features, update_features | |
| `workitem` | list, list_archived, retrieve, retrieve_by_identifier, search, count, create, update, delete, archive, manage_assignee, manage_label | the core "issue/task" resource |
| `workitem_comment`, `workitem_link`, `workitem_attachment`, `workitem_activity`, `workitem_relation` | full CRUD each | sub-resources of a work item |
| `workitem_type`, `workitem_property` | type/custom-field management | |
| `cycle`, `module`, `milestone` | list/retrieve/create/update/delete + list/manage_workitems; cycle and module also archive/unarchive | sprint-like groupings |
| `state`, `label` | full CRUD | workflow states, labels |
| `release`, `release_label`, `release_tag` | full CRUD + changelog | |
| `initiative` | full CRUD + project linking | groups of projects |
| `intake` | full CRUD | intake/triage queue |
| `customer`, `customer_property`, `customer_request` | full CRUD | Plane's customer-tracking feature |
| `project_estimate` | full CRUD + points | |
| `page` | list, retrieve, create, list/attach/detach for work items | |
| `work_log` | list, create, update, delete | time tracking |
| `member` | **read-only**: me, list_workspace, list_project, list_roles, retrieve_role | no add/remove-member action exists in this tool at all |
| `workspace` | **feature-flags only**: get_features, update_features | no delete-workspace or workspace-settings surface |
| `get_pql_reference` | read | documentation tool for Plane's query language |

**No admin-destructive surface is exposed anywhere in this catalog** — no delete-workspace,
no remove-member, no billing/account actions. The `delete` actions that do exist are all
ordinary "delete a project/work item/label you have access to" operations, gated the same
way any other write is: by Plane's own RBAC for that account.

## Should some tools be restricted? (open question, not yet built)

There is currently **no mechanism** to expose a subset of tools per deployment or per
connection — `required_scopes=["read", "write"]` in `server.py` is unconditional, the
sign-in form always issues both scopes, and no middleware filters `list_tools`/`call_tool`
by anything user- or workspace-specific. It's all 28 tools/183 actions or none.

Given the catalog audit above (no admin-destructive actions, Plane's RBAC already gates
everything), a stricter allowlist is probably not *necessary* for safety — but it may still
be worth it for **UX** (a business user connecting via claude.ai doesn't need `release`,
`project_estimate`, or `customer_property` cluttering the surface) or for **defense in
depth** against a compromised or over-provisioned Plane account. If that's wanted later,
the natural hook is a new `PLANE_MCP_ALLOWED_TOOLS` env var checked in `register_tools`
(`tools/__init__.py`) before a resource module's `register(mcp)` is called — not built as
part of this deployment.

## Copying this to another Plane instance (baristaai.cloud / geekboss)

The MCP implementation is portable and workspace-agnostic; per-instance state lives
entirely in environment variables, not code:

- `PLANE_BASE_URL` (and `PLANE_INTERNAL_BASE_URL` if the MCP server reaches Plane over a
  different address than the public one)
- `PLANE_MCP_OAUTH_MODE=api_key`, a fresh `PLANE_MCP_AUTH_SECRET` (32+ random chars, unique
  per instance — do not reuse iDeum's), `PLANE_MCP_ALLOWED_WORKSPACES` set to whatever
  workspaces that specific instance should serve, `PLANE_MCP_DEFAULT_WORKSPACE` only if it
  serves exactly one
- **`PLANE_OAUTH_PROVIDER_BASE_URL`** — required even in `api_key` mode (confirmed by a
  standalone build test 2026-09-29; `CLAUDE.md`'s own env-var table only lists it under
  "http/sse OAuth" without flagging this). Must be the MCP server's own public HTTPS URL
  (e.g. `https://mcp-plane.baristaai.cloud`), not Plane's URL. Omitting it fails at startup
  with a pydantic URL-parsing error (`'None/http'`), not a helpful message — worth fixing
  in the codebase itself, but noted here in the meantime.
- `REDIS_HOST`/`REDIS_PORT` pointed at that instance's own Redis (falls back to in-memory
  if unset — fine for a single-replica deployment, loses sessions on restart otherwise)
- A Cloudflare tunnel ingress hostname of that instance's choosing added to its own
  `cloudflared` config, mirroring the pattern in `DEPLOY_WORKSPACE_OVERRIDE.md`

See `plane-mcp-implementation/` (sibling to this repo) for a stripped copy containing only
`plane_mcp/`, the `Dockerfile`, and `pyproject.toml` — no `.venv`, tests, or git history —
ready to `docker build` against a fresh instance.
