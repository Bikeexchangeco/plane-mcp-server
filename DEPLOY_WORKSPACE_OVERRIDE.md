# Deploying the per-call workspace override — iDeum instance (LXC 201)

## Context

`plane-mcp-server` (the official Plane MCP server, `makeplane/plane-mcp-server`) binds
one workspace slug per connection — the `X-Workspace-slug` header is read once and
baked into every tool call for the life of that connection. This means reaching N
Plane workspaces from one AI client normally requires N separate MCP server
registrations (N headers, N PATs, N restarts).

This repo is a fork (`Bikeexchangeco/plane-mcp-server`, branch
`feature/per-call-workspace-override`) that adds an optional `workspace` argument to
every one of the 28 tools. When supplied, it overrides the connection's default
workspace for that one call only; when omitted, behavior is 100% unchanged (existing
single-workspace connections keep working exactly as before).

**This has already been built, tested, and deployed successfully against ONA's own
Plane instance** (`plane.baristaai.cloud`, LXC 200, container name `plane`, host
`pve4` / Proxmox at `192.168.1.40` / Tailscale `100.116.200.99`). That deployment is
live and confirmed working with real workspace data (see "Verification already done
on ONA" below).

**What's needed now**: repeat the exact same deployment on the separate iDeum Plane
instance — `plane.ideum.co`, self-hosted in **LXC 201** (container name
`plane-ideum`), on the **same Proxmox host** (`pve4`, reachable the same way as LXC
200 — see "How to reach the host" below). Same `makeplane/plane-aio-community`
install, same `plane-mcp` compose setup, byte-for-byte identical
`docker-compose.mcp.yml` to ONA's — this is not a new integration, it's the same
patch applied to a second, parallel instance.

## Current state (as of this handoff)

- ✅ Code changes: complete, tested, merged into `feature/per-call-workspace-override`
  on `Bikeexchangeco/plane-mcp-server` (GitHub).
- ✅ Docker image built and tagged `plane-mcp-server:workspace-override` — exists on
  the felipe workstation (built via `docker build -t plane-mcp-server:workspace-override .`
  from the repo root) **and already transferred into LXC 201's local Docker image
  cache** (`docker save | ssh ... | docker load` was already run against LXC 201 —
  confirm with `docker images | grep workspace-override` inside LXC 201, it should
  already be there).
- ✅ ONA's instance (LXC 200): fully deployed and verified in production.
- ⬜ iDeum's instance (LXC 201): image loaded, **not yet tested or deployed**. This is
  where you're picking up.
- ⚠️ No Personal Access Token for the iDeum Plane workspace was available in the
  session that did the ONA deployment, so the standalone test on LXC 201 could only
  be schema/boot-verified there, not fully round-trip tested with real data before
  this handoff. See "Verification" below for what's still needed.

## How to reach the host

```bash
ssh -i ~/.ssh/id_ed25519_mac_mini root@100.116.200.99   # this is the pve4 Proxmox host, via Tailscale
pct exec 201 -- bash                                     # drops you into LXC 201 (plane-ideum)
```
(`id_ed25519_mac_mini` is the same SSH key used for the other Proxmox-family hosts in
this environment — `proxmox`, `proxmox-ts`, `marketiq`, etc.)

Everything below assumes you're running commands **inside LXC 201** (either via
`pct exec 201 -- bash -c '...'` from the host, or having dropped into an interactive
shell with `pct exec 201 -- bash`).

## Step 1 — confirm the image is present

```bash
docker images | grep workspace-override
```

If it's not there (e.g. this is a fresh session and the transfer didn't happen), build
it fresh instead of re-transferring:

```bash
mkdir -p /opt/plane/plane-mcp-build && cd /opt/plane/plane-mcp-build
git clone --branch feature/per-call-workspace-override \
  https://github.com/Bikeexchangeco/plane-mcp-server.git .
docker build -t plane-mcp-server:workspace-override .
```

**Do not use plain `docker build` from your own workstation if that workstation's
Docker is itself nested inside an LXC container** — building triggered an apparmor
error under nested containerization on LXC 200 (`unable to apply apparmor profile`)
during intermediate `RUN apt-get` steps. If you hit that, build on a host with a
non-nested Docker daemon instead (a normal workstation, or a plain VM) and transfer
the image in via `docker save | ssh ... docker load`, same as was done for LXC 200.

## Step 2 — standalone test (do this before touching the live container)

Run the new image as a **separate, differently-ported** container alongside the
still-running production `plane-mcp` — this never touches the live service.

```bash
docker rm -f plane-mcp-test 2>/dev/null
docker run -d --name plane-mcp-test \
  --network plane_default \
  --env-file /opt/plane/mcp-variables.env \
  -e REDIS_HOST=plane-mcp-redis -e REDIS_PORT=6379 \
  -p 18211:8211 \
  --security-opt apparmor=unconfined \
  plane-mcp-server:workspace-override

sleep 4
docker logs plane-mcp-test --tail 20
```

**Expect to see, in order**: `Redis connection verified (PING succeeded)` →
`Token store: Redis (auth=none, host=plane-mcp-redis, port=6379)` →
`Plane MCP: advertising 28 tools` (twice — normal, it's initialized once per mounted
sub-app) → `Uvicorn running on http://0.0.0.0:8211`. No errors.

LXC 201's LAN IP is `192.168.1.185` (confirm with `hostname -I` if this changes), so
the test container is reachable at `http://192.168.1.185:18211` from anywhere on the
same LAN — e.g. from the felipe workstation directly, no tunnel needed.

**Important path gotcha found during the ONA deployment**: the server's own startup
log says `"Starting HTTP server at URLs: /mcp and /header/mcp"` — **this is stale/
wrong**, ignore it. The real header-auth path (matching production's actual URL
shape) is:

```
/http/api-key/mcp
```

i.e. test against `http://192.168.1.185:18211/http/api-key/mcp`, not `/header/mcp`.

## Step 3 — verify

### 3a. Schema-level (no credentials needed)

Confirm the `workspace` tool has 28 tools listed and the new `workspace` parameter
present in each tool's schema. Easiest with the FastMCP Python client:

```python
import asyncio, json
from fastmcp import Client
from fastmcp.client.transports import StreamableHttpTransport

# Any real iDeum PAT + workspace slug works here -- even one with minimal read
# access is enough to prove the schema and the override mechanism.
headers = {"Authorization": "Bearer <IDEUM_PAT>", "X-Workspace-slug": "<ideum-workspace-slug>"}

async def main():
    transport = StreamableHttpTransport(url="http://192.168.1.185:18211/http/api-key/mcp", headers=headers)
    async with Client(transport) as client:
        tools = await client.list_tools()
        print(f"{len(tools)} tools")
        ws_tool = next(t for t in tools if t.name == "workspace")
        print("workspace param present:", "workspace" in ws_tool.inputSchema["properties"])

asyncio.run(main())
```

### 3b. Full round-trip (needs a real iDeum PAT — this is the gap left from the ONA session)

Repeat what was done for ONA:

1. Call a cheap read action with **no** `workspace` override — e.g.
   `project` tool, `list` action, `per_page: 3` — confirm it returns real iDeum
   project data (proves zero regression to existing single-workspace behavior).
2. Call the **same** action with `workspace` set to a slug the PAT does **not** have
   access to (anything bogus works, e.g. `"definitely-not-a-real-workspace-xyz"`).
   Expect a **different** result than step 1 — specifically an HTTP 403/404 from
   Plane's own API — not a silent fallback to the default workspace's data. That
   difference is the proof the override is actually being honored server-side, not
   just accepted-and-ignored.

If you don't have an iDeum PAT: ask Felipe for one before doing the production swap
in Step 5 below, or if he's comfortable proceeding on the schema-level check alone
(the underlying code is identical to what's already proven working end-to-end on
ONA's instance, so this is a lower-risk gap than it would be for genuinely new code).

## Step 4 — clean up the test container

```bash
docker rm -f plane-mcp-test
```

## Step 5 — the actual swap (production)

Back up the compose file first, so rollback is a one-command file restore:

```bash
cd /opt/plane
cp docker-compose.mcp.yml docker-compose.mcp.yml.bak-$(date +%Y%m%d-%H%M%S)
sed -i 's|image: makeplane/plane-mcp-server:stable|image: plane-mcp-server:workspace-override|' docker-compose.mcp.yml
diff docker-compose.mcp.yml.bak-* docker-compose.mcp.yml   # sanity check: should show exactly one changed line
```

Recreate **only** the `plane-mcp` service — this does not touch `plane-mcp-redis`,
and does not touch the actual Plane app/database containers (`plane`, `plane-db`,
`plane-mq`, `plane-minio`) at all; they're not even in this compose file.

```bash
docker compose -f docker-compose.mcp.yml up -d plane-mcp
sleep 4
docker ps --filter name=plane-mcp --format "{{.Names}}\t{{.Image}}\t{{.Status}}"
docker logs plane-mcp --tail 20
```

You'll likely see a `Found orphan containers (plane, plane-db, plane-mq, ...)`
warning — that's expected and harmless, it's Compose noting those containers belong
to the *other* compose file (the main Plane app stack), not this one. Ignore it.

## Step 6 — verify production

Repeat Step 3's checks, but against the real public URL instead of the LAN test port:

```
https://mcp-plane.ideum.co/http/api-key/mcp
```

(confirmed reachable via Cloudflare during this handoff — `dig +short mcp-plane.ideum.co`
resolves, and the domain is already routed the same way as ONA's
`mcp-plane.baristaai.cloud`.)

**Any already-open AI client session connected to the iDeum Plane MCP server will
have cached the old tool schema from before the swap** — MCP clients fetch
`tools/list` once at connection time and don't auto-refresh mid-session. To see the
new `workspace` parameter reflected, either open a **fresh** connection (a new script
run, like the one in Step 3a, works fine) or restart/reconnect the existing client.
Don't mistake a stale cached schema for the deploy having failed.

## Rollback (if anything looks wrong, at any point after Step 5)

```bash
cd /opt/plane
cp docker-compose.mcp.yml.bak-<timestamp> docker-compose.mcp.yml
docker compose -f docker-compose.mcp.yml up -d plane-mcp
```

## Known gaps to close

1. **No iDeum PAT was available during the ONA-session handoff** — Step 3b needs one
   for a complete verification before Step 5. Get one from whoever administers
   `plane.ideum.co`, or ask Felipe.
2. **A credential exposure happened earlier in the related work**: a PAT
   (`plane_api_742df5ed6bca49ebaf664decd467cb29`, for the *ONA* workspace
   `ona-barista-ai-apps`) was pasted into a chat transcript during the original
   planning conversation and should be rotated if it hasn't been already — unrelated
   to this deployment directly, but flagging since it's the same family of
   credentials.
3. Consider whether `plane.ideum.co`'s `mcp-variables.env` needs any values reissued
   or rotated as part of this — not checked in this handoff, only the compose
   structure was confirmed identical to ONA's.

## Reference — what "already proven working" looks like (from the ONA deployment)

```
28 tools advertised, workspace override param present: True

--- default workspace call (project list) ---
CallToolResult(... "total_count":4 ... "name":"Website reDesign implementation Dev" ...)

--- override to a bogus workspace slug ---
ToolError: Error calling tool 'project': HTTP 403: Forbidden: You do not have permission to perform this action.

connection's own default workspace slug: 'ona-internal-website-and-ecommerce'
```

That's the shape of a fully-passing verification: default call returns real data
unchanged, override call fails *differently* (a real, workspace-specific permission
error) rather than silently succeeding against the default workspace.
