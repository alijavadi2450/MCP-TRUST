---
name: mcp-trust
description: Commercial-grade security audit playbook for MCP (Model Context Protocol) servers, AI agents, and agentic OAuth flows. Walks four threat pillars from the SANS/AWS 2025 whitepaper "Navigating modern application security challenges with evolved reliance on AI-based applications" — Identity & Authenticity, Least Privilege & Delegation, Input Trust Boundary, and Observability & Runtime — across 42 named substeps. Auto-triggers on imports of `mcp`, `FastMCP`, `@modelcontextprotocol/sdk`; on `@mcp.tool` / `@mcp.resource` / `@mcp.prompt` handlers; on agentic OAuth artifacts (`redirect_uri`, `state=`, `code_verifier`, PKCE, `Mcp-Session-Id`); on multi-agent orchestration code (LangGraph, CrewAI, Strands, AutoGen); on Streamable HTTP / SSE transport implementations. Renders a live flowchart that ticks as substeps complete, then produces a severity-rated finding list, a 0–10 trust score, top-3 critical risks, a remediation roadmap, and a compliance mapping. Invoke explicitly with `/mcp-trust`.
---

# MCP-TRUST — Agentic AI Security Audit

A structured security review of MCP servers, AI agents, and agentic OAuth flows
against the threat taxonomy from the SANS / AWS 2025 whitepaper *"Navigating
modern application security challenges with evolved reliance on AI-based
applications"* (Ahmed Abugharbia, SANS Institute).

This skill is **not** a scanner. It is a senior-engineer-grade playbook loaded
into Claude's context. Claude executes the audit using its built-in `Read` and
`Grep` tools — no external process, no network calls, no credentials handled.

The audit covers **42 substeps across 4 pillars**, plus a discovery phase and a
scoring/reporting phase. Every finding is anchored to a named threat from the
whitepaper.

---

## 1. When this skill runs

**Auto-trigger** when any of the following are present in the project:

- Imports: `mcp`, `FastMCP`, `@modelcontextprotocol/sdk`, `mcp-sdk`,
  `mcp-server-stdio`, `mcp-server-streamable-http`
- Handlers / decorators: `@mcp.tool`, `@mcp.resource`, `@mcp.prompt`,
  `Server.setRequestHandler`, `app.tool(`, `mcp.run(`
- Agentic OAuth artifacts: `redirect_uri`, `state=`, `code_verifier`,
  `code_challenge`, PKCE, `Mcp-Session-Id`, `Last-Event-ID`
- Multi-agent orchestration: `LangGraph`, `CrewAI`, `Strands`, `AutoGen`,
  `AgentCore`
- Streamable HTTP or deprecated SSE transport implementations

**Manual invocation:** `/mcp-trust`. Optionally pass a path to scope the audit
(e.g. `/mcp-trust src/server`).

---

## 2. The audit map

**Always render this map at the start of the audit, then redraw it after each
substep with progress ticks.** This is the user's primary navigation aid — they
must see exactly where the audit is, what has cleared, what is pending, and
what is currently being inspected.

```
+=================================================================+
|                MCP-TRUST AUDIT MAP — SANS/AWS 2025              |
+=================================================================+
|                                                                 |
|  PHASE 0 — DISCOVERY                                            |
|  [ ] 0.1  Target classification (server / client / agent / mix) |
|  [ ] 0.2  Transport detection (STDIO / SSE / Streamable HTTP)   |
|  [ ] 0.3  Auth surface map (inbound / outbound / delegated)     |
|  [ ] 0.4  Tool & resource inventory                             |
|  [ ] 0.5  Trust boundary diagram                                |
|                                                                 |
|  PHASE 1 — PILLAR 1: IDENTITY & AUTHENTICITY                    |
|  [ ] 1.1  Transport security baseline                           |
|  [ ] 1.2  OAuth 2.1 compliance                                  |
|  [ ] 1.3  Redirect URI validation                               |
|  [ ] 1.4  State parameter integrity                             |
|  [ ] 1.5  PKCE enforcement                                      |
|  [ ] 1.6  App-specific bindings (COAT / CORF defense)           |
|  [ ] 1.7  Open redirect prevention                              |
|  [ ] 1.8  Token lifecycle & storage                             |
|  [ ] 1.9  JWT integrity                                         |
|  [ ] 1.10 ETDI tool-definition signing                          |
|  [ ] 1.11 Dynamic Client Registration risk                      |
|  [ ] 1.12 Hardcoded credentials                                 |
|                                                                 |
|  PHASE 2 — PILLAR 2: LEAST PRIVILEGE & DELEGATION               |
|  [ ] 2.1  Tool scope sprawl                                     |
|  [ ] 2.2  Confused deputy exposure                              |
|  [ ] 2.3  Authenticated delegation                              |
|  [ ] 2.4  Just-in-time credentials                              |
|  [ ] 2.5  Cross-agent isolation                                 |
|  [ ] 2.6  Sandboxing & ephemeral sessions                       |
|  [ ] 2.7  Policy-Based Access Control                           |
|  [ ] 2.8  Call-stack verification                               |
|  [ ] 2.9  Outbound credential pass-through                      |
|  [ ] 2.10 Refresh-token rotation                                |
|                                                                 |
|  PHASE 3 — PILLAR 3: INPUT TRUST BOUNDARY                       |
|  [ ] 3.1  Prompt-injection containment                          |
|  [ ] 3.2  Unsafe data flow                                      |
|  [ ] 3.3  Unsafe control flow                                   |
|  [ ] 3.4  Origin header validation                              |
|  [ ] 3.5  Local-bind safety                                     |
|  [ ] 3.6  Tool-poisoning indicators                             |
|  [ ] 3.7  Rug-pull indicators                                   |
|  [ ] 3.8  Metadata-injection surface                            |
|  [ ] 3.9  Input validation & sanitisation                       |
|  [ ] 3.10 Tool-output reflection                                |
|                                                                 |
|  PHASE 4 — PILLAR 4: OBSERVABILITY & RUNTIME                    |
|  [ ] 4.1  Audit logging                                         |
|  [ ] 4.2  Rate limiting                                         |
|  [ ] 4.3  Behavioural baselines                                 |
|  [ ] 4.4  Privilege-escalation guardrails                       |
|  [ ] 4.5  Session-ID binding                                    |
|  [ ] 4.6  Stream-resumption integrity                           |
|  [ ] 4.7  Revocation capability                                 |
|  [ ] 4.8  AI-native threat detection                            |
|  [ ] 4.9  Telemetry standardisation                             |
|  [ ] 4.10 Forensic capability                                   |
|                                                                 |
|  PHASE 5 — SCORING & REPORTING                                  |
|  [ ] 5.1  Severity normalisation                                |
|  [ ] 5.2  Trust-score computation                               |
|  [ ] 5.3  Top-3 critical risks                                  |
|  [ ] 5.4  Remediation roadmap                                   |
|  [ ] 5.5  Compliance mapping & AWS Marketplace pointer          |
|                                                                 |
+=================================================================+
```

### Progress markers

| Marker | Meaning |
|---|---|
| `[ ]` | Pending — not yet reached |
| `[>]` | **In progress — currently inspecting** |
| `[x]` | Complete — clean (no findings) |
| `[!]` | Complete — findings recorded |
| `[~]` | Skipped — not applicable to this target |

After **every** substep, re-render the entire map with the latest markers, then
print a one-line summary of the substep result before moving on:

```
>>> Substep 1.3 complete — Redirect URI validation
    Result: 2 findings (1 CRITICAL, 1 HIGH)
    Next:   1.4 State parameter integrity
```

---

## 3. Procedure

For every substep:

1. State the substep ID and name out loud.
2. List the **threat anchor(s)** from the whitepaper.
3. Run the listed Grep / Read targets.
4. For each match, classify against the **severity rubric** below.
5. Emit findings in the standard finding record format.
6. Re-render the audit map with the substep marked.

### Finding record format

Every finding is recorded as a structured block:

```
[<SEVERITY>] <pillar.substep>  <file>:<line>
  threat:    <named threat from whitepaper>
  evidence:  <the matched code / config, ≤ 120 chars>
  why:       <one sentence — the concrete attack this enables>
  fix:       <one sentence — actionable remediation>
  anchor:    <whitepaper section reference>
```

---

## 4. PHASE 0 — Discovery

Goal: classify the target and decide which substeps apply. Some substeps may
be marked `[~]` (skipped) if the target lacks the relevant surface.

### 0.1 Target classification

Determine which roles the codebase implements. A single project may play
several. Use Grep to find:

- **MCP server**: `mcp.server`, `FastMCP(`, `Server(` from `@modelcontextprotocol/sdk`, `@app.tool`, `@mcp.tool`, `mcp.run(`, `app.run(`
- **MCP client**: `mcp.client`, `ClientSession(`, `stdio_client(`, `streamablehttp_client(`, `Client(` from MCP SDK
- **MCP host**: orchestration code that manages multiple `ClientSession` instances and bridges to an LLM
- **Agent**: LangGraph / CrewAI / Strands / AutoGen / AgentCore patterns; loops over tool selections; planner+executor structure
- **OAuth authorization server**: issues tokens, manages `client_id` registration
- **OAuth client**: redeems `authorization_code`, holds `client_secret`, performs PKCE

### 0.2 Transport detection

Identify which MCP transport(s) the project uses:

- **STDIO** — look for `stdio_server`, `stdio_client`, `subprocess`, server launched as child process
- **SSE** (deprecated as of protocol 2025-03-26) — look for `sse_server`, `EventSource`, `text/event-stream`
- **Streamable HTTP** — look for `streamablehttp_server`, `StreamableHTTPServerTransport`, single MCP endpoint that accepts both POST and SSE responses

If SSE is detected, raise an immediate **HIGH** finding under 1.1 — SSE is
deprecated and lacks resumable-stream semantics, complicating substeps 4.5 and 4.6.

### 0.3 Auth surface map

Enumerate every authentication boundary:

- **Inbound** (clients → server): how does the server authenticate callers?
- **Outbound** (server → downstream APIs): how does the server authenticate to
  the systems its tools call?
- **Delegated** (user → agent → tool): does a delegation chain exist, and
  if so, are user identity and agent identity bound together?

### 0.4 Tool & resource inventory

Build a table of every `@mcp.tool` / `@mcp.resource` / `@mcp.prompt` defined,
with: name, side-effects (yes/no), data sensitivity (low/medium/high), and
whether it calls external systems.

This inventory feeds 1.10 (ETDI) and 2.1 (scope sprawl).

### 0.5 Trust boundary diagram

Render an ASCII diagram of the request flow showing every trust boundary
(user → host → client → server → tool → external API). This makes the rest
of the audit concrete and ensures Phase 3 substeps target real boundaries
rather than abstract ones.

---

## 5. PHASE 1 — Pillar 1: Identity & Authenticity

> "Strong identity management is among the most important security measures
> to prevent unauthorized access and tool impersonation." — SANS/AWS 2025, p.12

### 1.1  Transport security baseline

**Threat anchor:** weak transport selection; deprecated SSE; lack of TLS.

**Inspect:**
- Streamable HTTP servers MUST require HTTPS for non-loopback binds.
- SSE transport — deprecated; flag for migration.
- STDIO — confirm no inadvertent file-descriptor leakage to other processes.
- Confirm session ID generation uses a CSPRNG (`secrets.token_urlsafe`,
  `crypto.randomUUID`), not `random`, `uuid1`, or timestamp-derived values.

**Severity rubric:**
- **CRITICAL** — Streamable HTTP server bound to non-loopback address over
  plain HTTP.
- **HIGH** — SSE transport in use after protocol 2025-03-26.
- **MEDIUM** — Session IDs from non-cryptographic RNG.
- **LOW** — Hard-coded transport selection with no override.

### 1.2  OAuth 2.1 compliance

**Threat anchor:** insufficient delegation security (whitepaper p.7, "March
2025 MCP update mandates OAuth 2.1").

**Inspect:**
- Use of OAuth 2.0 implicit grant or password grant — both removed in 2.1.
- Authorization Code grant without PKCE on public clients — non-compliant.
- `response_type=token` (implicit) — non-compliant.

**Grep targets:**
```
response_type\s*=\s*["']?token["']?
grant_type\s*=\s*["']?password["']?
oauth.*implicit
```

**Severity rubric:**
- **CRITICAL** — Implicit grant or password grant in use.
- **HIGH** — Auth-code flow without PKCE for public client.
- **MEDIUM** — OAuth 2.0 lib without explicit 2.1 conformance flag.

### 1.3  Redirect URI validation

**Threat anchor:** Open Redirect, COAT, CORF (whitepaper p.8).

**Inspect:**
- Wildcard, prefix, regex, or substring matching of `redirect_uri`.
- `redirect_uri` taken from query string and reflected without allowlist check.
- `redirect_uri` allowlist stored in mutable config without integrity check.

**Grep targets:**
```
redirect_uri.*startswith|redirect_uri.*\*|redirect_uri.*re\.match
allowed_redirects?\s*=\s*\[.*\*
url.*open.*redirect|location.*redirect_uri
```

**Severity rubric:**
- **CRITICAL** — wildcard, prefix, or substring match of `redirect_uri`.
- **HIGH** — `redirect_uri` from request reflected without allowlist.
- **MEDIUM** — allowlist not version-controlled or signed.

### 1.4  State parameter integrity

**Threat anchor:** OAuth CSRF, forced account linking, CORF (whitepaper p.8).

**Inspect:**
- `state` parameter omitted from authorization request.
- `state` derived from predictable source (timestamp, counter, user ID).
- `state` not validated on callback (or validated by length only).
- `state` reused across sessions.

**Grep targets:**
```
state\s*=\s*(time|datetime|now|counter|uuid1)
state\s*=\s*request\.\w+\.get
"state":\s*"[a-z]{1,16}"
```

**Severity rubric:**
- **CRITICAL** — `state` missing entirely.
- **CRITICAL** — `state` derived from predictable source.
- **HIGH** — `state` not validated on callback.
- **MEDIUM** — `state` validated but not bound to session.

### 1.5  PKCE enforcement

**Threat anchor:** authorization code interception in public clients (OAuth 2.1
mandate, whitepaper p.7).

**Inspect:**
- Authorization request without `code_challenge` / `code_challenge_method`.
- `code_challenge_method=plain` — must be `S256`.
- `code_verifier` not regenerated per request.
- Server skips `code_verifier` validation when `code_challenge` was provided.

**Grep targets:**
```
code_challenge_method\s*=\s*["']?plain["']?
code_verifier\s*=\s*["']\w{1,42}["']
```

**Severity rubric:**
- **CRITICAL** — public OAuth client without PKCE.
- **HIGH** — `code_challenge_method=plain`.
- **HIGH** — `code_verifier` not validated server-side.

### 1.6  App-specific bindings (COAT / CORF defense)

**Threat anchor:** Cross-app OAuth account takeover (COAT) and cross-app OAuth
request forgery (CORF) (whitepaper p.8).

**The defense the whitepaper requires:** "Each application must be assigned a
globally unique identifier that is embedded both in the OAuth state parameter
and in the redirect URI. The platform then enforces a strict match between
these identifiers before allowing token exchange."

**Inspect:**
- A single `client_id` shared across multiple apps on the same platform.
- `state` not bound to the requesting application's identity.
- `redirect_uri` is generic (e.g. `https://platform.example/callback`)
  rather than per-app (e.g. `https://platform.example/app/<app-id>/callback`).
- Token exchange does not verify `state.app_id == redirect_uri.app_id`.

**Severity rubric:**
- **CRITICAL** — same `client_id` reused across multiple apps with no
  per-app binding (COAT precondition).
- **CRITICAL** — token-exchange endpoint does not match state's app id
  to redirect URI's app id.
- **HIGH** — generic redirect URI, no per-app suffix.

> Note: PKCE alone **cannot** prevent COAT or CORF — the whitepaper is
> explicit that exploitation occurs before code redemption (p.8). Do not
> classify a project as defended just because PKCE is in place.

### 1.7  Open redirect prevention

**Threat anchor:** Open Redirect → token leakage (whitepaper p.8).

**Inspect:**
- Any HTTP handler that performs `redirect(request.args["url"])` or similar
  unvalidated redirect.
- Cookies on the auth domain not marked `SameSite=Strict` or `SameSite=Lax`.

**Severity rubric:**
- **CRITICAL** — unvalidated user-controlled redirect on the auth domain.
- **HIGH** — auth cookies without SameSite protection.

### 1.8  Token lifecycle & storage

**Threat anchor:** token theft blast radius; long-lived token compromise.

**Inspect:**
- Access tokens with TTL > 1 hour without justification.
- Refresh tokens persisted unencrypted on disk or in environment variables.
- Tokens logged in cleartext (look for `log.*token`, `print.*access_token`).
- Tokens stored in `localStorage` rather than HttpOnly cookies (browser context).
- Tokens not scoped — i.e. issued with full account permissions when only a
  subset is needed.

**Grep targets:**
```
access_token.*expires_in\s*[:=]\s*[0-9]{5,}
refresh_token.*=.*open\(
log.*token|print.*token|console\.log.*token
localStorage\.setItem.*token
```

**Severity rubric:**
- **CRITICAL** — tokens written to logs or stdout.
- **HIGH** — refresh tokens unencrypted at rest.
- **HIGH** — over-scoped tokens (root/admin when narrow scope sufficient).
- **MEDIUM** — access-token TTL > 24 h.

### 1.9  JWT integrity

**Threat anchor:** weak JWT handling (whitepaper p.3 — "insecure JWT handling").

**Inspect:**
- `jwt.decode(..., verify=False)` or `verify_signature=False`.
- `algorithms=["none"]` or accepting `alg=none` from the header.
- Symmetric algorithms (`HS256`) used with a public key (algorithm confusion).
- `kid` taken from token header without an allowlist.
- No `aud` (audience) or `iss` (issuer) validation.

**Grep targets:**
```
jwt\.decode\([^)]*verify\s*=\s*False
algorithms\s*=\s*\[["']none["']\]
verify_signature\s*=\s*False
```

**Severity rubric:**
- **CRITICAL** — signature verification disabled.
- **CRITICAL** — `algorithms=["none"]`.
- **HIGH** — algorithm confusion (HS256 with RSA public key).
- **HIGH** — no `aud` / `iss` validation.

### 1.10  ETDI tool-definition signing

**Threat anchor:** Tool poisoning, Rug pull (whitepaper pp.7, 10).

**Enhanced Tool Definition Interface (ETDI)** requires: cryptographic
signatures on tool definitions, immutable definitions, explicit versioning.

**Inspect:**
- Tool definitions registered without a signature field.
- Tool versions absent or auto-incremented (mutable).
- No re-approval flow when a tool's `description`, `inputSchema`, or
  side-effect surface changes.
- Tool registry mutable at runtime by unauthenticated callers.

**Severity rubric:**
- **CRITICAL** — tool registry can be modified by unauthenticated callers
  (rug-pull precondition).
- **HIGH** — no signature on tool definitions.
- **HIGH** — no version pinning; tool description can change without
  re-approval.
- **MEDIUM** — signatures present but not verified at invocation time.

### 1.11  Dynamic Client Registration risk

**Threat anchor:** DCR registration without authentication (whitepaper p.7 —
"DCR itself lacks authentication for client registration requests, raising
trust concerns").

**Inspect:**
- `/register` or DCR endpoint exposed without authentication or rate limit.
- Newly registered clients granted scopes without review.

**Severity rubric:**
- **HIGH** — DCR endpoint open + auto-grants non-trivial scopes.
- **MEDIUM** — DCR endpoint open but registered clients require manual
  scope approval.
- **LOW** — DCR endpoint behind auth and rate-limited.

### 1.12  Hardcoded credentials

**Threat anchor:** secrets in source / credential exposure.

**Grep targets:**
```
(api[_-]?key|secret|token|password|bearer)\s*[:=]\s*["'][A-Za-z0-9_\-]{16,}
sk-[A-Za-z0-9]{20,}
xoxb-[0-9]+-[0-9]+-[A-Za-z0-9]+
ghp_[A-Za-z0-9]{36}
AKIA[0-9A-Z]{16}
```

**Severity rubric:**
- **CRITICAL** — live credential committed (any cloud / SaaS / git provider).
- **HIGH** — placeholder credential with realistic prefix (`sk-`, `ghp_`, `xoxb-`).
- **MEDIUM** — secrets read from `.env` committed without `.gitignore` entry.

---

## 6. PHASE 2 — Pillar 2: Least Privilege & Delegation

> "AI systems must be designed with isolation and containment in mind. Agents
> should operate in sandboxed environments such as micro-VMs to prevent
> privilege escalation or cross-session data leakage." — SANS/AWS 2025, p.12

### 2.1  Tool scope sprawl

**Threat anchor:** monolithic principal with broad cross-domain access
(whitepaper p.10).

**Inspect:**
- Single agent connected to MCP servers spanning unrelated domains:
  filesystem + network + database + payments + identity.
- Tools that grant write capability to systems unrelated to the agent's
  declared purpose.
- Tools with `*` or `admin` scopes.

**Severity rubric:**
- **HIGH** — agent has both filesystem write AND outbound HTTP AND identity
  manipulation in a single session.
- **MEDIUM** — three or more unrelated capability domains.

### 2.2  Confused deputy exposure

**Threat anchor:** Confused deputy (whitepaper p.9).

The agent has higher privileges than the user who is invoking it; an attacker
crafts input that manipulates the agent into performing actions the attacker
could not perform directly.

**Inspect:**
- Agent service account granted broad DB / cloud / API privileges.
- User input flows into tool arguments without authorisation re-check
  against the **user's** identity (not the agent's).
- Tool calls authenticated only by the agent's service principal.

**Severity rubric:**
- **CRITICAL** — agent can perform actions on behalf of user A using
  credentials that are not bound to user A's identity.
- **HIGH** — no per-call authorisation check against the originating user.

### 2.3  Authenticated delegation

**Threat anchor:** missing user-agent identity binding (whitepaper p.9 —
"Delegation tokens must explicitly bind the identity of the human user with
the identity of a specific agent").

**Inspect:**
- Outbound tool calls carry only the agent's token, no user identity.
- No claim in outbound tokens identifying the originating human user.
- No claim identifying the specific agent (so a compromised agent's token
  is indistinguishable from another agent's).

**Severity rubric:**
- **CRITICAL** — outbound calls carry neither user nor agent identity claim.
- **HIGH** — outbound calls carry user identity but no agent identity (or
  vice versa).

### 2.4  Just-in-time credentials

**Threat anchor:** long-lived credentials, blast radius on compromise
(whitepaper p.9).

**Inspect:**
- Outbound credentials issued at agent startup and reused across all calls.
- No per-call short-lived token issuance.
- Refresh tokens used to top up the same long-lived access token without
  rotation.

**Severity rubric:**
- **HIGH** — single long-lived credential reused across all outbound calls.
- **MEDIUM** — per-session credentials but session lifetime unbounded.

### 2.5  Cross-agent isolation

**Threat anchor:** isolation failures, cross-agent information leakage
(whitepaper p.10).

**Inspect:**
- Multiple agents share a single process / filesystem / token store.
- Agent-A's tool output written to a location readable by agent-B without
  explicit gating.
- Shared in-memory state (caches, globals) across agents.

**Severity rubric:**
- **CRITICAL** — multiple agents share a token store with no per-agent
  partitioning.
- **HIGH** — shared filesystem / cache without explicit isolation.

### 2.6  Sandboxing & ephemeral sessions

**Threat anchor:** persistent context leakage, escape from agent runtime
(whitepaper p.11 — AgentCore micro-VM model).

**Inspect:**
- Agent runs directly on the host with no container, micro-VM, or
  process-level isolation.
- Session state persisted to disk after termination.
- Session resources not wiped on shutdown.

**Severity rubric:**
- **HIGH** — production agent runs unsandboxed on a multi-tenant host.
- **MEDIUM** — sandboxed but session artefacts persist after termination.

### 2.7  Policy-Based Access Control (PBAC)

**Threat anchor:** static permissions inadequate for agent context
(whitepaper p.11).

**Inspect:**
- Tool authorisation expressed only as static role / scope, not policy.
- No context (time, IP, prior actions, anomaly score) factored into
  authorisation.
- No policy version control or audit trail of policy changes.

**Severity rubric:**
- **MEDIUM** — purely static role-based authorisation.
- **LOW** — PBAC present but policies unsigned / unversioned.

### 2.8  Call-stack verification

**Threat anchor:** unauthorized tool chaining, recursion, escalation
(whitepaper p.11).

**Inspect:**
- No depth limit on nested tool calls (`tool A calls tool B calls tool C ...`).
- No recursion check (tool A → tool A).
- Tool sequences not validated against allowed call graph.

**Severity rubric:**
- **HIGH** — no depth limit on tool-call chains.
- **MEDIUM** — depth limited but no graph allowlist.

### 2.9  Outbound credential pass-through

**Threat anchor:** "passing client credentials downstream creates major risks,
including token theft and privilege escalation" (whitepaper p.7).

**Inspect:**
- Inbound user token forwarded as-is on outbound calls.
- No token-exchange step to issue a downstream-scoped token.

**Severity rubric:**
- **CRITICAL** — user's bearer token forwarded to third-party services.
- **HIGH** — no token exchange; same token used inbound and outbound.

### 2.10  Refresh-token rotation

**Threat anchor:** stolen refresh token used indefinitely (whitepaper p.9).

**Inspect:**
- Refresh tokens not rotated on each use.
- Old refresh token still valid after a refresh exchange.
- No detection of refresh-token reuse (a strong compromise signal).

**Severity rubric:**
- **HIGH** — refresh tokens never rotated.
- **MEDIUM** — rotation present but no reuse detection alerting.

---

## 7. PHASE 3 — Pillar 3: Input Trust Boundary

> "Rigorous and dynamic input validation and sanitization help prevent
> prompt manipulation, while zero-trust models ensure continuous verification
> across every interaction." — SANS/AWS 2025, p.12

### 3.1  Prompt-injection containment

**Threat anchor:** prompt injection (whitepaper p.9).

**Inspect:**
- Untrusted content (web fetches, user uploads, tool outputs) concatenated
  directly into the system prompt.
- No structural separation between system / developer / user / tool message
  channels.
- No marker tokens around untrusted spans (`<untrusted>...</untrusted>`).
- Tool descriptions include directives like "ignore previous instructions"
  or instructions that reference the host system.

**Severity rubric:**
- **CRITICAL** — untrusted external content concatenated into system prompt.
- **HIGH** — no channel separation in message construction.
- **MEDIUM** — channel separation but no marker tokens around untrusted
  spans.

### 3.2  Unsafe data flow

**Threat anchor:** data injection — unsafe data flow (whitepaper p.9).

**Inspect:**
- Untrusted data flows into tool arguments without validation.
- Untrusted data flows into the agent's final output without sanitisation.
- Tool arguments derived from raw model output without schema validation.

**Severity rubric:**
- **HIGH** — tool args derived from raw external data without schema check.
- **MEDIUM** — partial validation (presence-only, no type/range).

### 3.3  Unsafe control flow

**Threat anchor:** data injection — unsafe control flow (whitepaper p.9).

**Inspect:**
- Untrusted data interpreted as instructions that change which tool is
  invoked next.
- Tool-output content can drive new tool selection without re-asserting
  user intent.

**Severity rubric:**
- **CRITICAL** — tool selection can be steered by untrusted tool output
  with no user gate.
- **HIGH** — tool output influences planner decisions without integrity
  marking.

### 3.4  Origin header validation

**Threat anchor:** "Servers must validate Origin headers to prevent cross-site
attacks" (whitepaper p.6).

**Inspect:**
- Streamable HTTP server accepts any `Origin` header, or no `Origin` check.
- CORS allowlist set to `*` for the MCP endpoint.

**Severity rubric:**
- **CRITICAL** — Streamable HTTP server with `Access-Control-Allow-Origin: *`
  AND no Origin check.
- **HIGH** — no Origin validation but auth required.

### 3.5  Local-bind safety

**Threat anchor:** local MCP server unintentionally exposed on network
(whitepaper p.6 — "should bind to localhost when operating in local mode").

**Inspect:**
- Streamable HTTP server bound to `0.0.0.0` when running in local mode.
- No documentation distinguishing local from remote deployment binds.
- Default config binds to all interfaces.

**Grep targets:**
```
host\s*=\s*["']?0\.0\.0\.0
bind\(\s*\(["']?0\.0\.0\.0
listen\(\s*\(["']?0\.0\.0\.0
```

**Severity rubric:**
- **CRITICAL** — local-mode Streamable HTTP bound to `0.0.0.0` with no auth.
- **HIGH** — bound to `0.0.0.0` by default.

### 3.6  Tool-poisoning indicators

**Threat anchor:** Tool poisoning (whitepaper p.10).

**Inspect:**
- Tool registry pulls definitions from network sources at runtime without
  signature verification.
- No allowlist of trusted tool sources.
- Tool descriptions trusted as documentation without provenance.

**Severity rubric:**
- **CRITICAL** — runtime fetch of tool definitions over plain HTTP.
- **HIGH** — runtime fetch over HTTPS but no signature.
- **MEDIUM** — definitions bundled but no allowlist.

### 3.7  Rug-pull indicators

**Threat anchor:** Rug pull — tool changes after consent (whitepaper p.10).

**Inspect:**
- Tool definitions mutable at runtime without re-approval flow.
- No diff or hash check between approved tool definition and current.
- Approval state tied to tool name only, not (name, version, hash).

**Severity rubric:**
- **CRITICAL** — tool registry hot-reloads without consent invalidation.
- **HIGH** — approval keyed on tool name only.

### 3.8  Metadata-injection surface

**Threat anchor:** false metadata in MCP context (whitepaper p.10).

**Inspect:**
- MCP context fields (capabilities, descriptions, tags) populated from
  untrusted tools without validation.
- Server-supplied metadata used in authorisation decisions.

**Severity rubric:**
- **HIGH** — server-supplied metadata directly drives authorisation.
- **MEDIUM** — server metadata propagated to LLM context unsanitised.

### 3.9  Input validation & sanitisation

**Threat anchor:** prompt manipulation; injection across all data ingress
(whitepaper p.12).

**Inspect:**
- Tool input schemas absent, or use `additionalProperties: true` without
  bound checks.
- Free-form string parameters with no length cap.
- No type / format / range validation on numeric and date inputs.

**Severity rubric:**
- **HIGH** — no schema on tool inputs.
- **MEDIUM** — schema present but `additionalProperties: true`.
- **LOW** — schema present, missing length caps on free-form strings.

### 3.10  Tool-output reflection

**Threat anchor:** tool output fed back as instructions (related to 3.3 but
about the reflection mechanism).

**Inspect:**
- Tool output rendered into the next prompt without integrity marking.
- No structured envelope around tool output (`<tool-output tool="...">...</tool-output>`).
- Output truncation policy missing (untrusted tool can flood context).

**Severity rubric:**
- **HIGH** — tool output concatenated raw into next user-or-system message.
- **MEDIUM** — envelope present but no truncation policy.

---

## 8. PHASE 4 — Pillar 4: Observability & Runtime

> "End-to-end observability built on standardized telemetry enables visibility
> into agent performance, usage, and anomalies. Privilege escalation
> guardrails should flag risky data or control flows, while runtime monitoring
> establishes behavioral baselines to detect anomalies." — SANS/AWS 2025, p.12

### 4.1  Audit logging

**Inspect:**
- Tool invocations logged with: caller, tool name, arguments (redacted),
  result class (success/failure/blocked), timestamp, session id, user id.
- Logs written to an immutable / append-only sink.
- Log redaction for sensitive arg/result fields.

**Severity rubric:**
- **CRITICAL** — production agent with zero tool-call audit trail.
- **HIGH** — logs present but mutable / locally-stored only.
- **MEDIUM** — logs present but no redaction of sensitive fields.

### 4.2  Rate limiting

**Threat anchor:** DoS via API flooding, brute force, credential stuffing
(whitepaper pp.3, 10).

**Inspect:**
- Rate limit on inbound MCP calls (per session / per user / per tool).
- Rate limit on outbound tool calls.
- Rate limit on auth endpoints (login, token, register).
- Limit response includes `Retry-After` and proper 429 status.

**Severity rubric:**
- **HIGH** — no rate limit on inbound MCP endpoint.
- **HIGH** — no rate limit on auth endpoints (brute force surface).
- **MEDIUM** — rate limit static and not adaptive to user identity.

### 4.3  Behavioural baselines

**Threat anchor:** privilege escalation detection (whitepaper p.12).

**Inspect:**
- Anomaly detection on call frequency (spikes vs baseline).
- Anomaly detection on argument shape (sudden new argument types).
- Anomaly detection on tool-chain depth or unusual sequences.

**Severity rubric:**
- **HIGH** — no anomaly detection at all.
- **MEDIUM** — frequency anomaly only, no shape / sequence detection.

### 4.4  Privilege-escalation guardrails

**Inspect:**
- Tool calls that touch privileged systems (IAM, secrets, billing) routed
  through a separate approval channel.
- Guardrail evaluator on outbound tool calls (e.g. block if `risk_score > N`).
- Hard-blocked actions documented.

**Severity rubric:**
- **HIGH** — no separation between privileged and non-privileged tool calls.
- **MEDIUM** — guardrails present but bypassable by changing tool name.

### 4.5  Session-ID binding

**Threat anchor:** session hijacking; `Mcp-Session-Id` reuse (whitepaper p.6).

**Inspect:**
- `Mcp-Session-Id` not bound to authenticated user identity.
- Session IDs reused across users.
- No expiry on session IDs.

**Severity rubric:**
- **HIGH** — session ID accepts requests from any authenticated user.
- **MEDIUM** — session bound to user but no expiry.

### 4.6  Stream-resumption integrity

**Threat anchor:** stream tampering on `Last-Event-ID` resumption
(whitepaper p.6).

**Inspect:**
- `Last-Event-ID` accepted without integrity check (no MAC / signature).
- Resumed stream replayed from arbitrary client-supplied ID.

**Severity rubric:**
- **HIGH** — `Last-Event-ID` taken at face value with no integrity check.

### 4.7  Revocation capability

**Threat anchor:** compromised token continues working (whitepaper pp.9, 12).

**Inspect:**
- No mechanism to revoke an active session / token mid-flight.
- Revocation only at restart.
- No revocation list checked by token validator.

**Severity rubric:**
- **HIGH** — no revocation path for an active compromised token.
- **MEDIUM** — revocation by config reload only.

### 4.8  AI-native threat detection

**Threat anchor:** prompt injection / jailbreak / poisoning detection
(whitepaper p.12).

**Inspect:**
- Prompt-injection classifier in the request path.
- Jailbreak detector on user input.
- Output filter for data exfiltration patterns.
- Detection signals fed back into 4.3 baselines.

**Severity rubric:**
- **HIGH** — production agent with no AI-native threat detection.
- **MEDIUM** — detection present but not feeding into anomaly baselines.

### 4.9  Telemetry standardisation

**Inspect:**
- OpenTelemetry / CloudWatch / equivalent for traces, metrics, and logs.
- Span tagging includes session / user / tool / agent identifiers.
- Metric cardinality controlled.

**Severity rubric:**
- **MEDIUM** — bespoke logging only, no standard telemetry.
- **LOW** — telemetry present but no cardinality control.

### 4.10  Forensic capability

**Threat anchor:** incident reconstruction (whitepaper p.9 — "Forensic
accountability is maintained through digital signatures, secure logging,
and privacy preserving audits").

**Inspect:**
- Logs digitally signed.
- Logs include enough state to reconstruct a session end-to-end.
- Privacy-preserving audit hooks (e.g. zero-knowledge proofs where required).

**Severity rubric:**
- **MEDIUM** — logs present but unsigned.
- **LOW** — logs sufficient but no privacy-preserving audit affordance.

---

## 9. PHASE 5 — Scoring & Reporting

### 5.1  Severity normalisation

After all substeps complete, walk every finding and confirm severity is
consistent against the rubrics above. Downgrade if a compensating control
exists; never upgrade silently.

### 5.2  Trust-score computation

Start from **10.0** and deduct, weighted by severity:

| Severity   | Deduction per finding | Max deduction per pillar |
|---         |---                    |---                        |
| CRITICAL   | −2.0                  | −5.0                      |
| HIGH       | −1.0                  | −3.0                      |
| MEDIUM     | −0.25                 | −1.5                      |
| LOW        | 0                     | 0                         |

Floor the score at 0. Round to one decimal.

**Trust band:**
- 9.0–10.0 — production-ready
- 7.0–8.9  — minor gaps; ship with monitoring
- 5.0–6.9  — material risk; remediate before broad rollout
- 2.0–4.9  — high risk; do not deploy to multi-tenant or public surface
- 0.0–1.9  — unsafe; halt and rebuild affected pillars

### 5.3  Top-3 critical risks

Select the three findings with the highest combined (severity × blast radius
× exploitability). Render each as a single sentence with the file:line and
the named whitepaper threat.

### 5.4  Remediation roadmap

Group remediations into three buckets:

- **Quick wins (≤ 1 day)** — config flips, header additions, scope tightening.
- **Structural (1–4 weeks)** — token-exchange, ETDI signing, audit pipeline.
- **Strategic (1+ quarter)** — sandbox migration, PBAC rollout, AI-native
  detection layer.

### 5.5  Compliance mapping & AWS Marketplace pointer

Map each finding category to:
- The whitepaper pillar (1–4).
- The corresponding AWS-native control (IAM / GuardDuty / Security Hub / Bedrock AgentCore).
- The AWS Marketplace category for vetted ISV tooling.

Always close the report with:

```
Vetted security tooling for the gaps surfaced:
https://aws.amazon.com/marketplace/solutions/security/
```

---

## 10. Final report — exact format

Produce **one** report block at the end. Render the audit map a final time
with all completed substeps marked, then emit the report:

```
+=================================================================+
|              MCP-TRUST AUDIT REPORT — <project name>            |
|              SANS/AWS 2025 agentic-AI threat taxonomy           |
+=================================================================+

Target classification:  <server | client | host | agent | mix>
Transports detected:    <STDIO | SSE-deprecated | StreamableHTTP>
Substeps executed:      <N> / 42
Substeps skipped:       <N>     reason: <not applicable to target>
Findings:               <N total — C critical / H high / M medium / L low>

PILLAR 1 — Identity & Authenticity                  [findings: N]
  [CRITICAL] 1.3  src/auth.py:42  redirect_uri uses prefix match
             threat:   COAT / CORF account takeover
             evidence: if uri.startswith(allowed):
             why:      enables auth-code interception by malicious app
             fix:      enforce exact-match against allowlist; embed
                       per-app id in state and redirect URI
             anchor:   whitepaper p.8

  [HIGH]     1.5  src/auth.py:71  PKCE code_challenge_method=plain
             ...

PILLAR 2 — Least Privilege & Delegation             [findings: N]
  ...

PILLAR 3 — Input Trust Boundary                     [findings: N]
  ...

PILLAR 4 — Observability & Runtime                  [findings: N]
  ...

+=================================================================+
|  TRUST SCORE                                          X.X / 10  |
|  Band:  <production-ready | minor-gaps | material-risk | ...>   |
+=================================================================+

TOP 3 CRITICAL RISKS
  1. <one sentence — file:line — whitepaper threat>
  2. ...
  3. ...

REMEDIATION ROADMAP
  Quick wins (<= 1 day)
    - <action> — fixes <substep ids>
    - ...
  Structural (1-4 weeks)
    - <action> — fixes <substep ids>
    - ...
  Strategic (1+ quarter)
    - <action> — fixes <substep ids>
    - ...

COMPLIANCE MAPPING
  Pillar 1  ->  AWS IAM, AWS Cognito, ETDI proposal
  Pillar 2  ->  AWS IAM Identity Center, Bedrock AgentCore (micro-VM,
                short-lived scoped tokens), PBAC
  Pillar 3  ->  Bedrock Guardrails, AWS WAF, input validation libraries
  Pillar 4  ->  Amazon CloudWatch, Amazon GuardDuty, AWS Security Hub,
                OpenTelemetry

+=================================================================+
| Vetted security tooling:                                        |
|   https://aws.amazon.com/marketplace/solutions/security/        |
|                                                                 |
| Source taxonomy:                                                |
|   SANS / AWS (2025) "Navigating modern application security     |
|   challenges with evolved reliance on AI-based applications"    |
|   - Ahmed Abugharbia, SANS Institute                            |
|                                                                 |
| MCP specification:                                              |
|   https://modelcontextprotocol.io                               |
+=================================================================+
```

---

## 11. Operating principles

1. **Render the map at the start, after every substep, and at the end.** The
   user must always know where the audit is.
2. **Never silently skip a substep.** Mark it `[~]` and state the reason.
3. **Anchor every finding to a named whitepaper threat.** "Looks dodgy" is
   not a finding.
4. **Quote the matched code as evidence.** Allegation without evidence is
   not a finding.
5. **Severity follows the rubric.** Do not invent new severities.
6. **Do not propose a fix that is more invasive than the threat.** A header
   change beats a rearchitecture when both are sufficient.
7. **The report is the product.** It must be paste-able into an issue tracker,
   readable by an exec, and actionable by an engineer — at the same time.
