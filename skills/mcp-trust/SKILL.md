---
name: mcp-trust
description: Commercial-grade security audit playbook for MCP (Model Context Protocol) servers, AI agents, and agentic OAuth flows. Walks 48 substeps across five pillars from the SANS/AWS 2025 whitepaper "Navigating modern application security challenges with evolved reliance on AI-based applications" plus a Supply Chain & Dependency layer — Identity & Authenticity, Least Privilege & Delegation, Input Trust Boundary, Observability & Runtime, and Supply Chain & Dependency Security. Auto-triggers on imports of `mcp`, `FastMCP`, `@modelcontextprotocol/sdk`; on `@mcp.tool` / `@mcp.resource` / `@mcp.prompt` handlers; on agentic OAuth artifacts (`redirect_uri`, `state=`, `code_verifier`, PKCE, `Mcp-Session-Id`); on multi-agent orchestration code (LangGraph, CrewAI, Strands, AutoGen); on Streamable HTTP / SSE transport implementations; and on the presence of dependency manifests (`package.json`, `requirements.txt`, `pyproject.toml`, `Cargo.toml`, `go.mod`). Renders an architectural flowchart at start and end and a live substep tracker that ticks after every substep, then produces a severity-rated finding list, a 0–10 trust score, top-3 critical risks, a remediation roadmap, AWS-control compliance mapping, live CVE/advisory cross-reference, and jurisdictional supply-chain risk screening anchored to OFAC/EU/UN/BIS sanctions frameworks. Invoke explicitly with `/mcp-trust`.
---

# MCP-TRUST — Agentic AI Security Audit

A structured security review of MCP servers, AI agents, and agentic OAuth flows
against the threat taxonomy from the SANS / AWS 2025 whitepaper *"Navigating
modern application security challenges with evolved reliance on AI-based
applications"* (Ahmed Abugharbia, SANS Institute), extended with a supply-chain
and jurisdictional-risk layer that the whitepaper notes but does not codify
into substeps.

This skill is **not** a scanner. It is a senior-engineer-grade playbook loaded
into Claude's context. Claude executes the audit using its built-in `Read`,
`Grep`, and `WebFetch` tools — no external process, no credentials handled.

The audit covers **48 substeps across 5 pillars**, plus a discovery phase
and a scoring/reporting phase. Every finding is anchored to a named threat
from the whitepaper or to a concrete external advisory / sanctions source.

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
- Dependency manifests: `package.json`, `package-lock.json`, `yarn.lock`,
  `pnpm-lock.yaml`, `requirements.txt`, `Pipfile.lock`, `pyproject.toml`,
  `poetry.lock`, `Cargo.toml`, `go.mod`, `Gemfile.lock`, `pom.xml`

**Manual invocation:** `/mcp-trust`. Optionally pass a path to scope the audit
(e.g. `/mcp-trust src/server`).

---

## 2. The audit map

The audit map has two views. The **architectural flowchart** is rendered
once at the start and once at the end — it shows the audit pipeline as a
connected graph. The **detailed substep tracker** is rendered at the start
and re-rendered after every substep so the user always knows where the
audit is.

### 2.1 Architectural flowchart (render at start and end)

```
+======================================================================+
|                       MCP-TRUST AUDIT PIPELINE                       |
|         SANS / AWS 2025  ·  4-Pillar Model  +  Supply Chain          |
+======================================================================+

                     [ codebase  +  package manifests ]
                                     │
                                     ▼
                       ┌────────────────────────┐
                       │  PHASE 0 · DISCOVERY   │
                       │  classify | scope | map│
                       └────────────┬───────────┘
                                    │
                          target  +  transport
                          +  auth surface  +  inventory
                                    │
        ┌───────────────────────────┼───────────────────────────┐
        ▼                           ▼                           ▼
 ┌─────────────┐             ┌─────────────┐             ┌─────────────┐
 │  PHASE 1    │             │  PHASE 2    │             │  PHASE 3    │
 │  IDENTITY   │             │  PRIVILEGE  │             │   INPUT     │
 │     &       │             │      &      │             │   TRUST     │
 │ AUTHENTIC.  │             │ DELEGATION  │             │  BOUNDARY   │
 │             │             │             │             │             │
 │  12 steps   │             │  10 steps   │             │  10 steps   │
 │             │             │             │             │             │
 │ OAuth · JWT │             │  Confused   │             │  Prompt &   │
 │  ETDI       │             │   deputy    │             │   data      │
 │  COAT/CORF  │             │  JIT · PBAC │             │  injection  │
 │  secrets    │             │  isolation  │             │  origin     │
 └──────┬──────┘             └──────┬──────┘             └──────┬──────┘
        │                           │                           │
        └───────────────────────────┼───────────────────────────┘
                                    │
                       identity / privilege / input
                       findings stream
                                    │
                       ┌────────────┴────────────┐
                       ▼                         ▼
                ┌─────────────┐           ┌─────────────┐
                │  PHASE 4    │           │  PHASE 5    │
                │  OBSERVE    │           │   SUPPLY    │
                │     &       │           │   CHAIN     │
                │  RUNTIME    │           │     &       │
                │             │           │ DEPENDENCY  │
                │ 10 steps    │           │  6 steps    │
                │             │           │             │
                │ Logs · rate │           │  Live CVE   │
                │ limit       │           │  feeds      │
                │ anomaly     │           │ Jurisdic-   │
                │ revoke      │           │   tion      │
                └──────┬──────┘           └──────┬──────┘
                       │                         │
                       └────────────┬────────────┘
                                    │
                          all findings + severity
                                    │
                                    ▼
                       ┌────────────────────────┐
                       │  PHASE 6 · SCORE &     │
                       │           REPORT       │
                       │  trust score · top-3   │
                       │  roadmap · compliance  │
                       └────────────┬───────────┘
                                    │
                                    ▼
                       [ commercial-grade audit report ]
```

### 2.2 Detailed substep tracker (re-render after every substep)

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
|  PHASE 5 — PILLAR 5: SUPPLY CHAIN & DEPENDENCY SECURITY         |
|  [ ] 5.1  Dependency manifest inventory                         |
|  [ ] 5.2  Known-vulnerability cross-reference (live advisories) |
|  [ ] 5.3  Maintainer jurisdiction & sanctions screening         |
|  [ ] 5.4  Typosquatting & namespace confusion                   |
|  [ ] 5.5  Integrity & provenance                                |
|  [ ] 5.6  Maintenance health                                    |
|                                                                 |
|  PHASE 6 — SCORING & REPORTING                                  |
|  [ ] 6.1  Severity normalisation                                |
|  [ ] 6.2  Trust-score computation                               |
|  [ ] 6.3  Top-3 critical risks                                  |
|  [ ] 6.4  Remediation roadmap                                   |
|  [ ] 6.5  Compliance mapping & AWS Marketplace pointer          |
|                                                                 |
+=================================================================+
```

### 2.3 Progress markers

| Marker | Meaning |
|---|---|
| `[ ]` | Pending — not yet reached |
| `[>]` | **In progress — currently inspecting** |
| `[x]` | Complete — clean (no findings) |
| `[!]` | Complete — findings recorded |
| `[~]` | Skipped — not applicable to this target |

After **every** substep, re-render the detailed substep tracker (section 2.2)
with the latest markers, then print a one-line summary of the substep result
before moving on:

```
>>> Substep 1.3 complete — Redirect URI validation
    Result: 2 findings (1 CRITICAL, 1 HIGH)
    Next:   1.4 State parameter integrity
```

The architectural flowchart (section 2.1) is rendered **only** at audit start
and at audit end, with an "audit complete" annotation on the closing render.

---

## 3. Procedure

For every substep:

1. State the substep ID and name out loud.
2. List the **threat anchor(s)** from the whitepaper or external source.
3. Run the listed Grep / Read / WebFetch targets.
4. For each match, classify against the **severity rubric** below.
5. Emit findings in the standard finding-record format.
6. Re-render the substep tracker with the substep marked.

### Finding record format

Every finding is recorded as a structured block:

```
[<SEVERITY>] <pillar.substep>  <file>:<line>
  threat:    <named threat from whitepaper or external source>
  evidence:  <the matched code / config / dep, ≤ 120 chars>
  why:       <one sentence — the concrete attack this enables>
  fix:       <one sentence — actionable remediation>
  anchor:    <whitepaper section reference or external URL>
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

## 9. PHASE 5 — Pillar 5: Supply Chain & Dependency Security

> Beyond the four core whitepaper pillars, every modern AI agent and MCP
> server depends on dozens to hundreds of third-party packages. A compromise
> of a single dependency, or a maintainer operating in a sanctioned or
> high-risk jurisdiction, can defeat every other control in this audit.
> This pillar inspects the **dependency surface itself** — not the code
> that uses it.

> **Scope note:** the SANS/AWS 2025 whitepaper acknowledges supply-chain
> attacks (tool poisoning, rug pulls — pillar 1 / pillar 3 here) but does
> not codify a dependency-layer audit. Pillar 5 extends the framework with
> industry-standard supply-chain practices anchored to NIST SP 800-161,
> US Executive Order 14028 (Improving the Nation's Cybersecurity), and
> the OFAC/EU/UN sanctions frameworks.

### 5.1  Dependency manifest inventory

Collect every manifest the project ships:

| Ecosystem | Manifests |
|---|---|
| npm / yarn / pnpm | `package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml` |
| Python | `requirements.txt`, `requirements-*.txt`, `Pipfile`, `Pipfile.lock`, `pyproject.toml`, `poetry.lock`, `setup.py`, `setup.cfg` |
| Rust | `Cargo.toml`, `Cargo.lock` |
| Go | `go.mod`, `go.sum` |
| Ruby | `Gemfile`, `Gemfile.lock` |
| Java / Kotlin | `pom.xml`, `build.gradle`, `build.gradle.kts`, `settings.gradle` |
| .NET | `*.csproj`, `packages.lock.json` |
| Containers | `Dockerfile`, `docker-compose.yml` (extract base images) |

For each manifest record: ecosystem, direct deps count, transitive deps
count, total unique packages, manifest version-pinning style
(pinned / range / floating).

**Inspect:**
- Range-only constraints (`^1.0.0`, `~2.3`, `>=1.0`) in production
  lockfiles — reproducibility risk.
- Untracked lockfiles (manifest present, lockfile absent).
- Mixed registries (e.g. an npm dep pointing at a private mirror with no
  fallback documented).
- Direct deps using `git+` or HTTP URLs rather than registry references.

**Severity rubric:**
- **HIGH** — production manifest with floating versions and no lockfile.
- **MEDIUM** — manifest references private registry with no documented
  fallback.
- **LOW** — manifest pins versions but no integrity hashes.

### 5.2  Known-vulnerability cross-reference (live advisory feeds)

**Always fetch current advisory data at audit time** — do not rely on
training-time knowledge. Vulnerability disclosures are continuous; a clean
audit yesterday may be insecure today. Query a representative source from
each tier below; do not stop at one source.

**Tier A — Canonical / authoritative CVE databases** (always query):

| Source | URL | Coverage |
|---|---|---|
| **NVD (NIST National Vulnerability Database)** | https://nvd.nist.gov | Canonical CVE detail records, CVSS scores, CWE mappings. Per-CVE: `https://nvd.nist.gov/vuln/detail/<CVE-ID>` |
| **MITRE CVE Program** | https://cve.mitre.org | Canonical CVE issuance. Per-CVE: `https://cve.mitre.org/cgi-bin/cvename.cgi?name=<CVE-ID>` |
| **GitHub Advisory Database** | https://github.com/advisories | GitHub-curated, ecosystem-tagged. Per-package: `https://github.com/advisories?query=<pkg>` |
| **OSV.dev** | https://osv.dev | Cross-ecosystem unified DB. API: `https://api.osv.dev/v1/query` |

**Tier B — Active-exploitation signals** (always query — these flag CVEs
that move from "theoretical" to "weaponised"):

| Source | URL | Coverage |
|---|---|---|
| **CISA Known Exploited Vulnerabilities (KEV)** | https://www.cisa.gov/known-exploited-vulnerabilities-catalog | CVEs confirmed exploited in the wild — auto-CRITICAL if a dep is affected |
| **Exploit Database** | https://www.exploit-db.com | Public PoC / exploit code; per-CVE search shows weaponisation maturity |
| **CERT/CC Vulnerability Notes** | https://kb.cert.org/vuls | Coordinated-disclosure analysis with vendor responses |
| **Full Disclosure Mailing List** | https://seclists.org/fulldisclosure | Earliest signal for some 0-days; useful for emerging-threat awareness |

**Tier C — Aggregators / continuous monitoring** (cross-reference and
free alerting):

| Source | URL | Coverage |
|---|---|---|
| **CVEdetails** | https://www.cvedetails.com | Vendor / product-pivoted CVE search and statistics |
| **OpenCVE** | https://www.opencve.io | Free CVE alerting & monitoring (subscribe per vendor / CWE) |
| **Snyk Vulnerability Database** | https://security.snyk.io | Cross-ecosystem with proprietary research; strong for open-source |
| **Vulhub** | https://vulhub.org | Pre-built vulnerable environments — confirm exploitability of a finding without standing it up from scratch |

**Tier D — Ecosystem-specific advisory DBs** (query the matching tier
for each manifest detected in 5.1):

| Ecosystem | Source | URL |
|---|---|---|
| Python | PyPA Advisory Database | https://github.com/pypa/advisory-database |
| npm | npm Security Advisories | https://www.npmjs.com/advisories |
| Rust | RustSec Advisory Database | https://rustsec.org/advisories |
| Ruby | Ruby Advisory DB | https://github.com/rubysec/ruby-advisory-db |
| Go | Go Vulnerability DB | https://pkg.go.dev/vuln |

**Tier E — Bug-bounty public-disclosure feeds** (catch issues that have
been responsibly disclosed but are not yet CVE-assigned):

| Source | URL |
|---|---|
| HackerOne Hacktivity | https://www.hackerone.com/hacktivity |
| Bugcrowd Disclosures | https://www.bugcrowd.com |

**Tier F — Emerging-threat news** (situational awareness for items not
yet in CVE feeds):

| Source | URL |
|---|---|
| The Hacker News | https://thehackernews.com |

**Per-package security-advisories pages** for high-profile packages
(query when the dependency is on this list):

```
axios            https://github.com/axios/axios/security/advisories
express          https://github.com/expressjs/express/security/advisories
fastify          https://github.com/fastify/fastify/security/advisories
django           https://github.com/django/django/security/advisories
flask            https://github.com/pallets/flask/security/advisories
requests         https://github.com/psf/requests/security/advisories
urllib3          https://github.com/urllib3/urllib3/security/advisories
cryptography     https://github.com/pyca/cryptography/security/advisories
pyjwt            https://github.com/jpadilla/pyjwt/security/advisories
node-fetch       https://github.com/node-fetch/node-fetch/security/advisories
ws               https://github.com/websockets/ws/security/advisories
jsonwebtoken     https://github.com/auth0/node-jsonwebtoken/security/advisories
passport         https://github.com/jaredhanson/passport/security/advisories
mongoose         https://github.com/Automattic/mongoose/security/advisories
sequelize        https://github.com/sequelize/sequelize/security/advisories
sqlalchemy       https://github.com/sqlalchemy/sqlalchemy/security/advisories
fastapi          https://github.com/tiangolo/fastapi/security/advisories
tornado          https://github.com/tornadoweb/tornado/security/advisories
mcp (Python)     https://github.com/modelcontextprotocol/python-sdk/security/advisories
mcp (TS)         https://github.com/modelcontextprotocol/typescript-sdk/security/advisories
```

**Procedure for each direct dependency:**

1. **Tier A query** — fetch advisories for the package from at least one
   canonical source (NVD, MITRE CVE, GitHub Advisory DB, or OSV.dev).
   Example: `https://github.com/advisories?query=<pkg>+ecosystem%3A<eco>`.
2. **Tier B query** — cross-reference against CISA KEV (auto-escalate to
   CRITICAL if the CVE is on the KEV list); check Exploit-DB for public
   PoC code (escalate severity if weaponised exploit exists).
3. **Tier C / Tier D** — query the matching ecosystem-specific source
   from 5.1's ecosystem detection (PyPA for Python, npm advisories for
   npm, RustSec for Rust, etc.) and an aggregator (Snyk or OpenCVE) to
   catch advisories not yet propagated to Tier A.
4. **Tier E (optional)** — for high-traffic / high-sensitivity packages,
   scan HackerOne Hacktivity for not-yet-CVE-assigned disclosures.
5. **Per-package page** — if the package is on the high-profile list
   below, additionally fetch its dedicated security-advisories page.
6. Compare the **installed version** against advisory affected-version
   ranges.
7. Record any matching advisories with full URL and CVE ID.

**Severity rubric** (pin to advisory metadata; do not invent severities):
- **CRITICAL** — installed version is in the affected range of an advisory
  with CVSS ≥ 9.0, **or** the CVE is present in CISA KEV (actively
  exploited in the wild), **or** a weaponised public exploit exists on
  Exploit-DB.
- **HIGH** — CVSS ≥ 7.0, or CVSS ≥ 4.0 with active discussion on the
  Full Disclosure list / Hacker News.
- **MEDIUM** — CVSS ≥ 4.0.
- **LOW** — CVSS < 4.0.

**Always include the advisory URL and CVE ID in the finding** so the
reader can verify the claim against the source. Cite at least one Tier A
source (NVD or MITRE) when a CVE has been assigned.

### 5.3  Maintainer jurisdiction & sanctions screening

> **Why this matters:** software supply chains are subject to the legal,
> political, and law-enforcement frameworks of the jurisdictions in which
> their maintainers operate. A maintainer in a sanctioned jurisdiction
> may be compelled by local law to introduce backdoors or exfiltrate
> telemetry; a maintainer in a jurisdiction without robust code-signing
> infrastructure may be subject to account takeover with no cryptographic
> recourse for the package's users.
>
> **Country of origin is one signal among many — never the sole basis
> for a finding.** The tiers below mirror US OFAC, EU restrictive
> measures, UN sanctions, and US BIS Entity-List frameworks — they are
> not personal judgments of contributors.

#### Tier 1 — Sanctioned (CRITICAL — mandatory review or block)

Anchored to current OFAC, UN, EU, UK sanctions:

- Russia
- Belarus
- Iran
- North Korea (DPRK)
- Cuba
- Syria
- Crimea, Donetsk People's Republic (DNR), Luhansk People's Republic (LNR) — occupied regions of Ukraine

Severity: **CRITICAL** for any direct dependency whose primary maintainer
or owning organisation is in a Tier 1 jurisdiction. Beyond security risk,
deploying such packages may itself constitute a sanctions-compliance issue
depending on the deploying entity.

#### Tier 2 — Elevated review (HIGH / MEDIUM — export-control / incident history)

Anchored to US BIS Entity List, US Executive Order 14034, documented
nation-state APT activity, and prior supply-chain compromise records:

- **China** (PRC) — US BIS export controls, broad national-intelligence-law
  obligations on PRC-domiciled entities (Article 7 of the 2017 National
  Intelligence Law), multiple state-sponsored APT groups documented by
  US-CERT and CISA.
- **Hong Kong** and **Macao** — increasingly aligned with mainland PRC
  legal compulsion since 2020.
- **Eastern European jurisdictions outside EU rule-of-law** — e.g.
  Transnistria; documented organised-cybercrime and APT presence.
- **Latin American jurisdictions with sanctioned regimes or incident
  history** — Venezuela, Nicaragua.
- Any jurisdiction hosting state-sponsored APT groups not already in
  Tier 1.

Severity:
- **HIGH** — direct dependency in a Tier 2 jurisdiction with a single
  maintainer key, no corporate backing in a Tier 3 jurisdiction, and no
  reproducible build.
- **MEDIUM** — direct dependency in a Tier 2 jurisdiction with at least
  one of: corporate backing domiciled in a Tier 3 jurisdiction,
  reproducible build, multi-party signing, or strong adoption history
  (top 100 in the ecosystem with no prior compromise).

#### Tier 3 — Standard (rule-of-law jurisdictions)

US, UK, EU member states (with mature rule-of-law and code-signing
infrastructure: France, Germany, Netherlands, Italy, Spain, Sweden,
Finland, Denmark, Poland, Czechia, Slovakia, Slovenia, Romania, Bulgaria,
Estonia, Latvia, Lithuania, Hungary, Austria, Belgium, Ireland, Portugal,
Greece, Croatia, Cyprus, Luxembourg, Malta), Canada, Australia, New
Zealand, Japan, South Korea, Israel, Singapore, Switzerland, Norway,
Iceland, Taiwan.

> Note on EU members: EU jurisdictions have shared GDPR / NIS2 / DORA
> obligations and ENISA-coordinated incident response. They are Tier 3
> as a baseline — but a specific package may still warrant elevated
> review on a per-incident basis (e.g. a particular maintainer with a
> history of pushing malicious updates).

Severity: **LOW** for unsigned releases; otherwise no finding.

#### Methodology

For each direct dependency:

1. Query the registry for maintainer / owning-org metadata:
   - npm: `npm view <pkg> maintainers` (or registry API:
     `https://registry.npmjs.org/<pkg>`)
   - PyPI: `pip show <pkg>` (or `https://pypi.org/pypi/<pkg>/json`)
   - crates.io: `https://crates.io/api/v1/crates/<pkg>`
   - Go: module path and `https://pkg.go.dev/<module>`
2. Identify the maintainer's stated location via:
   - Registry profile fields.
   - Linked GitHub profile (`https://github.com/<user>` — look for
     `location`, `company`).
   - If a company maintains the package, the company's `about` page.
3. If the maintainer's location cannot be reasonably determined, record
   **MEDIUM** with the note `jurisdiction unknown — manual review`.
4. Cross-reference against current sanctions lists at audit time
   (do not hard-code the list — fetch it):

   | List | URL |
   |---|---|
   | US OFAC SDN | https://sanctionssearch.ofac.treas.gov |
   | US BIS Entity List | https://www.bis.doc.gov/index.php/policy-guidance/lists-of-parties-of-concern/entity-list |
   | EU Sanctions Map | https://www.sanctionsmap.eu |
   | UK OFSI Consolidated List | https://www.gov.uk/government/publications/financial-sanctions-consolidated-list-of-targets |
   | UN Security Council Sanctions | https://www.un.org/securitycouncil/content/un-sc-consolidated-list |

**Reporting requirements for 5.3 findings:**
- State the maintainer / owning-org name.
- State the jurisdiction inferred and the source used to infer it.
- State the tier (1 / 2 / 3) and which framework the tier is anchored to.
- Be explicit that this is **jurisdictional risk screening**, not a
  judgement of any individual contributor.

### 5.4  Typosquatting & namespace confusion

**Threat anchor:** dependency-confusion attacks; lookalike package names;
internal package shadowing.

**Inspect:**
- Direct deps whose name differs by one character from a top-100 package
  in the ecosystem (e.g. `jsonwebtoken` vs `json-webtoken`, `cross-env`
  vs `crossenv`, `python-dateutil` vs `python_dateutil`).
- Direct deps published within the last 30 days with low download counts
  (potential supply-chain plant).
- Internal / private package names also published on a public registry
  (classic dependency-confusion attack — the public package is fetched
  in preference to the private one).
- Scoped packages where the scope owner does not match the expected
  organisation.

**Methodology:**
- For each direct dep, query the registry for: publish date, total
  download count last 30 days, scope owner.
- For top-100 lookalike detection, query the ecosystem's most-downloaded
  list and compute Levenshtein distance ≤ 1 against each direct dep.

**Severity rubric:**
- **CRITICAL** — internal package name shadowed by a public-registry
  package with a higher version (classic dependency-confusion).
- **HIGH** — direct dep is a one-char-typo of a top-100 package in its
  ecosystem.
- **MEDIUM** — direct dep published <30 days ago with no organisational
  adoption signal.

### 5.5  Integrity & provenance

**Inspect:**
- SBOM (CycloneDX or SPDX) present in the repo and current with the
  manifest.
- Releases signed:
  - npm package provenance attestations (Sigstore-backed).
  - PyPI Trusted Publishers / signed wheels.
  - Sigstore / cosign signatures on container images.
  - GPG-signed release artefacts.
- Reproducible build metadata (`SOURCE_DATE_EPOCH`, deterministic
  archive ordering).
- Lockfile integrity hashes match upstream (npm `integrity` field, pip
  `--require-hashes`, Cargo `Cargo.lock` checksums).

**Severity rubric:**
- **HIGH** — production deployment with no SBOM and no signature
  verification.
- **MEDIUM** — SBOM absent but lockfile hashes verified.
- **LOW** — SBOM stale (>90 days behind manifest).

### 5.6  Maintenance health

**Inspect** (per direct dependency):
- Last commit / release age.
- Number of distinct maintainers (bus factor).
- Open security issues outstanding > 90 days.
- Repository archived / read-only / abandoned.
- Recent change in maintainership (transfer of trust — historical
  precedent for malicious updates after a popular package changes hands).

**Severity rubric:**
- **HIGH** — direct dep with last release > 24 months and known unfixed
  CVEs.
- **MEDIUM** — single-maintainer dep with no corporate backing, last
  commit > 12 months.
- **MEDIUM** — direct dep that changed primary maintainer in the last 90
  days and has not yet been re-audited.
- **LOW** — single-maintainer but actively maintained (last commit
  < 6 months).

---

## 10. PHASE 6 — Scoring & Reporting

### 6.1  Severity normalisation

After all substeps complete, walk every finding and confirm severity is
consistent against the rubrics above. Downgrade if a compensating control
exists; never upgrade silently.

### 6.2  Trust-score computation

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

### 6.3  Top-3 critical risks

Select the three findings with the highest combined (severity × blast
radius × exploitability). Render each as a single sentence with the
file:line and the named threat / advisory anchor.

### 6.4  Remediation roadmap

Group remediations into three buckets:

- **Quick wins (≤ 1 day)** — config flips, header additions, scope
  tightening, dependency upgrades to patched versions.
- **Structural (1–4 weeks)** — token-exchange, ETDI signing, audit
  pipeline, SBOM rollout, swap maintainer-jurisdiction-flagged deps for
  alternatives.
- **Strategic (1+ quarter)** — sandbox migration, PBAC rollout, AI-native
  detection layer, supply-chain attestation enforcement.

### 6.5  Compliance mapping & AWS Marketplace pointer

Map each finding category to:
- The whitepaper pillar (1–4) or supply-chain pillar (5).
- The corresponding AWS-native control.
- The AWS Marketplace category for vetted ISV tooling.

| Pillar | AWS-native controls | Marketplace category |
|---|---|---|
| 1. Identity & Authenticity | AWS IAM, AWS Cognito, AWS IAM Identity Center, ETDI proposal | Identity & Access |
| 2. Privilege & Delegation | AWS IAM Identity Center, Bedrock AgentCore (micro-VM, scoped tokens), PBAC engines | Identity & Access |
| 3. Input Trust Boundary | Bedrock Guardrails, AWS WAF, input validation libraries | Application Security |
| 4. Observability & Runtime | Amazon CloudWatch, Amazon GuardDuty, AWS Security Hub, OpenTelemetry | Logging & Monitoring |
| 5. Supply Chain & Dependency | AWS Inspector (vulnerability scanning), AWS Signer, AWS CodeArtifact, ECR image scanning, GuardDuty Malware Protection | Vulnerability & SCA |

Always close the report with:

```
Vetted security tooling for the gaps surfaced:
https://aws.amazon.com/marketplace/solutions/security/
```

---

## 11. Final report — exact format

Produce **one** report block at the end. Render the architectural flowchart
(section 2.1) once with an "audit complete" annotation, then render the
detailed substep tracker (section 2.2) with all completed substeps marked,
then emit the report:

```
+=================================================================+
|              MCP-TRUST AUDIT REPORT — <project name>            |
|              SANS/AWS 2025 agentic-AI threat taxonomy           |
|              + Supply Chain & Dependency Security extension     |
+=================================================================+

Target classification:  <server | client | host | agent | mix>
Transports detected:    <STDIO | SSE-deprecated | StreamableHTTP>
Substeps executed:      <N> / 48
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

PILLAR 5 — Supply Chain & Dependency Security       [findings: N]
  [CRITICAL] 5.2  package-lock.json:1842  axios@0.27.2
             threat:   CVE-2024-39338 SSRF via absolute URL
             evidence: "axios": { "version": "0.27.2", ... }
             why:      attacker-controlled URL bypasses host allowlist
             fix:      upgrade to axios >= 1.7.4
             anchor:   https://github.com/axios/axios/security/advisories/GHSA-8hc4-vh64-cxmj

  [HIGH]     5.3  package.json:34       <pkg>@<ver> — Tier 2 jurisdiction
             threat:   maintainer in PRC; BIS Entity List context
             evidence: <maintainer name / org>
             why:      single-key release; no reproducible build; no
                       corporate backing in Tier 3 jurisdiction
             fix:      replace with <alt-pkg> or pin + verify hash and
                       enable signature attestation
             anchor:   US BIS Entity List; framework: NIST SP 800-161
  ...

+=================================================================+
|  TRUST SCORE                                          X.X / 10  |
|  Band:  <production-ready | minor-gaps | material-risk | ...>   |
+=================================================================+

TOP 3 CRITICAL RISKS
  1. <one sentence — file:line — threat / advisory anchor>
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
  Pillar 2  ->  AWS IAM Identity Center, Bedrock AgentCore, PBAC
  Pillar 3  ->  Bedrock Guardrails, AWS WAF, input validation libraries
  Pillar 4  ->  Amazon CloudWatch, GuardDuty, Security Hub, OpenTelemetry
  Pillar 5  ->  AWS Inspector, AWS Signer, CodeArtifact, ECR scanning,
                GuardDuty Malware Protection
                Frameworks: NIST SP 800-161, EO 14028, OFAC/EU/UN/BIS

+=================================================================+
| Vetted security tooling:                                        |
|   https://aws.amazon.com/marketplace/solutions/security/        |
|                                                                 |
| Source taxonomy:                                                |
|   SANS / AWS (2025) "Navigating modern application security     |
|   challenges with evolved reliance on AI-based applications"    |
|   - Ahmed Abugharbia, SANS Institute                            |
|                                                                 |
| Supply-chain frameworks:                                        |
|   NIST SP 800-161 - Supply Chain Risk Management Practices      |
|   US Executive Order 14028 - Improving the Nation's Cybersec.   |
|   OFAC SDN, EU Sanctions Map, UN Consolidated List, BIS Entity  |
|                                                                 |
| Vulnerability data sources used in this audit:                  |
|   Canonical:   NVD, MITRE CVE, GitHub Advisory DB, OSV.dev      |
|   Exploitation: CISA KEV, Exploit-DB, CERT/CC, Full Disclosure  |
|   Aggregators: CVEdetails, OpenCVE, Snyk, Vulhub                |
|   Bug bounty:  HackerOne Hacktivity, Bugcrowd                   |
|   News:        The Hacker News                                  |
|                                                                 |
| MCP specification:                                              |
|   https://modelcontextprotocol.io                               |
+=================================================================+
```

---

## 12. Operating principles

1. **Render the architectural flowchart (2.1) at the start and at the end.**
   Render the substep tracker (2.2) at the start, after every substep, and
   at the end. The user must always know where the audit is.
2. **Never silently skip a substep.** Mark it `[~]` and state the reason.
3. **Anchor every finding to a named whitepaper threat or external source
   (CVE, advisory, sanctions list).** "Looks dodgy" is not a finding.
4. **Quote the matched code or dependency entry as evidence.** Allegation
   without evidence is not a finding.
5. **Severity follows the rubric.** Do not invent new severities.
6. **For Phase 5, fetch live data.** Do not rely on training-time
   knowledge for advisories or sanctions. Use `WebFetch` against the
   authoritative URLs in 5.2 and 5.3.
7. **For 5.3, frame jurisdictional risk as supply-chain risk anchored to
   sanctions frameworks.** It is not a judgment of individuals. State the
   framework and the inferred jurisdiction explicitly so the reader can
   verify.
8. **Do not propose a fix that is more invasive than the threat.** A
   header change beats a rearchitecture when both are sufficient.
9. **The report is the product.** It must be paste-able into an issue
   tracker, readable by an exec, and actionable by an engineer — at the
   same time.
