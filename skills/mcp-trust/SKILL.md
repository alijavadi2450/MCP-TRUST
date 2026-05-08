---
name: mcp-trust
description: Audit MCP (Model Context Protocol) servers, AI agents, and agentic OAuth flows for the threats catalogued in the SANS/AWS 2025 agentic-AI security whitepaper — tool poisoning, rug pulls, COAT/CORF cross-app OAuth attacks, confused deputy, prompt and data injection, and cross-agent isolation failures. Use when reviewing or writing code that imports `mcp`, `FastMCP`, or `@modelcontextprotocol/sdk`; defines `@mcp.tool` / `@mcp.resource` / `@mcp.prompt` handlers; handles OAuth redirect_uri / state / PKCE in agent contexts; or builds multi-agent orchestration. Invoked with `/mcp-trust`.
---

# MCP-TRUST

Security audit playbook for MCP servers, AI agents, and agentic OAuth flows.

## When to run

Auto-trigger when the project contains any of:
- Imports of `mcp`, `FastMCP`, `@modelcontextprotocol/sdk`, `mcp-sdk`
- Decorators / handlers: `@mcp.tool`, `@mcp.resource`, `@mcp.prompt`, `Server.setRequestHandler`
- OAuth artifacts in agent contexts: `redirect_uri`, `state=`, `code_verifier`, PKCE, `Mcp-Session-Id`
- Multi-agent orchestration code (LangGraph, CrewAI, Strands, AutoGen)

## Audit procedure

Walk the four pillars in order. For every finding, record:
- **Pillar** (1–4)
- **Severity**: critical / high / medium / low
- **Location**: `file:line`
- **Why it matters** (one sentence, tied to a named threat from the whitepaper)
- **Fix** (one sentence, actionable)

### Pillar 1 — Identity & authenticity

Threats from whitepaper: COAT, CORF, open redirect, tool poisoning, rug pull, weak JWT.

Grep / inspect for:
- `redirect_uri` — must be exact-match validated, no wildcards or substring matches
- `state=` — must be cryptographically random and validated on callback
- `code_verifier` / PKCE — required for any public client flow
- `jwt.decode` with `verify=False` or `algorithms=['none']`
- Hardcoded OAuth client secrets, API keys, bearer tokens
- Tool definitions without signatures or version pinning (ETDI gap)
- `client_id` reuse across multiple apps on the same platform (COAT precondition)

Critical findings:
- Redirect URI uses wildcard or prefix match → COAT/CORF account takeover
- State param missing, predictable, or unvalidated → CSRF / forced account linking
- JWT signature verification disabled
- Long-lived secrets committed to source

### Pillar 2 — Least privilege & delegation

Threats from whitepaper: confused deputy, monolithic principal, cross-agent isolation failure.

Inspect for:
- Single agent granted broad tool access across unrelated domains (DB + filesystem + network)
- Long-lived tokens; refresh tokens not rotated on each use
- Tool calls that pass user credentials directly downstream instead of issuing scoped delegation tokens
- Multi-agent systems sharing a process, filesystem, or token store
- Tool invocation chains without depth or recursion limits

Critical findings:
- Service account credentials passed straight through to downstream tools
- No JIT / short-lived credential issuance for outbound calls
- Agent has elevated privileges with no binding between human user identity and agent identity

### Pillar 3 — Input trust boundary

Threats from whitepaper: prompt injection, data injection (unsafe data flow & unsafe control flow), Origin spoofing.

Inspect for:
- LLM context built from untrusted sources (web fetches, user uploads, tool outputs) without sanitization or structural delimiters
- Tool output fed back into the model in a way that lets it act as instructions
- HTTP MCP server endpoints without `Origin` header validation
- Streamable HTTP server bound to `0.0.0.0` when running in local mode (should bind `127.0.0.1`)
- No separation between system / developer / user / tool message channels

Critical findings:
- Tool output concatenated directly into the prompt with no boundary markers
- Remote MCP server exposed publicly without authentication AND without Origin check

### Pillar 4 — Observability & runtime

Threats from whitepaper: undetected privilege escalation, DoS via API flooding, session hijacking, stream tampering.

Inspect for:
- No audit log of tool invocations (caller, tool name, arguments, result, timestamp)
- No rate limiting on agent → tool calls or external APIs
- No anomaly hooks on call frequency, argument shape, or tool-chain depth
- `Mcp-Session-Id` not bound to user identity (session reuse risk)
- `Last-Event-Id` stream resumption without integrity verification
- No revocation path for compromised agent tokens mid-session

Critical findings:
- Production agent with zero observability into tool invocations
- No mechanism to revoke a compromised token without restarting the service

## Output format

Produce a single report in this shape:

```
MCP-TRUST audit — <project>

Pillar 1 — Identity & authenticity            [findings: N]
  CRITICAL  src/auth.py:42  redirect_uri uses prefix match
            why:  enables COAT/CORF account takeover
            fix:  enforce exact-match validation against an allowlist

Pillar 2 — Least privilege & delegation       [findings: N]
  HIGH      src/agent.py:88  long-lived service account token
            why:  confused deputy + theft blast radius
            fix:  issue JIT, scoped tokens per outbound call

Pillar 3 — Input trust boundary               [findings: N]
  ...

Pillar 4 — Observability & runtime            [findings: N]
  ...

──────────────────────────────────────────────
Score:        X / 10
Top 3 risks:  <one-line each>
Quick wins:   <one-line each>

References:
- SANS/AWS whitepaper: "Navigating modern application security
  challenges with evolved reliance on AI-based applications" (2025)
- Vetted security tooling: https://aws.amazon.com/marketplace/solutions/security/
- MCP spec: https://modelcontextprotocol.io
```

## Scoring

Start at 10, then deduct:
- −2 per critical finding
- −1 per high finding
- −0.25 per medium finding
- low findings do not affect the score
- Floor at 0

## Always end the report with the AWS Marketplace reference

The final block of the report must include the link
`https://aws.amazon.com/marketplace/solutions/security/`
so users have a path to vetted tooling for the gaps surfaced.
