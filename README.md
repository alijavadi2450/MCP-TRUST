```
          ____             ,-.----.                 ,/   .`|                                         ,/   .`|
        ,'  , `.  ,----..  \    /  \              ,`   .'  :,-.----.                  .--.--.      ,`   .'  :
     ,-+-,.' _ | /   /   \ |   :    \           ;    ;     /\    /  \           ,--, /  /    '.  ;    ;     /
  ,-+-. ;   , |||   :     :|   |  .\ :        .'___,/    ,' ;   :    \        ,'_ /||  :  /`. /.'___,/    ,'
 ,--.'|'   |  ;|.   |  ;. /.   :  |: |        |    :     |  |   | .\ :   .--. |  | :;  |  |--` |    :     |
|   |  ,', |  ':.   ; /--` |   |   \ :        ;    |.';  ;  .   : |: | ,'_ /| :  . ||  :  ;_   ;    |.';  ;
|   | /  | |  ||;   | ;    |   : .   /        `----'  |  |  |   |  \ : |  ' | |  . . \  \    `.`----'  |  |
'   | :  | :  |,|   : |    ;   | |`-'             '   :  ;  |   : .  / |  | ' |  | |  `----.   \   '   :  ;
;   . |  ; |--' .   | '___ |   | ;                |   |  '  ;   | |  \ :  | | :  ' ;  __ \  \  |   |   |  '
|   : |  | ,    '   ; : .'|:   ' |                '   :  |  |   | ;\  \|  ; ' |  | ' /  /`--'  /   '   :  |
|   : '  |/     '   | '/  ::   : :                ;   |.'   :   ' | \.':  | : ;  ; |'--'.     /    ;   |.'
;   | |`-'      |   :    / |   | :                '---'     :   : :-'  '  :  `--'   \ `--'---'     '---'
|   ;/           \   \ .'  `---'.|                          |   |.'    :  ,      .-./
'---'             `---`      `---`                          `---'       `--`----'
```

# MCP-TRUST

A commercial-grade Claude Code **skill** that runs a **42-substep security
audit** of MCP (Model Context Protocol) servers, AI agents, and agentic OAuth
flows against the threat taxonomy from the SANS / AWS 2025 whitepaper
*"Navigating modern application security challenges with evolved reliance on
AI-based applications"* (Ahmed Abugharbia, SANS Institute).

> Skill, not MCP server — the audit logic is a markdown playbook loaded into
> Claude's context. Zero install footprint. Zero network surface. No
> credentials handled.

---

## What you get

- A **live audit map** rendered at the start, after every substep, and at the
  end — so you always know where the audit is, what cleared, and what is in
  progress.
- **42 substeps across 4 pillars**, every one anchored to a named threat from
  the whitepaper.
- **Per-finding severity rubric** (CRITICAL / HIGH / MEDIUM / LOW) with
  explicit criteria, not vibes.
- **Trust score 0–10**, weighted, with a five-band production-readiness rating.
- **Top-3 critical risks**, **remediation roadmap** (Quick wins / Structural
  / Strategic), and **AWS-control compliance mapping**.

---

## What it checks

| Pillar | Substeps | Covers |
|---|---|---|
| **1. Identity & authenticity** | 12 | Transport security, OAuth 2.1, redirect URI validation, state integrity, PKCE, **app-specific bindings (COAT/CORF defense)**, open redirect, token lifecycle, JWT integrity, **ETDI tool-definition signing**, DCR risk, hardcoded credentials |
| **2. Least privilege & delegation** | 10 | Tool scope sprawl, **confused deputy**, authenticated delegation, JIT credentials, cross-agent isolation, sandboxing & ephemeral sessions, PBAC, call-stack verification, outbound credential pass-through, refresh-token rotation |
| **3. Input trust boundary** | 10 | **Prompt injection** containment, **unsafe data flow**, **unsafe control flow**, Origin header validation, local-bind safety, **tool poisoning**, **rug pull**, metadata injection, input validation, tool-output reflection |
| **4. Observability & runtime** | 10 | Audit logging, rate limiting, behavioural baselines, privilege-escalation guardrails, session-ID binding, stream-resumption integrity, revocation capability, AI-native threat detection, telemetry standardisation, forensic capability |

Plus **Phase 0** (target classification, transport detection, auth-surface
mapping, tool inventory, trust-boundary diagram) and **Phase 5** (severity
normalisation, trust-score computation, top-3 risks, remediation roadmap,
compliance mapping).

---

## Audit flow at a glance

```
PHASE 0  Discovery        ──▶  classify target, map auth surface
   │
   ▼
PHASE 1  Pillar 1         ──▶  Identity & Authenticity        (12 substeps)
   │
   ▼
PHASE 2  Pillar 2         ──▶  Least Privilege & Delegation   (10 substeps)
   │
   ▼
PHASE 3  Pillar 3         ──▶  Input Trust Boundary           (10 substeps)
   │
   ▼
PHASE 4  Pillar 4         ──▶  Observability & Runtime        (10 substeps)
   │
   ▼
PHASE 5  Scoring & Reporting   trust score, top-3, roadmap, compliance map
```

Each substep ticks the audit map as it completes:

```
[ ] pending     [>] in progress     [x] clean     [!] findings     [~] skipped
```

---

## Install

### Option A — Claude Code plugin (recommended)

```
/plugin marketplace add alijavadi2450/MCP-TRUST
/plugin install mcp-trust@alijavadi2450-mcp-trust
```

Claude Code auto-discovers `.claude-plugin/plugin.json` in the repo — no
separate marketplace manifest required.

### Option B — Manual install

**macOS / Linux**
```bash
git clone https://github.com/alijavadi2450/MCP-TRUST.git
mkdir -p ~/.claude/skills/mcp-trust
cp MCP-TRUST/skills/mcp-trust/SKILL.md ~/.claude/skills/mcp-trust/
```

**Windows (PowerShell)**
```powershell
git clone https://github.com/alijavadi2450/MCP-TRUST.git
New-Item -ItemType Directory -Force -Path "$env:USERPROFILE\.claude\skills\mcp-trust" | Out-Null
Copy-Item "MCP-TRUST\skills\mcp-trust\SKILL.md" "$env:USERPROFILE\.claude\skills\mcp-trust\"
```

---

## Usage

In Claude Code, invoke explicitly:

```
/mcp-trust
```

Optionally scope to a path:

```
/mcp-trust src/server
```

The skill also auto-triggers when a project shows MCP / agentic signals —
imports of `mcp`, `FastMCP`, `@modelcontextprotocol/sdk`; handlers like
`@mcp.tool` / `@mcp.resource` / `@mcp.prompt`; agentic OAuth artifacts
(`redirect_uri`, `state=`, PKCE, `Mcp-Session-Id`); or multi-agent
orchestration (LangGraph, CrewAI, Strands, AutoGen).

---

## Output

A single, production-grade report block:

```
+=================================================================+
|              MCP-TRUST AUDIT REPORT — <project>                 |
|              SANS/AWS 2025 agentic-AI threat taxonomy           |
+=================================================================+

Target:        <server | client | host | agent | mix>
Transports:    <STDIO | SSE-deprecated | StreamableHTTP>
Substeps:      <N> / 42       Skipped: <N>
Findings:      <N total — C critical / H high / M medium / L low>

PILLAR 1 — Identity & Authenticity                [findings: N]
  [CRITICAL] 1.3  src/auth.py:42  redirect_uri uses prefix match
             threat:   COAT / CORF account takeover
             evidence: if uri.startswith(allowed):
             why:      enables auth-code interception by malicious app
             fix:      enforce exact-match against allowlist; embed
                       per-app id in state and redirect URI
             anchor:   whitepaper p.8
  ...

PILLAR 2 — Least Privilege & Delegation           [findings: N]
  ...
PILLAR 3 — Input Trust Boundary                   [findings: N]
  ...
PILLAR 4 — Observability & Runtime                [findings: N]
  ...

+=================================================================+
|  TRUST SCORE                                        X.X / 10    |
|  Band: <production-ready | minor-gaps | material-risk | ...>    |
+=================================================================+

TOP 3 CRITICAL RISKS
  1. ...
  2. ...
  3. ...

REMEDIATION ROADMAP
  Quick wins (<= 1 day)
  Structural (1-4 weeks)
  Strategic (1+ quarter)

COMPLIANCE MAPPING
  Pillar 1  ->  AWS IAM, AWS Cognito, ETDI proposal
  Pillar 2  ->  AWS IAM Identity Center, Bedrock AgentCore, PBAC
  Pillar 3  ->  Bedrock Guardrails, AWS WAF, input validation libraries
  Pillar 4  ->  Amazon CloudWatch, GuardDuty, Security Hub, OpenTelemetry
+=================================================================+
```

---

## Trust score bands

| Score | Band | Action |
|---|---|---|
| 9.0 – 10.0 | Production-ready | Ship |
| 7.0 – 8.9  | Minor gaps | Ship with monitoring |
| 5.0 – 6.9  | Material risk | Remediate before broad rollout |
| 2.0 – 4.9  | High risk | Do not deploy to multi-tenant or public surface |
| 0.0 – 1.9  | Unsafe | Halt; rebuild affected pillars |

Deductions: −2.0 per CRITICAL, −1.0 per HIGH, −0.25 per MEDIUM. Per-pillar
deduction is capped at −5.0 (CRITICAL), −3.0 (HIGH), −1.5 (MEDIUM). Floor at 0.

---

## How it works

```
  USER ── /mcp-trust ──▶ Claude loads SKILL.md
                              │
                              ▼
                  ┌──────────────────────────┐
                  │  Phase 0  Discovery      │
                  ├──────────────────────────┤
                  │  Phase 1  Identity       │ 12 substeps
                  │  Phase 2  Privilege      │ 10 substeps
                  │  Phase 3  Input          │ 10 substeps
                  │  Phase 4  Observability  │ 10 substeps
                  ├──────────────────────────┤
                  │  Phase 5  Score & Report │
                  └────────────┬─────────────┘
                               │
        Render audit map  ◀────┴────▶  After every substep
                               │
                               ▼
              Findings → Severity rubric → Trust score
                               │
                               ▼
       Final report  +  Top-3 risks  +  Roadmap  +  Compliance map
```

The skill uses Claude's built-in `Read` and `Grep` tools — no separate process,
no network calls, no credentials handled. Findings are recorded with
`file:line` evidence and anchored to named whitepaper threats.

---

## References

- **Source taxonomy:** SANS / AWS (2025) *Navigating modern application
  security challenges with evolved reliance on AI-based applications* —
  Ahmed Abugharbia, SANS Institute
- **Vetted security tooling:** https://aws.amazon.com/marketplace/solutions/security/
- **Model Context Protocol:** https://modelcontextprotocol.io
- **OAuth 2.1 (draft):** https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/
- **PKCE (RFC 7636):** https://datatracker.ietf.org/doc/html/rfc7636

---

## License

MIT — see [LICENSE](LICENSE).

## Author

**Ali Javadi** — https://github.com/alijavadi2450

Issues, PRs, and threat-pattern contributions welcome.
