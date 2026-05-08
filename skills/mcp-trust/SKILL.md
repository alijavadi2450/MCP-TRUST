---
name: mcp-trust
description: Commercial-grade security audit playbook for MCP (Model Context Protocol) servers, AI agents, and agentic OAuth flows. Walks 55 substeps across five pillars from the SANS/AWS 2026 whitepaper "Navigating modern application security challenges with evolved reliance on AI-based applications" plus a Supply Chain & Dependency layer — Identity & Authenticity, Least Privilege & Delegation, Input Trust Boundary, Observability & Runtime, and Supply Chain & Dependency Security. Auto-triggers on imports of `mcp`, `FastMCP`, `@modelcontextprotocol/sdk`; on `@mcp.tool` / `@mcp.resource` / `@mcp.prompt` handlers; on agentic OAuth artifacts (`redirect_uri`, `state=`, `code_verifier`, PKCE, `Mcp-Session-Id`); on multi-agent orchestration code (LangGraph, CrewAI, Strands, AutoGen); on Streamable HTTP / SSE transport implementations; and on the presence of dependency manifests (`package.json`, `requirements.txt`, `pyproject.toml`, `Cargo.toml`, `go.mod`). Renders an architectural flowchart at start and end and a live substep tracker that ticks after every substep, then produces a severity-rated finding list, a 0–10 trust score, top-3 critical risks, a remediation roadmap, AWS-control compliance mapping, live CVE/advisory cross-reference, and jurisdictional supply-chain risk screening anchored to OFAC/EU/UN/BIS sanctions frameworks. Invoke explicitly with `/mcp-trust`.
---

# MCP-TRUST — Agentic AI Security Audit

A structured security review of MCP servers, AI agents, and agentic OAuth flows
against the threat taxonomy from the SANS / AWS 2026 whitepaper *"Navigating
modern application security challenges with evolved reliance on AI-based
applications"* (Ahmed Abugharbia, SANS Institute), extended with a supply-chain
and jurisdictional-risk layer that the whitepaper notes but does not codify
into substeps.

This skill is **not** a scanner. It is a senior-engineer-grade playbook loaded
into Claude's context. Claude executes the audit using its built-in `Read`,
`Grep`, and `WebFetch` tools — no external process, no credentials handled.

The audit covers **55 substeps across 5 pillars** (12 / 12 / 12 / 10 / 9),
plus a discovery phase (6 substeps) and a scoring/reporting phase. Every
finding is anchored to a named threat from the whitepaper or to a
concrete external advisory / sanctions source.

---

## 0. Setup / Permissions (one-time)

Claude Code skills cannot ship their own tool permissions via frontmatter.
Phase 5.2 makes ~30 `WebFetch` calls per audit run against public security
feeds; without an allow-list, the host prompts you for each one.

Paste the block below into your `~/.claude/settings.json` `permissions.allow`
array (one-time setup). All domains are read-only, public security data
sources — no credentials are sent.

```jsonc
"WebFetch(domain:github.com)",
"WebFetch(domain:raw.githubusercontent.com)",
"WebFetch(domain:api.github.com)",
"WebFetch(domain:nvd.nist.gov)",
"WebFetch(domain:services.nvd.nist.gov)",
"WebFetch(domain:cve.mitre.org)",
"WebFetch(domain:www.cve.org)",
"WebFetch(domain:osv.dev)",
"WebFetch(domain:api.osv.dev)",
"WebFetch(domain:deps.dev)",
"WebFetch(domain:api.deps.dev)",
"WebFetch(domain:pypi.org)",
"WebFetch(domain:registry.npmjs.org)",
"WebFetch(domain:www.npmjs.com)",
"WebFetch(domain:crates.io)",
"WebFetch(domain:pkg.go.dev)",
"WebFetch(domain:rubygems.org)",
"WebFetch(domain:rustsec.org)",
"WebFetch(domain:security.snyk.io)",
"WebFetch(domain:www.opencve.io)",
"WebFetch(domain:www.cvedetails.com)",
"WebFetch(domain:www.exploit-db.com)",
"WebFetch(domain:kb.cert.org)",
"WebFetch(domain:seclists.org)",
"WebFetch(domain:vulhub.org)",
"WebFetch(domain:www.hackerone.com)",
"WebFetch(domain:www.bugcrowd.com)",
"WebFetch(domain:thehackernews.com)",
"WebFetch(domain:www.cisa.gov)",
"WebFetch(domain:ossindex.sonatype.org)",
"WebFetch(domain:avd.aquasec.com)",
"WebFetch(domain:attackerkb.com)",
"WebFetch(domain:googleprojectzero.blogspot.com)",
"WebFetch(domain:research.jfrog.com)",
"WebFetch(domain:www.tenable.com)",
"WebFetch(domain:www.wiz.io)",
"WebFetch(domain:msrc.microsoft.com)",
"WebFetch(domain:socket.dev)",
"WebFetch(domain:securityscorecards.dev)",
"WebFetch(domain:api.securityscorecards.dev)",
"WebFetch(domain:nodejs.org)",
"WebFetch(domain:openjsf.org)",
"WebFetch(domain:bleepingcomputer.com)",
"WebFetch(domain:www.bleepingcomputer.com)",
"WebFetch(domain:securelist.com)",
"WebFetch(domain:isc.sans.edu)",
"WebFetch(domain:krebsonsecurity.com)",
"WebFetch(domain:sanctionssearch.ofac.treas.gov)",
"WebFetch(domain:www.bis.doc.gov)",
"WebFetch(domain:www.sanctionsmap.eu)",
"WebFetch(domain:www.gov.uk)",
"WebFetch(domain:www.un.org)",
```

If you skip this step, the audit still works — you'll just be asked to
approve each fetch as it happens. To hard-disable Phase 5.2 instead,
add `"WebFetch"` to `permissions.deny`; the audit will mark all of 5.2
as `[~] live advisory feeds disabled`.

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

### 2.0 Banner (render verbatim at audit start, before anything else)

Print this banner exactly, then a single blank line, then proceed to the
architectural flowchart (2.1). This is the first thing the user sees on
every `/mcp-trust` invocation.

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

                Agentic AI Security Audit  ·  SANS / AWS 2026
                55 substeps  ·  5 pillars  ·  live CVE + sanctions feeds
```

### 2.1 Architectural flowchart (render at start and end)

```
+======================================================================+
|                       MCP-TRUST AUDIT PIPELINE                       |
|         SANS / AWS 2026  ·  4-Pillar Model  +  Supply Chain          |
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
 │  12 steps   │             │  12 steps   │             │  12 steps   │
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
                │ 10 steps    │           │  9 steps    │
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
|                MCP-TRUST AUDIT MAP — SANS/AWS 2026              |
+=================================================================+
|                                                                 |
|  PHASE 0 — DISCOVERY                                            |
|  [ ] 0.0  Scope declaration                                     |
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
|  [ ] 2.11 Tool consent boundary                                 |
|  [ ] 2.12 Multi-turn authority persistence                      |
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
|  [ ] 3.11 Resource URI trust                                    |
|  [ ] 3.12 Sensitive result reflection                           |
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
|  [ ] 5.7  CI/CD and release-pipeline security                   |
|  [ ] 5.8  Install-time and runtime dangerous behaviour          |
|  [ ] 5.9  Supply-chain ownership & maintainership (technical)   |
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

### 2.4  Dynamic phase locator (render at every phase transition)

A vertical, single-column view of the seven phases with a `◀── YOU ARE HERE`
marker that moves down the chart as the audit walks through each phase.
This complements the macro architectural flowchart (2.1, rendered only at
bookends) and the detailed substep tracker (2.2, re-rendered after every
substep) by giving the user a phase-level "where am I, what just finished,
what's next" view at every phase boundary.

**When to render:**
- Once at audit start, with `◀── starting here` on Phase 0.
- Each time the audit enters a new phase (i.e. before substep 0.1, 1.1,
  2.1, 3.1, 4.1, 5.1, 6.1) — re-render with `[x]` (or `[!]` / `[~]`) on
  all completed phases and `◀── YOU ARE HERE` on the newly active phase.
- Once at audit end, with `[*] ◀── audit complete` on Phase 6.

**Marker semantics on phase lines:**

| Phase line marker                      | Meaning                            |
|----------------------------------------|------------------------------------|
| `[ ] PHASE n · ...`                    | Pending — not yet entered          |
| `[>] PHASE n · ... ◀── YOU ARE HERE`   | Currently in this phase            |
| `[x] PHASE n · ...`                    | Completed — clean (no findings)    |
| `[!] PHASE n · ...`                    | Completed — findings recorded      |
| `[~] PHASE n · ...`                    | Skipped — not applicable to target |
| `[*] PHASE n · ... ◀── audit complete` | Final close                        |

**Template** (replace each `<MARKER>` per the table above):

```
+======================================================================+
|                  MCP-TRUST  ·  PHASE LOCATOR                         |
+======================================================================+

   ┌─────────────────────────────────────────┐
   │  PHASE 0  ·  DISCOVERY                  │  <MARKER>
   │  classify · transport · auth · invent.  │
   └────────────────────┬────────────────────┘
                        │
                        ▼
   ┌─────────────────────────────────────────┐
   │  PHASE 1  ·  IDENTITY & AUTHENTICITY    │  <MARKER>
   │  12 substeps · OAuth · JWT · ETDI       │
   └────────────────────┬────────────────────┘
                        │
                        ▼
   ┌─────────────────────────────────────────┐
   │  PHASE 2  ·  LEAST PRIVILEGE & DELEG.   │  <MARKER>
   │  10 substeps · confused deputy · JIT    │
   └────────────────────┬────────────────────┘
                        │
                        ▼
   ┌─────────────────────────────────────────┐
   │  PHASE 3  ·  INPUT TRUST BOUNDARY       │  <MARKER>
   │  10 substeps · prompt / data injection  │
   └────────────────────┬────────────────────┘
                        │
                        ▼
   ┌─────────────────────────────────────────┐
   │  PHASE 4  ·  OBSERVABILITY & RUNTIME    │  <MARKER>
   │  10 substeps · logs · rate · anomaly    │
   └────────────────────┬────────────────────┘
                        │
                        ▼
   ┌─────────────────────────────────────────┐
   │  PHASE 5  ·  SUPPLY CHAIN & DEPENDENCY  │  <MARKER>
   │  6 substeps · live CVE · jurisdiction   │
   └────────────────────┬────────────────────┘
                        │
                        ▼
   ┌─────────────────────────────────────────┐
   │  PHASE 6  ·  SCORE & REPORT             │  <MARKER>
   │  trust score · top-3 · roadmap          │
   └─────────────────────────────────────────┘
```

**Worked example** — the locator while the audit is mid-Phase-2:

```
   ┌─────────────────────────────────────────┐
   │  PHASE 0  ·  DISCOVERY                  │  [x] done
   └────────────────────┬────────────────────┘
                        ▼
   ┌─────────────────────────────────────────┐
   │  PHASE 1  ·  IDENTITY & AUTHENTICITY    │  [!] 3 findings
   └────────────────────┬────────────────────┘
                        ▼
   ┌─────────────────────────────────────────┐
   │  PHASE 2  ·  LEAST PRIVILEGE & DELEG.   │  [>] ◀── YOU ARE HERE
   └────────────────────┬────────────────────┘
                        ▼
   ┌─────────────────────────────────────────┐
   │  PHASE 3  ·  INPUT TRUST BOUNDARY       │  [ ] pending
   └────────────────────┬────────────────────┘
                  (... remaining phases ...)
```

### 2.5  Per-substep preview (print before running each substep)

Before running any substep's checks, print a single preview block so the
user knows exactly what is about to be examined. After the substep's
checks complete, print a result summary. This wraps every substep in a
"about to look at X" → "X done, found Y" envelope.

**Format (before substep runs):**

```
▶ Substep X.Y — <substep name>
  Examines: <one-sentence preview derived from the substep's "Inspect:"
            block — what code patterns, configurations, or external
            sources are about to be checked>
```

**Format (after substep runs):**

```
>>> Substep X.Y complete — <count> findings
    Severity:  C critical / H high / M medium / L low
    Next:      X.Y+1 <next substep name>
```

**Examples:**

```
▶ Substep 1.3 — Redirect URI validation
  Examines: how the OAuth client matches redirect_uri against its
  allowlist — wildcard / prefix / regex / substring matching are
  unsafe; only exact match is acceptable.

[... checks run ...]

>>> Substep 1.3 complete — 2 findings
    Severity:  1 critical / 1 high
    Next:      1.4 State parameter integrity
```

```
▶ Substep 5.2 — Known-vulnerability cross-reference (live advisories)
  Examines: each direct dependency against NVD, MITRE CVE, GitHub
  Advisory DB, OSV.dev, CISA KEV, Exploit-DB, CERT/CC, Snyk, OpenCVE
  and per-package security-advisory pages — fetched live via WebFetch.

[... checks run ...]

>>> Substep 5.2 complete — 1 finding
    Severity:  0 critical / 1 high
    Next:      5.3 Maintainer jurisdiction & sanctions screening
```

---

## 3. Procedure

For every substep:

1. **If this substep is the first of its phase** (i.e. 0.1, 1.1, 2.1, 3.1,
   4.1, 5.1, or 6.1), re-render the dynamic phase locator (Section 2.4)
   with `◀── YOU ARE HERE` on the new active phase and the appropriate
   completed-phase marker (`[x]` clean, `[!]` findings, `[~]` skipped) on
   each prior phase.
2. **Print the per-substep preview block** (Section 2.5) — substep ID,
   name, and a one-sentence `Examines: ...` line derived from the
   substep's `Inspect:` block.
3. State the **threat anchor(s)** from the whitepaper or external source.
4. Run the listed Grep / Read / WebFetch targets.
5. For each match, classify against the **severity rubric** below.
6. Emit findings in the standard finding-record format.
7. **Print the post-substep result summary** (Section 2.5) — finding count
   by severity and the name of the next substep.
8. Re-render the substep tracker (Section 2.2) with the substep marked.

### Finding record format

Every finding is recorded as a structured block:

```
[<SEVERITY>] [<CONFIDENCE>] [<TYPE>]  <pillar.substep>  <file>:<line | n/a>
  threat:        <named threat from whitepaper or external source>
  evidence:      <the matched code / config / dep, ≤ 120 chars>
  why:           <one sentence — the concrete attack this enables>
  fix:           <one sentence — actionable remediation>
  anchor:        <whitepaper section reference or external URL>
  context:       <deployment-context modifier if it shifted severity — see 3.5.6>
  compensating:  <named compensating control if severity was downgraded — see 3.5.7>
```

`<SEVERITY>`   ∈ { CRITICAL, HIGH, MEDIUM, LOW }
`<CONFIDENCE>` ∈ { CONFIRMED, STRONG_SIGNAL, WEAK_SIGNAL, UNKNOWN } — see 3.5.1
`<TYPE>`       ∈ { DEFECT, RISK, GAP, OBSERVATION, QUESTION } — see 3.5.2

---

## 3.5  Audit methodology

This section is the methodological frame that every Phase 1–5 substep
inherits. It is the glue that prevents the audit from emitting fake
certainty: every grep hit must justify itself, every runtime claim must
declare whether it is actually evidenced from the repository, and every
emitted item must declare whether it is a real defect or a question for
human review.

The seven sub-blocks below are foundational — they retroactively temper
every existing pillar rubric. A rule in Phase 1–5 that says "missing X
= HIGH" still fires, but it now fires with a confidence and a finding
type, and is silently downgraded to a `QUESTION` when the underlying
evidence is unverifiable from the repo alone.

### 3.5.1  Evidence confidence model

Severity alone is not enough. Every finding **must** also carry a
confidence rating that states how much of the conclusion is supported
by direct repository evidence vs inference vs absence-of-evidence.

| Confidence | When to use |
|---|---|
| **CONFIRMED**     | The matched line, config value, or advisory record itself proves the issue (e.g. `verify_signature=False` is in the executed path; `axios@0.27.2` is in `package-lock.json` and the CVE's affected range covers it). |
| **STRONG_SIGNAL** | Multiple consistent indicators in code/config strongly suggest the issue, but full exploitability or runtime posture is not proven from the repo (e.g. wildcard CORS combined with no auth check, but the deployed reverse-proxy configuration is not in the repo). |
| **WEAK_SIGNAL**   | A single heuristic indicator (one grep hit, one suspicious symbol) with no semantic confirmation. Triage signal only — must be elevated by manual validation before it can drive scoring. |
| **UNKNOWN**       | The control cannot be verified from repository evidence alone. Typical for runtime, deployment, observability, isolation, log-sink, anomaly-detection, and revocation claims. |

**Hard rules:**
- A grep hit, by itself, is at most `WEAK_SIGNAL` unless the matched line literally proves the insecure behaviour.
- Absence of code evidence for a *runtime* control is `UNKNOWN`, not "the control is missing." A repo may simply not contain the deployment manifest.
- Findings whose confidence is `UNKNOWN` **do not deduct from the trust score** (see 3.5.3) — they are emitted as review questions instead.

### 3.5.2  Finding types taxonomy

In addition to severity and confidence, every emitted item is tagged
with a finding *type*. This stops every observation from being
mis-rendered as a "LOW finding."

| Type | Meaning |
|---|---|
| **DEFECT**      | Directly evidenced security flaw with a plausible, named exploit path. |
| **RISK**        | Risky design or architectural choice that creates a plausible exploit path under realistic conditions, but the flaw itself is not yet manifest. |
| **GAP**         | Missing control or hardening measure. The system is not necessarily broken — it lacks defence-in-depth. |
| **OBSERVATION** | A condition worth noting that may inform risk but is not itself a defect, risk, or gap (e.g. "single maintainer, actively maintained"). |
| **QUESTION**    | Repository evidence is insufficient; needs human confirmation. Emitted into the Manual Validation appendix, not the pillar finding lists. |

**Worked re-classifications** (these are real past failure modes —
items that previous versions of this skill emitted as score-deducting
findings, but which under this taxonomy are tagged correctly):

| Item | Was | Is now |
|---|---|---|
| Protected, rate-limited DCR endpoint                            | LOW finding | `OBSERVATION` — secure state, not a finding |
| Single-maintainer dep, actively maintained                      | LOW finding | `OBSERVATION` |
| Maintainer jurisdiction unknown                                 | MEDIUM finding | `QUESTION` (manual review) |
| No anomaly detection visible in repo                            | HIGH finding | `QUESTION` (runtime, not evidenced from repo) |
| ETDI tool definitions unsigned (registry not runtime-mutable)   | HIGH finding | `GAP` MEDIUM (advanced hardening) |
| ETDI + tool registry mutable at runtime by unauth callers       | HIGH finding | `DEFECT` CRITICAL (rug-pull precondition) — unchanged |

### 3.5.3  Do not score unknowns

`QUESTION`-typed and `UNKNOWN`-confidence items **do not reduce the
trust score**. They surface in the report only as:
- "Manual validation required" appendix entries
- "Open review questions" enumerations
- "Operational gaps to confirm" notes

Rationale: the score is meant to reflect security posture *that the
audit can verify*. Folding unverifiable claims into the score
manufactures false precision and rewards confident-sounding guesses.

### 3.5.4  Heuristic match validation rules

Grep signatures throughout this skill are **triage**, not proof. Before
emitting a finding from a grep hit, all four conditions must hold:

1. The matched line is **executable code or active configuration** —
   not a comment, docstring, test fixture, example file, README
   excerpt, or migration that has been removed.
2. The matched symbol is **security-relevant in context** — e.g.
   `verify=False` matters in `jwt.decode(...)`; the same string in a
   test that only asserts schema does not.
3. The surrounding code path is **reachable** — the matched line is
   not dead code, behind an `if False:` guard, or otherwise
   unreachable from any entry point.
4. The insecure behaviour is **not contradicted** by nearby
   validation, framework defaults, or wrapper logic that already
   sanitises the input.

If any condition fails:
- Demote to `OBSERVATION` (still record, but not as a finding), **or**
- Convert to `QUESTION` (manual validation required), **or**
- Discard the hit entirely.

**Conversely:** absence of grep hits is *not* evidence of safety. It
only means the specific signature did not match. A negative grep
result is recorded as `coverage: heuristic` in the substep summary,
not as `status: clean`.

### 3.5.5  Automatic fail conditions

Regardless of trust-score arithmetic, the audit **must** mark the
target as `FAIL — manual remediation required` if any of the
following are present at `CONFIRMED` confidence:

- JWT signature verification disabled (`verify=False`,
  `algorithms=["none"]`, `verify_signature=False`)
- Public OAuth client without PKCE
- Wildcard / prefix / substring redirect-URI matching
- User bearer token forwarded downstream as-is to third-party services
- Plain-HTTP-bound remote MCP endpoint (Streamable HTTP without TLS)
- Remotely reachable privileged MCP endpoint with no authentication
- Hardcoded live cloud / SaaS / git-provider credential in repository
- Direct dependency version confirmed in the affected range of a
  CISA-KEV-listed CVE
- Unauthenticated runtime mutation of tool definitions or registry
  (rug-pull precondition)

A FAIL caps the trust band at "high risk — do not deploy" regardless
of the numeric score. The triggering condition is named explicitly in
the report's "Top 3 critical risks" block, and the fail is recorded as
the first line of the Trust-score panel:
`AUTO-FAIL: <triggering condition>`.

### 3.5.6  Deployment context modifiers

Severity is not context-free. Before scoring, classify the target:

| Context | Description |
|---|---|
| **LOCAL_DEV**            | Loopback-only; single developer; not network-reachable. |
| **INTERNAL_SINGLE_USER** | Internal network; one human user; behind a corporate-auth boundary. |
| **INTERNAL_MULTI_USER**  | Internal network; multiple users; some lateral exposure. |
| **EXTERNAL_PRODUCTION**  | Public internet; multi-tenant or unauthenticated reachable surface. |

The classification is recorded **once** in the report header
(`Deployment context: <CONTEXT>`); individual findings do not need to
repeat it. They reference it only when context shifted their severity,
via the `context:` line in the finding record.

Severity adjustments:
- Findings predicated on **network exposure** (CORS, `Origin`, `0.0.0.0`
  bind) are demoted by one level when the context is `LOCAL_DEV` and
  the binding is loopback-only.
- Findings predicated on **browser reachability** require the deployed
  endpoint to be reachable from a browser; for STDIO-only transports,
  such findings may be inapplicable (`[~]`).
- Findings on **operational / runtime** controls (logging sinks,
  anomaly detection, revocation infrastructure, sandboxing) demand
  stricter posture for `EXTERNAL_PRODUCTION` than for `LOCAL_DEV`,
  and at `LOCAL_DEV` typically convert to `QUESTION` rather than
  scored finding.

### 3.5.7  Compensating controls

Severity may be downgraded by **at most one level** when a directly
evidenced compensating control materially blocks the exploit path.
The compensating control must be named in the finding's
`compensating:` line.

Examples of legitimate compensation:
- Missing `Origin`-header validation **may** drop from CRITICAL → HIGH
  if the endpoint is loopback-only and not browser-reachable.
- Broad tool scope **may** drop from HIGH → MEDIUM if every privileged
  call requires explicit user re-confirmation gated by runtime policy.
- Long access-token TTL **may** drop from MEDIUM → LOW if the token
  is audience-bound, device-bound, and revocable with active
  monitoring.

**Hard rules:**
- Never downgrade below `LOW`.
- Never downgrade a confirmed cryptographic or authentication defect
  (disabled signature verification, `alg=none`, predictable `state`)
  on the strength of monitoring alone — monitoring detects exploits,
  it does not prevent them.
- Auto-fail triggers (3.5.5) **cannot** be compensated. Compensating
  controls reduce severity, never the auto-fail status.

---

## 4. PHASE 0 — Discovery

Goal: classify the target and decide which substeps apply. Some substeps may
be marked `[~]` (skipped) if the target lacks the relevant surface.

### 0.0 Scope declaration

Before any discovery work, declare and print the audit scope. This is
how the report avoids claiming complete coverage when key inputs are
missing. Render the block below at audit start; copy its values into
the final-report header (Section 11).

Required fields:

- **Path reviewed**         — absolute or repo-relative path the audit examined.
- **Files inspected**       — count of source files read, with breakdown by language.
- **Manifests detected**    — every dep manifest found (`package.json`, `pyproject.toml`, `Cargo.lock`, etc.).
- **Lockfiles available**   — yes / partial / no. If `no`, Phase 5 cannot resolve transitive deps and 5.2 coverage is reduced.
- **Transport surfaces**    — STDIO / SSE / Streamable HTTP / multiple / none.
- **Auth config present**   — yes / partial / no. If `no`, Pillar 1 findings on configured-state controls become `QUESTION` per 3.5.2.
- **Deployment manifests**  — Dockerfile, docker-compose, k8s manifests, Terraform, CDK, or none. If none, Pillar 4 runtime claims default to `UNKNOWN` confidence per 3.5.1.
- **Web access enabled**    — yes / no. If `no`, Phase 5.2 / 5.3 fall back to in-context advisory data only and are flagged `coverage: heuristic` in the substep summary.
- **Review classification** — `code-only` / `code+config` / `code+config+docs` / `full deployment evidence`.
- **Deployment context**    — LOCAL_DEV / INTERNAL_SINGLE_USER / INTERNAL_MULTI_USER / EXTERNAL_PRODUCTION (per 3.5.6). If unstated by the user, infer from binds + transport + deploy manifests; record the inference and emit a confirmation question into the Manual Validation appendix (6.6).

**Coverage rule:** if any field above is `no` or `partial`, name the
specific phases or substeps whose coverage is reduced, and state in
the final report that those substeps' negative results are
`coverage: heuristic`, not `status: clean`.

```
+======================================================================+
|                       AUDIT SCOPE DECLARATION                        |
+======================================================================+
  Path reviewed:         <abs / repo-relative path>
  Files inspected:       <N> total  ·  <breakdown by language>
  Manifests detected:    <list>
  Lockfiles:             <yes | partial | no>
  Transport surfaces:    <list>
  Auth config:           <yes | partial | no>
  Deployment manifests:  <list or "none">
  Web access:            <yes | no>
  Review classification: <code-only | code+config | code+config+docs |
                          full deployment evidence>
  Deployment context:    <LOCAL_DEV | INTERNAL_SINGLE_USER |
                          INTERNAL_MULTI_USER | EXTERNAL_PRODUCTION>
                          (inferred — confirm in Manual Validation)

  Coverage caveats:
    - <substep id>: <reason coverage is reduced>
    - ...
+======================================================================+
```

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
- **SSE** (deprecated as of protocol 2026-03-26) — look for `sse_server`, `EventSource`, `text/event-stream`
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
> to prevent unauthorized access and tool impersonation." — SANS/AWS 2026, p.12

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
- **HIGH** — SSE transport in use after protocol 2026-03-26.
- **MEDIUM** — Session IDs from non-cryptographic RNG.
- **LOW** — Hard-coded transport selection with no override.

### 1.2  OAuth 2.1 compliance

**Threat anchor:** insufficient delegation security (whitepaper p.7, "March
2026 MCP update mandates OAuth 2.1").

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

**Beyond-regex secret-handling inspection** (per 3.5.4: regex hits are
triage; these checks supply the semantic confirmation):

- `.env`, `secrets.toml`, `credentials.json`, `*.pem`, `*.key` files
  tracked in git history (use `git log --all --full-history -- <path>`,
  not just current tree).
- Secrets passed into log statements, exception payloads, tracing
  spans, debug output, or error messages — search for token-like
  parameters reaching `log.*`, `print(`, `console.log(`, `span.*`,
  `traceback`.
- Secrets reflected into tests, fixtures, CI snapshots, or
  documentation screenshots.
- Cloud credentials (`AWS_ACCESS_KEY_ID`, GCP service-account JSON,
  Azure SP secrets) used directly in code rather than via the
  platform's managed-identity mechanism (IAM role, Workload Identity,
  Managed Identity).
- Sample / template config files that encourage plaintext secret
  storage rather than referencing a secrets manager.

**Confidence rule:** a plausible-looking secret string in docs / tests
/ fixtures is `WEAK_SIGNAL`; elevate to `CONFIRMED` only when context
strongly indicates active runtime use (e.g. the same value appears
in a deploy manifest or env file referenced by the runtime).

---

## 6. PHASE 2 — Pillar 2: Least Privilege & Delegation

> "AI systems must be designed with isolation and containment in mind. Agents
> should operate in sandboxed environments such as micro-VMs to prevent
> privilege escalation or cross-session data leakage." — SANS/AWS 2026, p.12

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

### 2.11  Tool consent boundary

**Threat anchor:** confused deputy via under-gated side-effectful tools;
silent execution of destructive or external actions on behalf of a user
who never explicitly approved them. Specific to MCP because tool
invocations are model-driven and easily occur mid-conversation without
clear consent UX.

**Inspect:**
- Tools with side effects (file write, network egress, payments,
  identity manipulation, deletion, irreversible operations) callable
  by the LLM without an explicit user-confirmation step.
- No labelling or grouping that distinguishes read-only tools from
  side-effectful ones in the registry / tool descriptions.
- Same consent state covers both read and write actions (e.g. one
  approval at session start authorises every subsequent tool call,
  including destructive ones).
- Side-effect classification missing from the tool inventory built in
  Phase 0.4.

**Severity rubric:**
- **HIGH** — destructive or external-side-effect tools are callable by
  the model with no consent boundary distinct from read tools.
- **MEDIUM** — consent boundary exists but is granted globally at
  session start and not re-asserted per privileged action.
- **LOW** — read/write distinction exists but is not surfaced to the
  user UI clearly.

### 2.12  Multi-turn authority persistence

**Threat anchor:** elevated authority granted in one conversation turn
silently persists across later, unrelated turns, allowing prompt
injection or tool poisoning in turn N to exploit privileges that the
user only intended to grant for turn N − k.

**Inspect:**
- Tool-approval state stored at session level with no per-action expiry.
- Privileged scopes / capabilities granted on one task carrying
  unchanged into subsequent tasks initiated by the same session.
- No re-consent prompt when the conversation context shifts subject
  (different repo, different account, different tenant).
- No audit log of *when* an elevated capability was first authorised
  and what it was authorised for.
- Persistent "remember my choice" approvals with no TTL or revocation UX.

**Severity rubric:**
- **HIGH** — privileged tool approval persists across unrelated future
  turns without expiry or re-consent, and an attacker who controls
  later input can reach that capability.
- **MEDIUM** — approvals persist within a session but expire on
  session end, with no per-task scoping.
- **LOW** — approvals are per-task by default but there is no audit
  trail of when each was granted.

---

## 7. PHASE 3 — Pillar 3: Input Trust Boundary

> "Rigorous and dynamic input validation and sanitization help prevent
> prompt manipulation, while zero-trust models ensure continuous verification
> across every interaction." — SANS/AWS 2026, p.12

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

### 3.11  Resource URI trust

**Threat anchor:** MCP `resource://` references (or equivalent
resource identifiers) that escape their intended namespace and reach
arbitrary local files, internal URLs, or cross-tenant resources. This
is the MCP analogue of classic SSRF / path-traversal in resource
servers.

**Inspect:**
- Resource handlers accept user-controlled URIs without
  schema-allowlist enforcement (allowed schemes, allowed hosts,
  allowed path prefixes).
- Resource URIs can resolve to arbitrary filesystem paths
  (path-traversal: `..`, absolute paths, symlink-following).
- Resource URIs can resolve to internal-network URLs
  (`http://169.254.169.254/`, `http://localhost:*`,
  `http://10.*`, `http://*.svc.cluster.local`) — SSRF surface.
- No tenant / workspace / scope check on resource access — a request
  in tenant A can resolve a `resource://` from tenant B.
- Resource resolver follows redirects without re-validating the
  destination against the allowlist.

**Severity rubric:**
- **CRITICAL** — resource identifiers can escape the intended namespace
  to read cross-tenant or arbitrary-host resources.
- **HIGH** — resource resolver permits internal-network URIs / cloud
  metadata endpoints with no allowlist.
- **HIGH** — path-traversal possible in filesystem-backed resources.
- **MEDIUM** — allowlist exists but redirects are followed without
  re-validation.

### 3.12  Sensitive result reflection

**Threat anchor:** secrets, tokens, full filesystem paths, stack
traces, internal URLs, or PII contained in tool outputs are reflected
back into the model context (or to the user) without redaction. This
turns a benign tool-call into a data-exfiltration channel any time
the model is later asked to summarise or echo prior context.

**Inspect:**
- No redaction layer between tool output and the model's next prompt.
- Tool results containing OAuth tokens, API keys, or session
  identifiers are passed verbatim into the LLM context.
- Stack traces from tool errors include absolute filesystem paths,
  internal hostnames, or DB connection strings.
- File-read tools return file contents that may contain credentials
  without any pattern-based redaction.
- HTTP-fetch tools surface request/response headers including
  `Authorization`, `Cookie`, `Set-Cookie`.
- PII (emails, phone numbers, IDs) in tool outputs not classified or
  filtered before reaching the model.

**Severity rubric:**
- **HIGH** — confirmed flow where tool outputs containing tokens /
  cloud-metadata / DB creds reach the model context unredacted.
- **HIGH** — error-path stack traces reflected into model context with
  internal infrastructure detail.
- **MEDIUM** — no redaction layer, but no concrete sensitive-data sink
  identified in current code paths.
- **LOW** — redaction layer exists but pattern set is narrow (e.g.
  catches `Authorization` but not `X-Api-Key`).

> **Phase 3 procedure note — taint-trace requirement:** every Phase 3
> finding above (3.1, 3.2, 3.3, 3.8, 3.10, 3.12) must record an
> explicit taint-trace in the finding's `evidence:` line:
>
>     source  → transformation → sink
>
> where:
>
>   - **source** = web fetch result, user upload, tool output, MCP
>     resource read, env var, file read, etc.
>   - **transformation** = LLM processing, string concat, template
>     interpolation, schema validation, redaction layer, etc.
>   - **sink** = system prompt, tool argument, tool selection logic,
>     authorisation decision, final user-visible response, downstream
>     API call.
>
> The finding must also state whether each of the following is
> present: **schema validation** at the boundary, **integrity marking**
> on untrusted spans, **explicit trust-boundary crossing** in the
> code, **user re-consent** before privileged action.
>
> Without a concrete source/transformation/sink trace, downgrade the
> finding to `[QUESTION]` per 3.5.2 — speculative prompt-injection
> findings without a traceable flow are not actionable.

---

## 8. PHASE 4 — Pillar 4: Observability & Runtime

> "End-to-end observability built on standardized telemetry enables visibility
> into agent performance, usage, and anomalies. Privilege escalation
> guardrails should flag risky data or control flows, while runtime monitoring
> establishes behavioral baselines to detect anomalies." — SANS/AWS 2026, p.12

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

> **Scope note:** the SANS/AWS 2026 whitepaper acknowledges supply-chain
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

**All sources below are free and have a public, unauthenticated path.**
Two specific caveats on reachability and cost:

- **GitHub GraphQL `securityAdvisories`** is free but rate-limits unauth
  requests harshly (60/hr); set `GITHUB_TOKEN` for the 5,000/hr cap.
- **Sonatype OSS Index** anonymous batch usage is free up to a fair-use
  threshold; production volume requires a free account token.
- **CISA KEV's HTML catalogue page 403s automated agents** — use the
  JSON or CSV feed URLs in the Tier B table, both of which are
  unauthenticated and reliably reachable.
- **Vulhub, Exploit-DB, AttackerKB** sometimes geo-block or
  cloudflare-challenge automated agents from certain regions; if a
  fetch fails, fall back to the Tier A canonical source for the same
  CVE — no finding should depend on a single source's reachability.

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
| **CISA Known Exploited Vulnerabilities (KEV)** | JSON: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json · CSV: https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv | CVEs confirmed exploited in the wild — auto-CRITICAL if a dep is affected. The HTML catalogue page 403s automated agents; use the JSON or CSV feed instead. |
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

**Tier C+ — Efficient bulk APIs** (prefer these for scale — one HTTP
call covers many packages, vs. one fetch per package on the per-package
GitHub Advisory pages):

| Source | URL | Coverage |
|---|---|---|
| **OSV.dev batch query** | `POST https://api.osv.dev/v1/querybatch` | Send a JSON array of `{package, version}` → batched advisories. Single request can cover the whole dep tree. |
| **GitHub GraphQL `securityAdvisories`** | `POST https://api.github.com/graphql` | API-paginated, filterable by `ecosystem`, `package`, `severity`, `publishedSince`. Needs a `GITHUB_TOKEN` (5,000 req/hr). The right tool when you need *all* advisories for an ecosystem — pulls the full ~5,000-advisory pip catalog without scraping 199 HTML pages. |
| **deps.dev (Google)** | https://api.deps.dev/v3 | Free Google API; multi-ecosystem package metadata + advisories + dependency graph. Per-package: `https://api.deps.dev/v3/systems/<eco>/packages/<pkg>/versions/<ver>`. |
| **GHSA bulk JSON** | https://github.com/github/advisory-database | Whole GitHub Advisory DB shipped as JSON files. Clone once (`git clone --depth 1`), grep offline — no rate limit, fully reproducible. |
| **Sonatype OSS Index** | https://ossindex.sonatype.org/api/v3/component-report | Free REST API; batch endpoint accepts up to 128 PURL identifiers per call. |
| **AquaSec AVD** | https://avd.aquasec.com | Aggregator with strong container-image and Kubernetes coverage; backs the `trivy` scanner. |
| **Trivy DB** | https://github.com/aquasecurity/trivy-db | Distributed as OCI; the same DB `trivy` ships with — usable offline. |

**Tier D — Ecosystem-specific advisory DBs** (query the matching tier
for each manifest detected in 5.1):

| Ecosystem | Source | URL |
|---|---|---|
| Python | PyPA Advisory Database | https://github.com/pypa/advisory-database |
| npm | npm Security Advisories | https://www.npmjs.com/advisories |
| Node.js runtime | Official Node.js vulnerability blog | https://nodejs.org/en/blog/vulnerability |
| Node.js runtime | OpenJS Foundation security | https://openjsf.org/blog |
| Rust | RustSec Advisory Database | https://rustsec.org/advisories |
| Ruby | Ruby Advisory DB | https://github.com/rubysec/ruby-advisory-db |
| Go | Go Vulnerability DB | https://pkg.go.dev/vuln |

> Note for Node.js audits: npm-package CVEs and Node-runtime CVEs are
> distributed separately. A `node:*` runtime issue won't appear in
> `package-lock.json` advisory cross-references — check
> `https://nodejs.org/en/blog/vulnerability` against the Node version
> the project targets (read from `engines.node` in `package.json` or
> the project's `.nvmrc`).

**Tier E — Bug-bounty public-disclosure feeds** (catch issues that have
been responsibly disclosed but are not yet CVE-assigned):

| Source | URL |
|---|---|
| HackerOne Hacktivity | https://www.hackerone.com/hacktivity |
| Bugcrowd Disclosures | https://www.bugcrowd.com |

**Tier F — Emerging-threat news** (situational awareness for items not
yet in CVE feeds):

| Source | URL | Notes |
|---|---|---|
| The Hacker News | https://thehackernews.com | Daily security news; broad coverage. |
| Bleeping Computer | https://www.bleepingcomputer.com | Breach + vuln news, ransomware tracking. |
| Securelist (Kaspersky) | https://securelist.com | Threat-actor research, APT reports. |
| SANS Internet Storm Center | https://isc.sans.edu | Daily threat briefings; honeypot-derived signal. |
| Krebs on Security | https://krebsonsecurity.com | Investigative reporting on incidents. |

**Tier H — Real-time supply-chain attack detection** (catches malicious
packages, typosquats, and credential-stealers within minutes of publish
— before they show up in CVE feeds):

| Source | URL | Notes |
|---|---|---|
| Socket.dev | https://socket.dev | Free public scanner. Per-package: `https://socket.dev/<eco>/package/<pkg>`. Strong on npm and PyPI. Catches install-script abuse, typosquats, and behavioural anomalies. |
| OSSF Scorecard | https://securityscorecards.dev | Free, ranks repos on signed-releases, branch-protection, dangerous-workflows, etc. API: `https://api.securityscorecards.dev/projects/<repo>`. |
| OpenSSF Allstar | https://github.com/ossf/allstar | Continuous-policy scanner the OSSF runs against participating repos. |

**Tier G — Vendor / independent research disclosures** (often the first
place a high-impact bug appears, weeks before NVD assigns a CVE):

| Source | URL | Notes |
|---|---|---|
| AttackerKB (Rapid7) | https://attackerkb.com | Curated exploitability commentary — distinguishes "theoretical CVSS 9" from "actually weaponised tomorrow". |
| Google Project Zero | https://googleprojectzero.blogspot.com | Elite bug-finders; long-form root-cause analyses. |
| JFrog Security Research | https://research.jfrog.com/vulnerabilities | Independent research advisories, frequently catches typosquats and malicious packages. |
| Tenable Research | https://www.tenable.com/security/research | Vendor advisories, often early. |
| Wiz Threat Center | https://www.wiz.io/vulnerability-database | Strong on cloud-native and container-image issues. |
| Microsoft MSRC | https://msrc.microsoft.com | Authoritative for any Microsoft-published package or runtime. |

**Bulk ecosystem feeds — paginated GitHub Advisory walks** (catch advisories
that affect *transitive* deps not on the per-package page list, and
near-real-time disclosures the per-package crawl will miss):

| Ecosystem | Paginated URL (sort by published, newest first) |
|---|---|
| pip (Python)  | https://github.com/advisories?query=ecosystem%3Apip&sort=published-desc |
| npm           | https://github.com/advisories?query=ecosystem%3Anpm&sort=published-desc |
| Maven         | https://github.com/advisories?query=ecosystem%3Amaven&sort=published-desc |
| RubyGems      | https://github.com/advisories?query=ecosystem%3Arubygems&sort=published-desc |
| crates.io     | https://github.com/advisories?query=ecosystem%3Arust&sort=published-desc |
| Go            | https://github.com/advisories?query=ecosystem%3Ago&sort=published-desc |
| NuGet         | https://github.com/advisories?query=ecosystem%3Anuget&sort=published-desc |
| Composer (PHP)| https://github.com/advisories?query=ecosystem%3Acomposer&sort=published-desc |

**Procedure for bulk ecosystem walk:**

1. For each ecosystem detected in 5.1, fetch page 1 of the paginated URL
   above. Extract every advisory row: `(GHSA, CVE, package, affected
   versions, severity, published date)`.
2. If the oldest advisory on the page is **newer than the cutoff** (default
   90 days), fetch page 2 by appending `&page=2`. Repeat until either:
   - the oldest advisory on the page is older than the cutoff, or
   - 10 pages have been walked (hard cap to avoid runaway crawls).
3. Build an in-memory map: `package → [advisories]`.
4. Cross-reference the map against the **dep inventory from 5.1** —
   direct *and* transitive deps. Any installed version inside an advisory's
   affected range becomes a 5.2 finding.
5. **Prefer Tier C+ for scale.** If the dep tree is large (>50 packages),
   skip steps 1-4 and use a single OSV.dev `querybatch` POST instead — it
   returns the same data in one round trip with no rate-limit concerns.

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

**npmjs.com per-package Security tab** — for any npm package, the
official registry page exposes a built-in `Security` tab integrated
with Snyk data:

```
https://www.npmjs.com/package/<pkg>?activeTab=security
```

This is free, unauthenticated, and shows known vulns + dep issues +
a package-health score in a single fetch. Use this as the per-package
fallback for npm deps when the GitHub Advisory page returns sparse
results — Snyk often has coverage GHSA does not.

**Procedure for each direct dependency:**

> **Optimisation:** before walking per-package, do *one* Tier C+ batch call
> (OSV.dev `querybatch` or Sonatype OSS Index batch) covering the entire
> dep inventory from 5.1. That single call usually surfaces 80%+ of the
> findings; the per-package walk below then targets only the residual.

1. **Tier C+ batch** (preferred entry point) — POST the full
   `{package, version}` list to https://api.osv.dev/v1/querybatch.
   Record every returned advisory.
2. **Bulk ecosystem walk** — for each ecosystem in 5.1, walk the paginated
   GitHub Advisory feed (procedure above) back to the cutoff. Catches
   transitive-dep issues missed by per-package crawling.
3. **Tier A query** — for direct deps with no Tier C+ hit, fetch from at
   least one canonical source (NVD, MITRE CVE, GitHub Advisory DB,
   OSV.dev). Example: `https://github.com/advisories?query=<pkg>+ecosystem%3A<eco>`.
4. **Tier B query** — cross-reference against CISA KEV (auto-escalate to
   CRITICAL if the CVE is on the KEV list); check Exploit-DB for public
   PoC code (escalate severity if weaponised exploit exists).
5. **Tier C / Tier D** — query an aggregator (Snyk, OpenCVE, AquaSec AVD)
   and the matching ecosystem-specific source (PyPA, npm advisories,
   RustSec, etc.) to catch advisories not yet propagated to Tier A.
6. **Tier E (optional)** — for high-traffic / high-sensitivity packages,
   scan HackerOne Hacktivity for not-yet-CVE-assigned disclosures.
7. **Tier G (optional)** — for high-impact packages, sweep AttackerKB for
   exploitability commentary that may upgrade severity beyond raw CVSS.
8. **Per-package page** — if the package is on the high-profile list
   below, additionally fetch its dedicated security-advisories page.
9. Compare the **installed version** against advisory affected-version
   ranges.
10. Record any matching advisories with full URL and CVE ID.

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

### 5.7  CI/CD and release-pipeline security

**Threat anchor:** the build/release pipeline is the highest-leverage
attack surface in the modern software supply chain. A compromise here
ships malicious artifacts to every consumer of the package, often
signed and provenance-stamped by the legitimate org. Anchored to NIST
SP 800-218 (SSDF) and SLSA framework Levels 1–4.

**Inspect:**
- GitHub Actions / GitLab CI / CircleCI / other pipelines reference
  third-party actions by **mutable refs** (`@main`, `@v1`, branch
  names) rather than pinned commit SHAs.
- Release workflows triggerable from **untrusted contexts**: PRs from
  forks with access to release secrets, unprotected branches with
  publish permissions, manual `workflow_dispatch` available to
  non-maintainers.
- Secrets injected into PR builds from forks (`pull_request_target`
  misuse, `secrets:` scoped too broadly).
- Release workflow not restricted to **protected branches / signed
  tags** with required reviewers.
- Package publish step **not gated by trusted publishing / OIDC**
  (npm provenance attestations, PyPI Trusted Publishers, Sigstore).
- Build artifacts produced from a **local workstation** rather than a
  reproducible CI environment.
- Pipeline executes `curl | bash`, `wget | sh`, or downloads-and-runs
  remote scripts without integrity verification (`--checksum`,
  `sha256sum -c`, signed releases).
- `package-lock.json` / `poetry.lock` / `Cargo.lock` not honoured at
  install time in CI (e.g. CI runs `npm install` not `npm ci`).
- Workflow file permissions: `contents: write`, `id-token: write`,
  `packages: write` granted at the workflow level rather than the
  job level that needs them.

**Grep targets:**
```
uses:\s+\S+@(main|master|HEAD|v\d+\s*$)
pull_request_target
permissions:\s*write-all
npm install\b(?! --omit)
```

**Severity rubric:**
- **CRITICAL** — package publishing can be triggered from an
  untrusted PR context (fork PR can reach release secrets) or from
  an unprotected branch.
- **HIGH** — third-party CI actions referenced by mutable refs in a
  release workflow.
- **HIGH** — release published from local/manual process with no
  CI-side provenance attestation.
- **MEDIUM** — CI exists, but no artifact attestation, no signed
  releases, and no protected-tag gate.
- **MEDIUM** — `npm install` (instead of `npm ci`) in CI build/test.

### 5.8  Install-time and runtime dangerous behaviour

**Threat anchor:** dependencies (or the project itself) execute
arbitrary code at install time, at import, or at first use — this
runs *before* any sandbox or scanner you would otherwise rely on. The
classic supply-chain weaponisation point: malicious package versions
exfiltrate or persist via install hooks. Tools like Socket.dev (5.2,
Tier H) catch many of these but the audit must inspect the project's
own pipeline too.

**Inspect:**
- npm `preinstall`, `install`, `postinstall` scripts in
  `package.json` of direct deps **and** the project itself; flag any
  that invoke shell, network, filesystem outside the package
  directory, or download-and-execute.
- Python dynamic build backends (`pyproject.toml` `build-backend` set
  to a remote / unfamiliar backend); legacy `setup.py` that runs
  shell, `subprocess`, or network during install.
- Cargo `build.rs` scripts performing network or shell operations
  beyond local code generation.
- Go `go generate` directives invoking shell during build.
- Application code uses `eval`, `exec`, `Function(...)`, `vm.runIn*`,
  Python `exec` / `eval` / `compile`, or `subprocess` /
  `child_process` with arguments that include untrusted input.
- Dynamic plugin / extension loading from remote URLs without
  integrity verification.
- Download-and-execute patterns at startup
  (`urllib.request.urlopen(...).read() ; exec(...)`,
  `fetch(...).then(eval)`).
- Native add-ons (`*.node`, `*.so`) downloaded at install time without
  hash verification.

**Severity rubric:**
- **CRITICAL** — remote code fetched and executed at install or
  startup without integrity verification.
- **HIGH** — install / postinstall scripts execute shell or network
  operations not required for the build.
- **HIGH** — untrusted input reaches `eval` / `exec` / `Function` /
  subprocess in application code.
- **MEDIUM** — dynamic plugin loading without integrity controls,
  even if currently sourced from a trusted location.
- **MEDIUM** — native add-on download at install time without checksum
  pinning.

### 5.9  Supply-chain ownership & maintainership risk (technical-signal model)

> **Relationship to 5.3:** 5.3 frames jurisdictional risk via
> sanctions / export-control frameworks — a *compliance* lens, often
> driven by the deploying entity's legal posture. 5.9 frames
> ownership/maintainership risk via *technical signals visible in the
> repo and registry*. Both can fire on the same package; they are
> orthogonal lenses, not duplicates. Per the methodology framework
> (3.5.1, 3.5.2), 5.3 findings frequently land as `[QUESTION]
> [UNKNOWN]` because maintainer location is unverifiable from
> repo evidence alone, while 5.9 findings can reach `[CONFIRMED]`
> from registry metadata.

**Threat anchor:** account takeover of a maintainer; ownership
transfer followed by a malicious release; "trust-handoff" attacks
where a popular package changes hands and the new maintainer publishes
a backdoored version (historical: `event-stream`, `coa`, `rc`,
`ua-parser-js`, `ctx`).

**Inspect** (per direct dep, prefer registry API over scraping):
- **Maintainer turnover**: any maintainer added in the last 90 days
  with publish rights.
- **Ownership / scope transfer**: package owner or scope changed in
  the last 180 days.
- **Single privileged maintainer** with publish rights and no 2FA
  enforced (where the registry exposes 2FA status).
- **Release cadence anomalies**: long quiet period followed by a
  sudden release, especially with code-base churn.
- **New maintainer + suspicious release**: a new maintainer was added
  shortly before a release that introduces install hooks, network
  calls, or obfuscated code.
- **Release automation absent**: releases pushed manually from a
  workstation with no CI evidence.
- **Signing / provenance**: package releases unsigned and lacking
  Sigstore / npm-provenance / PyPI-trusted-publishing attestation.
- **Prior compromise history**: package has appeared in Snyk's malicious-
  package list, GitHub's malicious-packages advisories, or Socket.dev's
  alerts within the last 12 months.

**Severity rubric:**
- **CRITICAL** — confirmed malicious release, account takeover, or
  ownership transfer followed by demonstrably suspicious package
  behaviour. (Always fires regardless of compensating controls per
  3.5.7; this is also an auto-fail trigger candidate per 3.5.5.)
- **HIGH** — single privileged maintainer **and** unsigned releases
  **and** recent ownership change or anomalous release pattern.
- **MEDIUM** — single privileged maintainer without provenance /
  signing and low transparency, no recent anomaly.
- **LOW** — unsigned but stable project with multi-maintainer
  oversight (this is informational, not a defect — emit as
  `OBSERVATION` per 3.5.2).

**Reporting note:** jurisdictional signals (5.3) must remain in a
separate `Compliance / legal review note` block in the report. Never
infer a 5.9 finding from a 5.3 jurisdictional tier alone.

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

**Remediation quality rules** — every remediation entry must satisfy
all of the following:

1. **Minimal but actionable.** State the smallest change that closes
   the threat. A header flag beats a refactor when both suffice.
2. **Proportional to the threat.** Do not recommend rearchitecture for
   a config issue. Do not recommend advanced controls (PBAC, micro-VM,
   AI-native detection) as the *baseline* fix for a flaw that has a
   simpler proven mitigation.
3. **Explicit about location.** Name the file, config block, or
   pipeline step the change applies to. "Tighten validation" is not
   a remediation; "set `additionalProperties: false` on the
   `tool_call_args` schema in `tools/schema.py:48`" is.
4. **Explicit about kind.** Tag each entry as one of:
   `code-change` / `config-change` / `pipeline-change` /
   `runtime-policy-change` / `process-change`. Pipeline and runtime
   changes are operational and require coordination beyond the repo.
5. **Honest about dependencies.** If a remediation requires an
   operational control the audit could not verify (e.g. "rotate
   refresh tokens at the IDP"), state explicitly that the fix has
   a runtime / IDP dependency outside the repo and link it to the
   relevant Manual Validation question.
6. **No fixes for non-findings.** If the finding became
   `[OBSERVATION]` or `[QUESTION]` under 3.5.2, it does not appear
   in the roadmap — it appears in the Manual Validation appendix.
7. **No invented controls.** Do not propose a control that the
   ecosystem doesn't ship (e.g. "enforce ETDI" when the SDK has no
   ETDI primitives) without flagging it as `Strategic — requires
   upstream protocol support`.

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
|              SANS/AWS 2026 agentic-AI threat taxonomy           |
|              + Supply Chain & Dependency Security extension     |
+=================================================================+

Path reviewed:          <abs / repo-relative path>
Target classification:  <server | client | host | agent | mix>
Deployment context:     <LOCAL_DEV | INTERNAL_SINGLE_USER |
                         INTERNAL_MULTI_USER | EXTERNAL_PRODUCTION>
Transports detected:    <STDIO | SSE-deprecated | StreamableHTTP>
Lockfiles available:    <yes | partial | no>
Web access at audit:    <yes | no>
Review classification:  <code-only | code+config | code+config+docs |
                         full deployment evidence>
Substeps executed:      <N> / 55
Substeps skipped:       <N>     reason: <not applicable to target>

AUTO-FAIL:              <none | <triggering condition per 3.5.5>>

Findings (scored):      <N total — C critical / H high / M medium / L low>
                        DEFECT  : <N>      RISK : <N>      GAP : <N>
Findings (unscored):    <N> — <N OBSERVATION + N QUESTION>
                        (see Manual Validation appendix below; per 3.5.3
                         these do NOT deduct from the trust score)

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

SAFE DEFAULTS SUMMARY
  Auth required by default:           <yes | no | unknown>
  Remote bind disabled by default:    <yes | no | unknown>
  TLS expected for remote use:        <yes | no | unknown>
  PKCE enforced on public clients:    <yes | no | unknown | n/a>
  Tool inputs schema-validated:       <yes | partial | no | unknown>
  Tool outputs integrity-marked:      <yes | no | unknown>
  User -> agent delegation bound:     <yes | no | unknown>
  Refresh tokens rotated + reuse-detected:  <yes | no | unknown>
  Outbound credentials JIT-issued:    <yes | no | unknown>
  Dependency lockfile present:        <yes | no>
  CI release protections present:     <yes | no | unknown>
  SBOM produced + attached to release: <yes | no | unknown>

  Decision rule: a row is "yes" only when CONFIRMED from repo
  evidence. CONFIG_CONFIRMED counts as "yes". DEPLOYMENT_ASSUMED or
  UNKNOWN renders as "unknown" — those become Manual Validation
  questions below.

MANUAL VALIDATION REQUIRED
  These items could not be verified from repository evidence alone.
  Each is a [QUESTION] [UNKNOWN] item per 3.5.2 / 3.5.1, and per 3.5.3
  none of them deduct from the trust score above. They are listed
  here so the deploying engineer can confirm or rebut each one before
  go-live.

  Runtime / deployment posture
    [ ] Is the production MCP endpoint exposed beyond loopback?
    [ ] Is TLS terminated before the MCP service?
    [ ] Are audit logs shipped to an immutable / append-only sink?
    [ ] Are refresh tokens rotated and reuse-detected in production?
    [ ] Are revocation checks enforced at token validation time?
    [ ] Are tool invocations subject to runtime authorisation checks?
    [ ] Are sandboxing / micro-VM guarantees enforced by the deploy
        platform?
    [ ] Is anomaly detection enabled in production telemetry?
    [ ] Is rate-limiting active on inbound MCP and auth endpoints?
    [ ] Are session-IDs bound to authenticated user identity at the
        gateway layer?
    [ ] Is `Last-Event-ID` integrity-checked on stream resumption?

  Supply chain / release posture
    [ ] Are SBOMs generated in CI and attached to releases?
    [ ] Are package signatures / provenance attestations verified
        in CI/CD before deploy?
    [ ] Is the release pipeline restricted to protected branches/tags?
    [ ] Is package publishing gated by trusted-publishing / OIDC?
    [ ] Is the lockfile honoured at install time in CI and prod?

  Identity / delegation posture
    [ ] Are outbound tokens audience-bound and short-lived in
        production?
    [ ] Is the identity provider's token-revocation feed consumed?
    [ ] Are JWT signing keys rotated on schedule with key-id pinning?
    [ ] Are user identity AND agent identity both present in the
        delegation token used for tool calls?

  Inferred items requiring confirmation
    [ ] Deployment context inferred as <classification> — confirm.
    [ ] Lockfile-derived dep tree assumed authoritative — confirm CI
        installs from the lockfile, not the manifest, in production.
    [ ] Maintainer jurisdictional notes (5.3) are compliance hints,
        not security findings — confirm with legal/compliance if the
        deploying entity has jurisdictional restrictions.

OPEN REVIEW QUESTIONS (additional UNKNOWN-confidence items)
  - <substep>: <one-line description>
  - ...

OPERATIONAL GAPS TO CONFIRM
  - <substep>: <one-line description of the gap and why repo can't
    verify it>
  - ...

+=================================================================+
| Vetted security tooling:                                        |
|   https://aws.amazon.com/marketplace/solutions/security/        |
|                                                                 |
| Source taxonomy:                                                |
|   SANS / AWS (2026) "Navigating modern application security     |
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
|   Bulk APIs:   OSV.dev querybatch, deps.dev, GHSA bulk JSON,    |
|                Sonatype OSS Index, AquaSec AVD, Trivy DB        |
|   Bug bounty:  HackerOne Hacktivity, Bugcrowd                   |
|   Vendor R&D:  AttackerKB, Project Zero, JFrog Research,        |
|                Tenable, Wiz, MSRC                               |
|   News:        The Hacker News                                  |
|   Bulk feeds:  GitHub Advisory paginated walks per ecosystem    |
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
