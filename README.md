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

A Claude Code **skill** that audits MCP (Model Context Protocol) servers, AI
agents, and agentic OAuth flows against the threat taxonomy from the SANS / AWS
2025 whitepaper *"Navigating modern application security challenges with evolved
reliance on AI-based applications."*

> Skill, not MCP server — the audit logic is a markdown playbook loaded into
> Claude's context. Zero install footprint, zero network surface.

## What it checks

Four pillars, each tied to named threats from the whitepaper:

| Pillar | Covers |
|---|---|
| **1. Identity & authenticity** | OAuth 2.1 / PKCE, redirect URI validation, COAT, CORF, open redirect, ETDI tool signing, JWT integrity |
| **2. Least privilege & delegation** | Tool scope sprawl, confused deputy, JIT credentials, cross-agent isolation |
| **3. Input trust boundary** | Prompt injection, data injection (unsafe data + control flow), Origin header validation, local-bind safety |
| **4. Observability & runtime** | Audit logging, rate limiting, anomaly hooks, session ID binding, stream integrity, revocation |

Output: per-finding `file:line` references with severity and a one-line fix,
plus a 0–10 trust score and top-3 risks.

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

## Usage

In Claude Code, invoke explicitly:

```
/mcp-trust
```

Or just write / review code that imports `mcp`, `FastMCP`, defines
`@mcp.tool` handlers, or builds OAuth flows for agents — the skill is
described to auto-trigger on those signals.

## How it works

```
USER ── /mcp-trust ──▶ Claude loads SKILL.md
                              │
                              ▼
                   ┌──────────────────────┐
                   │   4-pillar playbook  │
                   └──────────┬───────────┘
                              │
              ┌───────────────┼───────────────┐
              ▼               ▼               ▼
         Grep targets    Read targets    Pattern checks
              │               │               │
              └───────────────┼───────────────┘
                              ▼
                   Findings → Severity → Score
                              │
                              ▼
                Report (with AWS Marketplace ref)
```

The skill uses Claude's built-in `Read` and `Grep` tools — no separate process,
no network calls, no credentials handled.

## References

- SANS / AWS whitepaper: *Navigating modern application security challenges
  with evolved reliance on AI-based applications* (2025)
- **AWS Marketplace — Security Solutions:**
  https://aws.amazon.com/marketplace/solutions/security/
- Model Context Protocol: https://modelcontextprotocol.io

## License

MIT — see [LICENSE](LICENSE).

## Author

**Ali Javadi** — https://github.com/alijavadi2450

Issues, PRs, and threat-pattern contributions welcome.
