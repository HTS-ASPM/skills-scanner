# skills-scanner

Security scanner for AI agent skills, MCP servers, and agent harness configurations.

Part of [HTS-ASPM](https://github.com/HTS-ASPM). Pairs with [aibom](https://github.com/HTS-ASPM/aibom) — together they give you one inventory and one risk surface across AI components, models, datasets, agents, skills, and MCP tools.

## What it covers

| Surface | Examples |
|---|---|
| **Agent skills** | Anthropic Claude Skills (`SKILL.md`), agentskills.io packages, OpenClaw skills, Cursor rules, Windsurf rules |
| **MCP servers** | `claude_desktop_config.json`, `.mcp.json`, Cursor / Windsurf / Cline / VS Code MCP configs |
| **Harness configs** | `CLAUDE.md`, `.claude/settings.json`, hooks, slash commands, agent definitions, `.cursorrules`, `.windsurfrules` |

## Threat coverage (target)

Built around the issue catalog observed in the field:

- **Static code in skill bundle** — unsafe shell, secrets, eval/exec, **including bundled `tests/`, `examples/`, `fixtures/` directories** (a gap competing scanners share)
- **Natural-language attacks** — prompt injection, tool poisoning, hidden instructions (zero-width / unicode tag chars / HTML comments / RTL override), guidance injection
- **Capability / blast radius** — `allowed-tools` overscope, hooks that auto-execute, MCP servers without auth/scopes
- **Provenance & supply chain** — unsigned skill, unknown publisher, version drift / "rug pull"

Mapped to **OWASP MCP Top‑10**, **OWASP LLM Top‑10**, **MITRE ATLAS**, **NIST AI RMF**.

## Status

Pre-alpha. Phase **S0 — discovery + parsers** is in progress.

## Roadmap

| Phase | Deliverable |
|---|---|
| S0 | Skill / MCP / harness discovery across Claude / Cursor / Windsurf / Codex; SKILL.md + MCP schema parsers; inventory JSON |
| S1 | Tier‑0 static + secret + hidden-char rules; SARIF report; CI integration |
| S2 | NL judge + prompt-injection rules; OWASP MCP Top‑10 mapping |
| S3 | Capability / blast-radius graph; bundled-test execution-surface scan |
| S4 | Provenance + drift + policy (allowlist) |
| S5 | HTS-ASPM integration; allowlist UI; exec report |

## License

Apache-2.0
