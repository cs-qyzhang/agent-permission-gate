# Claude Code Permission Gate

A PreToolUse hook for Claude Code that classifies tool calls and decides whether to allow, ask the user, or deny them.

## How It Works

1. **Deterministic allowlist** — Safe operations (read-only built-in tools, git status/diff/log, uv/pip/npm package management, linting, type checking, etc.) are allowed immediately with no latency.
2. **LLM fallback** — For uncertain cases, the hook sends a compact summary to a configured model (`claude-haiku-4-5-20251001` by default) for classification.
3. **No silent deny** — Dangerous actions become "ask" rather than "deny" by default. Explicit deny can be enabled with `CLAUDE_GATE_ENABLE_DENY=1`.

## Quick Start

```bash
cp .env.example .env
# Edit .env with your API key and model preferences
```

Then configure Claude Code (`~/.claude/settings.json`) to use the hook:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "*",
        "hooks": [
          {
            "type": "command",
            "command": "uv run --script ~/.claude/hooks/permission_gate.py",
            "timeout": 15,
            "statusMessage": "Checking tool permission"
          }
        ]
      }
    ]
  }
}
```

## Configuration (via `.env`)

| Variable | Description | Default |
|---|---|---|
| `ANTHROPIC_API_KEY` | API key for LLM fallback decisions | (required for LLM fallback) |
| `ANTHROPIC_BASE_URL` | Custom Anthropic-compatible API endpoint | `https://api.anthropic.com` |
| `CLAUDE_GATE_MODEL` | Model for fallback classification | `claude-haiku-4-5-20251001` |
| `CLAUDE_GATE_LOG` | Path for debug logs | (disabled if empty) |
| `CLAUDE_GATE_ENABLE_DENY` | Set to `1` to honor model-produced deny | `0` |
| `CLAUDE_GATE_LLM_TIMEOUT` | API timeout in seconds | `15` |

## What's Allowed by Default

- **Internal tools**: TaskCreate, Skill, AskUserQuestion, Plan mode, etc.
- **Web access**: WebFetch, WebSearch
- **Read-only built-in tools**: Read, Glob, Grep
- **Safe git commands**: status, diff, log, show, branch, blame, etc.
- **Python tooling**: `pytest`, `ruff check`, `mypy`, `black --check`, etc.
- **Package managers**: `uv sync/add/remove/pip install`, `npm install/ci/test`, `pnpm`, `yarn`
- **Read-only shell**: `ls`, `cat`, `head`, `tail`, `find` (no `-delete`/`-exec`), `grep`, `fd`, `rg`

## MCP Tool Allowlist

MCP tools are blocked by default. Add trusted tools in `~/.claude/permission_gate.json`:

```json
{
  "allowed_mcp_tools": ["mcp__context7__resolve-library-id"],
  "allowed_mcp_patterns": ["^mcp__context7__.*$"]
}
```
