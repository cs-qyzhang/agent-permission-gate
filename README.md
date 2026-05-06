# Claude Code Permission Gate

A PreToolUse hook for Claude Code that classifies tool calls and decides whether to allow, ask the user, or deny them.

## How It Works

1. **Deterministic allowlist** — Safe operations (internal tools, read-only built-in tools, git status/diff/log, uv/pip/npm package management, linting, type checking, read-only shell commands, etc.) are allowed immediately with no latency.
2. **LLM fallback** — For uncertain cases (edits, writes, agents, unknown tools, ambiguous bash commands), the hook sends a compact summary including recent user messages to a configured model (`claude-haiku-4-5` by default) for classification.
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
            "timeout": 20,
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
| `CLAUDE_GATE_MODEL` | Model for fallback classification | `claude-haiku-4-5` |
| `CLAUDE_GATE_CONFIG` | Path to JSON config file for MCP allowlists | `~/.claude/hooks/config.json` |
| `CLAUDE_GATE_ALLOWED_MCP_TOOLS` | Comma-separated extra MCP tool names to allow | (none) |
| `CLAUDE_GATE_ALLOWED_MCP_PATTERNS` | Comma-separated extra MCP regex patterns to allow | (none) |
| `CLAUDE_GATE_LOG` | Path for debug logs | (disabled if empty) |
| `CLAUDE_GATE_ENABLE_DENY` | Set to `1` to honor model-produced deny | `0` |
| `CLAUDE_GATE_LLM_TIMEOUT` | API timeout in seconds | `20` |

## What's Allowed by Default

### Internal tools (always allowed)
TaskCreate, TaskGet, TaskList, TaskUpdate, TaskOutput, TaskStop, Skill, AskUserQuestion, EnterPlanMode, ExitPlanMode, CronCreate, CronDelete, CronList, ScheduleWakeup

### Web access (always allowed)
WebFetch, WebSearch

### Read-only built-in tools
Read, Glob, Grep, LS (unless referencing sensitive paths like `.env`, `.ssh`, credentials, etc.)

### Safe git commands
`status`, `diff`, `log`, `show`, `branch`, `rev-parse`, `ls-files`, `grep`, `blame`, `remote`, `describe`, `tag` (excluding state-changing operations like push, commit, reset, checkout, merge, rebase, etc.)

### Python/uv tooling
- **uv**: `sync`, `add`, `remove`, `lock`, `tree`, `pip list`, `pip install`, `pip uninstall`, `python list`, `tool install`, `venv`, and `uv run` wrapping safe Python commands (below)
- **Test runners**: `pytest`, `python -m pytest`, `python -m unittest`, `coverage run -m pytest`, `coverage report`, `coverage html`
- **Linters/type checkers**: `ruff check` (without `--fix`), `ruff format --check`, `mypy`, `pyright`, `basedpyright`, `pyre`
- **Formatters (check-only)**: `black --check`, `isort --check-only`/`--check`

### Node.js package managers
`npm`, `pnpm`, `yarn` with subcommands: `install`, `ci`, `add`, `remove`, `run`, `exec`, `start`, `test`, `build`, `lint`, `format`, `info`, `version`, `list`, `ls`, `outdated`, `view`, `pack`, `init`

### Read-only shell commands
`ls`, `cat`, `head`, `tail`, `wc`, `du`, `df`, `file`, `stat`, `tree`, `find` (without `-delete`/`-exec`), `fd`, `rg`, `grep`, `pwd`, `date`, `whoami`, `uname`, `hostname`, `which`, `command`, `type`, `true`, `false`

Commands with shell control operators (`&&`, `||`, `|`, `;`, `` ` ``, `$()`, `>`, `<`, newlines) or references to sensitive paths are escalated to LLM fallback.

## Permission Modes

Claude Code has 6 permission modes that control how tool calls are approved. The hook receives the current mode in each event and can skip its custom logic for modes you trust, letting Claude Code's built-in permission system handle them instead.

| Mode | UI Name | What runs without asking |
|---|---|---|
| `default` | Ask before edits | Reads only |
| `acceptEdits` | Edit automatically | Reads, file edits, common filesystem commands |
| `plan` | Plan mode | Reads only (no source edits) |
| `auto` | Auto mode | Everything (with built-in classifier safety checks) |
| `dontAsk` | — | Only pre-approved tools via `permissions.allow` rules |
| `bypassPermissions` | Bypass permissions | Everything (no checks) |

Configure which modes activate the hook in `config.json`:

```json
{
  "enabled_modes": ["default", "acceptEdits", "plan"]
}
```

When the current mode is **not** in `enabled_modes`, the hook exits immediately with no output, and Claude Code's built-in permission system takes over. This avoids redundant LLM API calls in modes that already have their own safety mechanisms (e.g., `auto` mode's classifier).

If `enabled_modes` is omitted or empty, the hook runs in **all modes** (backward compatible).

## MCP Tool Allowlist

MCP tools are blocked by default. Add trusted tools in `~/.claude/hooks/config.json`:

```json
{
  "allowed_mcp_tools": ["mcp__context7__resolve-library-id"],
  "allowed_mcp_patterns": ["^mcp__context7__.*$", "^mcp__serper-search.*$"]
}
```

You can also add tools via environment variables:
```bash
export CLAUDE_GATE_ALLOWED_MCP_TOOLS="mcp__context7__resolve-library-id"
export CLAUDE_GATE_ALLOWED_MCP_PATTERNS="^mcp__context7__.*$,^mcp__serper-search.*$"
```

MCP tools not in the allowlist fall through to LLM classification rather than being denied outright.

## LLM Fallback

When a tool call doesn't match any deterministic rule, the hook sends a compact summary to the configured model. The summary includes:

- The tool name and input
- The current working directory
- The first user message and up to 3 most recent user messages (with turn numbers)
- A preliminary reason for why deterministic classification was skipped

The LLM is instructed with a detailed system prompt covering allow/ask policies for file operations, git commands, network requests, privileged operations, and Agent/subagent tool use. The model classifies subagent (Agent tool) requests based on the task description — code exploration, review, debugging, and standard development tasks are allowed; destructive or sensitive operations are escalated to "ask".

## Testing

```bash
# Run all tests (parse, normalize, and LLM integration)
uv run python test_permission_gate.py

# Parse and normalization tests only (no API key needed)
uv run python test_permission_gate.py --parse-only

# LLM integration tests only (requires ANTHROPIC_API_KEY)
uv run python test_permission_gate.py --llm-only

# Show raw API responses
uv run python test_permission_gate.py --verbose
```

The test suite covers:
- **Parse tests**: JSON extraction from 20 different malformed LLM outputs (markdown fences, text wrapping, nested braces, etc.)
- **Normalization tests**: Maps alternative field names from non-Anthropic APIs (MiniMax etc.) to `decision`/`reason`
- **LLM integration tests**: 20 real scenarios covering safe and dangerous tool calls, verifying the model returns valid JSON with correct decision/reason fields
