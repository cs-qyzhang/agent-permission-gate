# AI Assistant Permission Gate

A PreToolUse / PostToolUse hook for **Claude Code** and **Qoder (通义灵码)** that classifies tool calls and decides whether to allow, ask, or deny them.

The script auto-detects the IDE (Claude Code, Qoder IDE, or Qoder CLI), reads the current permission mode, and adapts tool-name normalization, logging, and database paths accordingly.

> For implementation details — return mechanisms, tool name mapping, database schema, IDE-specific behavior — see [DETAILS.md](DETAILS.md).

## How It Works

1. **Deterministic allowlist** — Safe operations (reads, git status/diff/log, uv/pip/npm installs, linting, type checking, etc.) are allowed immediately with no latency.
2. **LLM fallback** — Uncertain cases (edits, writes, agents, unknown tools, ambiguous bash commands) are sent to a configured model for classification.
3. **No silent deny** — Dangerous actions become "ask" rather than "deny" by default. Explicit deny can be enabled with `PERMISSION_GATE_ENABLE_DENY=1`.

## Quick Start

```bash
# Install uv if you haven't already
curl -LsSf https://astral.sh/uv/install.sh | sh

# Clone the hook
git clone https://github.com/cs-qyzhang/agent-permission-gate.git ~/.claude/agent-permission-gate
cd ~/.claude/agent-permission-gate

# Configure
cp .env.example .env
# Edit .env with your API key and model preferences
```

Add the hook to your IDE's settings file:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "*",
        "hooks": [
          {
            "type": "command",
            "command": "uv run --script ~/.claude/agent-permission-gate/permission_gate.py",
            "timeout": 20
          }
        ]
      }
    ],
    "PostToolUse": [
      {
        "matcher": "*",
        "hooks": [
          {
            "type": "command",
            "command": "uv run --script ~/.claude/agent-permission-gate/permission_gate.py",
            "timeout": 10
          }
        ]
      }
    ]
  }
}
```

The PostToolUse hook is optional but recommended — it enables the **user override memory** feature.

Place the JSON above in the appropriate file for your platform:

| Platform | Settings file |
|---|---|
| **Claude Code** | `~/.claude/settings.json` |
| **Qoder IDE** (International) | `~/.qoder/settings.json` |
| **Qoder CN IDE** (China / 通义灵码) | `~/.qoder-cn/settings.json` |
| **Qoder CLI** (International) | `~/.qoder/settings.json` |
| **Qoder CN CLI** (China / 通义灵码) | `~/.qoder-cn/settings.json` |

**Qoder IDE prerequisite:** Set **Terminal in Agent Mode** to **Auto-run** in the IDE settings. This ensures the hook's `ask` decisions are handled properly rather than blocking indefinitely.

![Qoder IDE Auto-Run Settings](qoder-ide-settings.png)

## Configuration (via `.env`)

| Variable | Description | Default |
|---|---|---|
| `PERMISSION_GATE_LLM_API_KEY` | API key for LLM fallback decisions | (required for LLM fallback) |
| `PERMISSION_GATE_LLM_BASE_URL` | Custom Anthropic-compatible API endpoint | `https://api.anthropic.com` |
| `PERMISSION_GATE_MODEL` | Model for fallback classification | `claude-haiku-4-5` |
| `PERMISSION_GATE_CONFIG` | Path to JSON config file for MCP allowlists | `config.json` (in the script's directory) |
| `PERMISSION_GATE_ALLOWED_MCP_TOOLS` | Comma-separated extra MCP tool names to allow | (none) |
| `PERMISSION_GATE_ALLOWED_MCP_PATTERNS` | Comma-separated extra MCP regex patterns to allow | (none) |
| `PERMISSION_GATE_ENABLE_DENY` | Set to `1` to honor model-produced deny | `0` |
| `PERMISSION_GATE_LLM_TIMEOUT` | API timeout in seconds | `20` |
| `PERMISSION_GATE_QODER_MODE` | Fallback permission mode for Qoder when mode cannot be detected from transcript | `default` |
| `PERMISSION_GATE_DEBUG` | Set to `1` to dump raw hook input and environment to `debug_input.jsonl` | `0` |

## Permission Modes

The hook has **two policy tiers**: **Normal** and **Readonly**. The IDE's current permission mode determines which tier is applied.

### Default mapping

| Policy tier | Default modes | What is allowed |
|---|---|---|
| **Normal** | `auto`, `acceptEdits`, `dontAsk` | Standard development operations: editing, testing, package installs, etc. |
| **Readonly** | `plan`, `default` | Read/analysis only: no file modification or package installs |
| *(Pass-through)* | `bypassPermissions` | Hook does not intervene; IDE handles permission directly |

### Claude Code modes

| Mode | UI Name | Default tier |
|---|---|---|
| `default` | Ask before edits | **Readonly** |
| `acceptEdits` | Edit automatically | **Normal** |
| `plan` | Plan mode | **Readonly** |
| `auto` | Auto mode | **Normal** |
| `dontAsk` | — | **Normal** |
| `bypassPermissions` | Bypass permissions | *(Pass-through)* |

### Qoder modes

| Qoder mode | Detected from | Mapped mode | Default tier |
|---|---|---|---|
| **Ask/Chat** | Transcript `session_meta` | `default` | **Readonly** |
| **Agent** | Transcript `session_meta` | `auto` | **Normal** |

Qoder CLI sends permission modes directly (same values as Claude Code). If the transcript cannot be read, falls back to `PERMISSION_GATE_QODER_MODE`.

### Customizing the mapping

Edit `config.json` in the script's directory to change which modes map to which tier:

```json
{
  "normal_modes": ["auto", "acceptEdits", "dontAsk"],
  "readonly_modes": ["plan", "default"]
}
```

- Add a mode to `normal_modes` to apply the standard allowlist.
- Add a mode to `readonly_modes` to apply the stricter read-only policy.
- Remove a mode from both lists to let the IDE handle it directly (pass-through).

### Readonly policy details

When the current mode is in `readonly_modes`:

- **Write/Edit/NotebookEdit/DeleteFile** tools are always "ask".
- **Bash** only allows read-only commands (`ls`, `cat`, `grep`, `git status`/`diff`/`log`, etc.). Package managers, test runners, and code execution are NOT allowed.
- **WebSearch/WebFetch** are still allowed.
- **LLM fallback** uses a stricter prompt that rejects even commonly safe commands like `pytest` or `uv sync`.

## MCP Tool Allowlist

MCP tools are blocked by default. Add trusted tools in `config.json` (in the script's directory):

```json
{
  "allowed_mcp_tools": ["mcp__context7__resolve-library-id"],
  "allowed_mcp_patterns": ["^mcp__context7__.*$", "^mcp__serper-search.*$"]
}
```

You can also add tools via environment variables:
```bash
export PERMISSION_GATE_ALLOWED_MCP_TOOLS="mcp__context7__resolve-library-id"
export PERMISSION_GATE_ALLOWED_MCP_PATTERNS="^mcp__context7__.*$,^mcp__serper-search.*$"
```

MCP tools not in the allowlist fall through to LLM classification rather than being denied outright.

## LLM Fallback

When a tool call doesn't match any deterministic rule, the hook sends a compact summary to the configured model. The summary includes:

- The tool name and input
- The current working directory
- The first user message and up to 3 most recent user messages (with turn numbers)
- A preliminary reason for why deterministic classification was skipped

The LLM is instructed with a detailed system prompt covering allow/ask policies for file operations, git commands, network requests, privileged operations, and Agent/subagent tool use.

## User Override Memory

When the PostToolUse hook is configured, the permission gate tracks cases where the LLM classified a tool as "ask" but the user chose to execute it anyway. This history is stored per-session and per-permission-mode in a SQLite database in the script's directory. Separate databases are used for Claude Code and Qoder, and within each database overrides are keyed by permission mode — chat-mode approvals do not leak into agent-mode decisions.

See [DETAILS.md](DETAILS.md) for full implementation details.

## What's Allowed by Default

### Internal tools (always allowed)
TaskCreate, TaskGet, TaskList, TaskUpdate, TaskOutput, TaskStop, Skill, AskUserQuestion, EnterPlanMode, ExitPlanMode, CronCreate, CronDelete, CronList, ScheduleWakeup, TodoWrite

### Web access (always allowed)
WebFetch, WebSearch

### Read-only built-in tools
Read, Glob, Grep, LS (unless referencing sensitive paths: `.env`, `.envrc`, `.ssh/`, `id_rsa`, `.aws/`, `.kube/config`, `secrets.yml`, `credentials.json`, `.npmrc`, `.pypirc`, `.netrc`, `.docker/config.json`, `.vault-token`, `token.json`, `private_key`, `.pem`, etc.)

### Safe git commands
`status`, `diff`, `log`, `show`, `branch`, `rev-parse`, `ls-files`, `grep`, `blame`, `remote`, `describe`, `tag`

Note: Even these safe subcommands are escalated to LLM fallback if they contain unsafe fragments like `config`, `push`, `pull`, `fetch`, `clone`, `reset`, `checkout`, `switch`, `merge`, `rebase`, `commit`, `add`, `restore`, `clean`, `stash push/pop/apply`.

### Python/uv tooling
- **uv**: `sync`, `add`, `remove`, `lock`, `tree`, `pip list`, `pip install`, `pip uninstall`, `python list`, `tool install`, `venv`, `version`/`--version`, and `uv run` wrapping safe Python commands (below)
- **Test runners**: `pytest`, `python -m pytest`, `python -m unittest`, `coverage run -m pytest`, `coverage report`, `coverage html`
- **Linters/type checkers**: `ruff check` (without `--fix`), `ruff format --check`, `mypy`, `pyright`, `basedpyright`, `pyre`, `pylint`
- **Formatters (check-only)**: `black --check`, `isort --check-only`/`--check`

### Node.js package managers
`npm`, `pnpm`, `yarn` with subcommands: `install`, `ci`, `add`, `remove`, `run`, `exec`, `start`, `test`, `build`, `lint`, `format`, `info`, `version`, `list`, `ls`, `outdated`, `view`, `pack`, `init`

### Read-only shell commands
`ls`, `cat`, `head`, `tail`, `wc`, `du`, `df`, `file`, `stat`, `tree`, `find` (without `-delete`/`-exec`), `fd`, `rg`, `grep`, `pwd`, `date`, `whoami`, `uname`, `hostname`, `which`, `command`, `type`, `true`, `false`

Commands with shell control operators (`&&`, `||`, `|`, `;`, `` ` ``, `$()`, `>`, `<`, newlines) or references to sensitive paths are escalated to LLM fallback.

## Status Line

`statusline-command.sh` displays real-time info in the status bar: current model, working directory, git branch, and context window remaining percentage.

Example output:

```
deepseek-v4-pro[1m] | agent-permission-gate | main | context left: 85%
```

### Configuration

Add a `statusLine` entry to your IDE's settings file:

```json
{
  "statusLine": {
    "type": "command",
    "command": "bash ~/.claude/agent-permission-gate/statusline-command.sh"
  }
}
```

### Dependencies

- `jq` is recommended for JSON parsing
- Falls back to `python3` (bundled with most systems)

## Testing

```bash
# Run all tests (parse, normalize, and LLM integration)
uv run python test_permission_gate.py

# Parse and normalization tests only (no API key needed)
uv run python test_permission_gate.py --parse-only

# LLM integration tests only (requires PERMISSION_GATE_LLM_API_KEY)
uv run python test_permission_gate.py --llm-only

# Show raw API responses
uv run python test_permission_gate.py --verbose
```

The test suite covers:
- **Parse tests**: JSON extraction from 20 different malformed LLM outputs
- **Normalization tests**: Maps alternative field names from non-Anthropic APIs to `decision`/`reason`
- **LLM integration tests**: 20 real scenarios covering safe and dangerous tool calls
