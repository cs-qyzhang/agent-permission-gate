# Technical Details

This document covers implementation details of the permission gate hook. For setup and usage instructions, see [README.md](README.md).

## Return Mechanism

- **Claude Code**: The hook always exits with code 0 and prints a JSON decision (`allow`/`ask`/`deny`) to stdout. Claude Code reads the JSON to determine the outcome.
- **Qoder**: The hook prints the same JSON for completeness, but uses exit code as the primary mechanism. Exit 0 means continue, exit 2 means block (used for `deny` decisions). `allow` and `ask` both exit 0.

## Qoder Tool Name Mapping

Qoder uses native tool names that differ from Claude Code's compatible names. The hook automatically normalizes them internally:

| Qoder native name | Claude Code compatible name |
|---|---|
| `run_in_terminal` | `Bash` |
| `read_file` | `Read` |
| `create_file` | `Write` |
| `search_replace` | `Edit` |
| `delete_file` | `DeleteFile` |
| `grep_code` | `Grep` |
| `search_file` | `Glob` |
| `list_dir` | `LS` |
| `task` | `Agent` |

This means the allowlists and classifiers reference the Claude Code compatible names, and the same logic applies regardless of which IDE is calling the hook.

## User Override Memory

### How it works

1. **PreToolUse**: LLM decides "ask" → a pending entry is recorded in the DB.
2. **PostToolUse**: The tool executes (user approved) → the pending entry is confirmed as a user override.
3. **Next LLM fallback**: The recent overrides are included in the prompt:
   ```
   ## Recent user overrides in this session
   Below are recent cases where the LLM classified a tool as "ask"
   but the user chose to execute it...
   1. Bash: npm install lodash
   2. Edit: file_path: /home/user/project/src/config.py
   ```

If the user denies a tool (no PostToolUse fires), the stale pending entry is cleaned up on the next PreToolUse invocation.

### Log and Database Files

Logs and SQLite databases are stored in the script's directory, with separate files per IDE:

| IDE | Log file | Database file |
|---|---|---|
| Claude Code | `permission-claude.log` | `permission_gate_memory_claude.db` |
| Qoder | `permission-qoder.log` | `permission_gate_memory_qoder.db` |

## Status Line

`statusline-command.sh` displays real-time info in Claude Code's status bar: current model, working directory, git branch, and context window remaining percentage.

Example output:

```
deepseek-v4-pro[1m] | agent-permission-gate | main | context left: 85%
```

### Configuration

Add a `statusLine` entry to `~/.claude/settings.json`:

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

## IDE Comparison

All three platforms use the same hook script, but they differ in how they send hook events:

| Aspect | Claude Code | Qoder CLI | Qoder IDE |
|---|---|---|---|
| **Config file** | `~/.claude/settings.json` | `~/.qoder/settings.json` (int'l) or `~/.qoder-cn/settings.json` (China) | `~/.qoder/settings.json` (int'l) or `~/.qoder-cn/settings.json` (China) |
| **`permission_mode`** | Always present (`default`/`acceptEdits`/`plan`/`auto`/`dontAsk`/`bypassPermissions`) | Always present (`acceptEdits`/`plan`/`auto`) | **Never present** |
| **`session_id`** | Always present | Always present | Present for **write/execute** tools only; **empty** for read-only tools (`read_file`, `list_dir`, `search_file`) |
| **`transcript_path`** | `~/.claude/.../transcript/...` | `~/.qoder{,-cn}/projects/.../<uuid>.jsonl` | Present only when `session_id` is present |
| **`tool_name`** | Native names (`Bash`, `Read`, `Write`, `Edit`) | Native names (`Bash`, `Read`) | Qoder native names (`run_in_terminal`, `read_file`, `search_replace`) — mapped internally |
| **`extra`** | Not present | Not present | Present (`branch`/`email`/`repo`/`request_time`) |
| **Return mechanism** | Exit 0 + JSON stdout | Exit 0/2 + JSON stdout | Exit 0/2 + JSON stdout |

Qoder has two editions: **International** (`~/.qoder`) and **China (通义灵码)** (`~/.qoder-cn`). Both editions behave identically; only the config directory differs. The hook treats both as `qoder` and shares the same log/database files.

### Mode Detection

- **Claude Code**: Reads `permission_mode` directly from the event.
- **Qoder CLI**: Reads `permission_mode` directly from the event.
- **Qoder IDE**: Reads `mode` (`chat`/`agent`) from the transcript file's first-line `session_meta` record. This only works for write/execute tools that carry a `transcript_path`. For read-only tools, falls back to `PERMISSION_GATE_QODER_MODE`.

### User Override Memory (SQLite)

- **Claude Code**: Fully functional (always has `session_id`).
- **Qoder CLI**: Fully functional (always has `session_id`).
- **Qoder IDE**: Only works for write/execute tools (~11% of calls). Read-only tools silently skip memory recording.

### Transcript File Locations

- **Claude Code**: `~/.claude/projects/<project>/transcript/<uuid>.jsonl`
- **Qoder CLI**: `~/.qoder{,-cn}/projects/-{cwd}/<uuid>.jsonl`
- **Qoder IDE**: `~/.qoder{,-cn}/projects/-{cwd}/transcript/<uuid>.jsonl`
