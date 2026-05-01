#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.9"
# dependencies = ["anthropic"]
# ///

"""
Claude Code PreToolUse permission gate.

Policy:
- Always allow WebFetch / WebSearch.
- Allow MCP tools only when they match an allowlist.
- Allow common safe local commands, especially Python / uv test and lint commands.
- For uncertain cases, ask a configured Anthropic model to decide allow vs ask.
- Avoid direct deny by default. Dangerous or uncertain actions become ask.

Environment (can also be set via .env file in the script's directory):
- ANTHROPIC_API_KEY: required only for LLM fallback.
- ANTHROPIC_BASE_URL: optional base URL for custom Anthropic-compatible API.
- CLAUDE_GATE_MODEL: model for fallback; default: claude-haiku-4-5-20251001.
- CLAUDE_GATE_CONFIG: optional config JSON path.
- CLAUDE_GATE_ENABLE_DENY: set to "1" if you want model-produced deny to be honored.
- CLAUDE_GATE_LLM_TIMEOUT: API timeout seconds; default: 6.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


# ---------------------------------------------------------------------------
# .env loading
# ---------------------------------------------------------------------------

def _load_dotenv() -> None:
    """Load .env from the directory where this script lives. Does not override existing env vars."""
    script_dir = Path(__file__).resolve().parent
    env_path = script_dir / ".env"
    if not env_path.exists():
        return
    try:
        for line in env_path.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if "=" not in stripped:
                continue
            key, _, value = stripped.partition("=")
            key = key.strip()
            value = value.strip().strip("'\"")
            if key:
                os.environ[key] = value
    except Exception:
        pass


_load_dotenv()


# ---------------------------------------------------------------------------
# Basic config
# ---------------------------------------------------------------------------

PROJECT_DIR = Path(os.environ.get("CLAUDE_PROJECT_DIR") or os.getcwd())
DEFAULT_CONFIG_PATH = PROJECT_DIR / ".claude" / "permission_gate.json"

MODEL = os.environ.get("CLAUDE_GATE_MODEL", "claude-haiku-4-5-20251001")
BASE_URL = os.environ.get("ANTHROPIC_BASE_URL") or None
LLM_TIMEOUT = float(os.environ.get("CLAUDE_GATE_LLM_TIMEOUT", "15"))
ENABLE_DENY = os.environ.get("CLAUDE_GATE_ENABLE_DENY", "0") == "1"

# Keep stdout clean: Claude Code expects JSON decision output on stdout.
LOG_PATH = os.path.expanduser(os.environ.get("CLAUDE_GATE_LOG", ""))


DEFAULT_ALLOWED_MCP_TOOLS = {
    # Fill in exact MCP tool names you trust, for example:
    # "mcp__context7__resolve-library-id",
    # "mcp__context7__get-library-docs",
    # "mcp__sequential-thinking__sequentialthinking",
}

DEFAULT_ALLOWED_MCP_PATTERNS = [
    # Regex patterns. Keep these conservative.
    #
    # Examples:
    # r"^mcp__context7__.*$",
    # r"^mcp__sequential-thinking__.*$",
]


WEB_TOOLS = {
    "WebFetch",
    "WebSearch",
}

READ_ONLY_BUILTIN_TOOLS = {
    "Read",
    "Glob",
    "Grep",
    "LS",  # Some Claude Code versions / tool sets may expose LS.
}

# Purely internal tools that never touch the filesystem — always safe to allow.
INTERNAL_TOOLS = {
    "TaskCreate",
    "TaskGet",
    "TaskList",
    "TaskUpdate",
    "TaskOutput",
    "TaskStop",
    "Skill",
    "AskUserQuestion",
    "EnterPlanMode",
    "ExitPlanMode",
    "CronCreate",
    "CronDelete",
    "CronList",
    "ScheduleWakeup",
}


SENSITIVE_PATTERNS = [
    r"(^|/)\.env(\.|$|/)",
    r"(^|/)\.ssh($|/)",
    r"(^|/)id_rsa($|[.\s])",
    r"(^|/)id_ed25519($|[.\s])",
    r"(^|/)\.aws($|/)",
    r"(^|/)\.config/gh($|/)",
    r"(^|/)\.npmrc$",
    r"(^|/)\.pypirc$",
    r"(^|/)\.netrc$",
    r"credentials?",
    r"secrets?",
    r"private[_-]?key",
    r"api[_-]?key",
    r"access[_-]?token",
    r"refresh[_-]?token",
]


SHELL_CONTROL_PATTERNS = [
    "&&",
    "||",
    ";",
    "|",
    "`",
    "$(",
    ">",
    "<",
    "\n",
]


# ---------------------------------------------------------------------------
# Claude Code output helpers
# ---------------------------------------------------------------------------

def emit(decision: str, reason: str) -> None:
    """
    Emit Claude Code PreToolUse decision JSON and exit.

    decision must be one of: allow, ask, deny, defer.
    """
    print(json.dumps(
        {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": decision,
                "permissionDecisionReason": reason[:500],
            }
        },
        ensure_ascii=False,
    ))
    raise SystemExit(0)


def allow(reason: str) -> None:
    emit("allow", reason)


def ask(reason: str) -> None:
    emit("ask", reason)


def log_debug(message: str) -> None:
    if not LOG_PATH:
        return
    try:
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(message.rstrip() + "\n")
    except Exception:
        pass


def log_separator() -> None:
    """Write a timestamped separator line to the log at each invocation."""
    from datetime import datetime
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    sep = "-" * 40
    log_debug(f"\n{sep} [{ts}] {sep}")


# ---------------------------------------------------------------------------
# Config loading
# ---------------------------------------------------------------------------

def load_json_file(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:
        log_debug(f"Failed to read config {path}: {e}")
        return {}


def split_env_list(name: str) -> List[str]:
    raw = os.environ.get(name, "")
    if not raw.strip():
        return []
    return [x.strip() for x in raw.split(",") if x.strip()]


def load_config() -> Dict[str, Any]:
    config_path = Path(os.environ.get("CLAUDE_GATE_CONFIG") or DEFAULT_CONFIG_PATH)
    config = load_json_file(config_path)

    allowed_mcp_tools = set(DEFAULT_ALLOWED_MCP_TOOLS)
    allowed_mcp_tools.update(config.get("allowed_mcp_tools", []))
    allowed_mcp_tools.update(split_env_list("CLAUDE_GATE_ALLOWED_MCP_TOOLS"))

    allowed_mcp_patterns = list(DEFAULT_ALLOWED_MCP_PATTERNS)
    allowed_mcp_patterns.extend(config.get("allowed_mcp_patterns", []))
    allowed_mcp_patterns.extend(split_env_list("CLAUDE_GATE_ALLOWED_MCP_PATTERNS"))

    return {
        "allowed_mcp_tools": allowed_mcp_tools,
        "allowed_mcp_patterns": allowed_mcp_patterns,
    }


# ---------------------------------------------------------------------------
# Generic safety helpers
# ---------------------------------------------------------------------------

def json_text(obj: Any) -> str:
    try:
        return json.dumps(obj, ensure_ascii=False, sort_keys=True)
    except Exception:
        return str(obj)


def contains_sensitive_reference(text: str) -> bool:
    lowered = text.lower()
    return any(re.search(pattern, lowered) for pattern in SENSITIVE_PATTERNS)


def has_shell_control_operator(command: str) -> bool:
    return any(x in command for x in SHELL_CONTROL_PATTERNS)


def shlex_split(command: str) -> Optional[List[str]]:
    try:
        return shlex.split(command)
    except ValueError:
        return None


def starts_with(tokens: List[str], prefix: Iterable[str]) -> bool:
    prefix_list = list(prefix)
    return tokens[: len(prefix_list)] == prefix_list


# ---------------------------------------------------------------------------
# MCP allowlist
# ---------------------------------------------------------------------------

def is_mcp_tool(tool_name: str) -> bool:
    return tool_name.startswith("mcp__")


def mcp_allowed(tool_name: str, config: Dict[str, Any]) -> bool:
    if tool_name in config["allowed_mcp_tools"]:
        return True

    for pattern in config["allowed_mcp_patterns"]:
        try:
            if re.match(pattern, tool_name):
                return True
        except re.error:
            log_debug(f"Invalid MCP regex pattern ignored: {pattern!r}")

    return False


# ---------------------------------------------------------------------------
# Built-in tool classifiers
# ---------------------------------------------------------------------------

def classify_builtin_read_tool(tool_name: str, tool_input: Dict[str, Any]) -> Tuple[Optional[str], str]:
    """
    Return:
      ("allow", reason), ("ask", reason), or (None, reason)
    """
    if tool_name not in READ_ONLY_BUILTIN_TOOLS:
        return None, "Not a read-only built-in tool."

    payload = json_text(tool_input)
    if contains_sensitive_reference(payload):
        return None, "Read-like tool references a potentially sensitive path or token."

    return "allow", f"{tool_name} is a read-only built-in tool and input looks non-sensitive."


# ---------------------------------------------------------------------------
# Bash classifiers
# ---------------------------------------------------------------------------

def safe_git_command(tokens: List[str]) -> bool:
    if len(tokens) < 2 or tokens[0] != "git":
        return False

    safe_subcommands = {
        "status",
        "diff",
        "log",
        "show",
        "branch",
        "rev-parse",
        "ls-files",
        "grep",
        "blame",
        "remote",
        "describe",
        "tag",
    }

    sub = tokens[1]

    if sub not in safe_subcommands:
        return False

    # Avoid allowing operations that may reveal credentials or mutate state.
    joined = " ".join(tokens)
    unsafe_git_fragments = [
        " config ",
        " push ",
        " pull ",
        " fetch ",
        " clone ",
        " reset ",
        " checkout ",
        " switch ",
        " merge ",
        " rebase ",
        " commit ",
        " add ",
        " restore ",
        " clean ",
        " stash push",
        " stash pop",
        " stash apply",
    ]

    return not any(fragment in f" {joined} " for fragment in unsafe_git_fragments)


def safe_python_command(tokens: List[str]) -> bool:
    if not tokens:
        return False

    python_bins = {"python", "python3", "python3.9", "python3.10", "python3.11", "python3.12", "python3.13"}

    if tokens[0] in python_bins:
        if len(tokens) == 2 and tokens[1] in {"--version", "-V"}:
            return True

        if starts_with(tokens, [tokens[0], "-m", "pytest"]):
            return True

        if starts_with(tokens, [tokens[0], "-m", "unittest"]):
            return True

        if starts_with(tokens, [tokens[0], "-m", "compileall"]):
            return True

        # Do not auto-allow python -c or arbitrary script execution.
        return False

    if tokens[0] == "pytest":
        return True

    if tokens[0] == "ruff":
        # Allow read-only linting, not --fix.
        if len(tokens) >= 2 and tokens[1] == "check" and "--fix" not in tokens:
            return True
        if len(tokens) >= 2 and tokens[1] == "format" and "--check" in tokens:
            return True
        return False

    if tokens[0] in {"mypy", "pyright", "basedpyright", "pyre"}:
        return True

    if tokens[0] == "black":
        return "--check" in tokens

    if tokens[0] == "isort":
        return "--check-only" in tokens or "--check" in tokens

    if tokens[0] == "coverage":
        # coverage writes local .coverage data, but is normally safe validation.
        if starts_with(tokens, ["coverage", "run", "-m", "pytest"]):
            return True
        if starts_with(tokens, ["coverage", "report"]):
            return True
        if starts_with(tokens, ["coverage", "html"]):
            return True
        return False

    return False


def skip_safe_uv_run_flags(tokens: List[str], i: int) -> int:
    """
    For: uv run [safe flags] <command> ...
    Return index of actual command after uv run flags.

    Conservative: only skip flags that do not install dependencies or hit network.
    """
    safe_no_value_flags = {
        "--locked",
        "--frozen",
        "--no-sync",
        "--isolated",
    }

    while i < len(tokens):
        tok = tokens[i]

        if tok in safe_no_value_flags:
            i += 1
            continue

        # Stop at first non-flag; that is the actual command.
        if not tok.startswith("-"):
            return i

        # Unknown uv run flag: not auto-safe.
        return i

    return i


def safe_uv_command(tokens: List[str]) -> bool:
    if not tokens or tokens[0] != "uv":
        return False

    if len(tokens) == 1:
        return False

    # uv --version
    if len(tokens) == 2 and tokens[1] in {"--version", "-V", "version"}:
        return True

    # uv tree / uv pip list are read-only introspection.
    if tokens[1] == "tree":
        return True

    if starts_with(tokens, ["uv", "pip", "list"]):
        return True

    if starts_with(tokens, ["uv", "python", "list"]):
        return True

    if starts_with(tokens, ["uv", "lock"]) and "--check" in tokens:
        return True

    if tokens[1] == "run":
        cmd_index = skip_safe_uv_run_flags(tokens, 2)
        if cmd_index >= len(tokens):
            return False

        subcmd = tokens[cmd_index:]
        return safe_python_command(subcmd)

    # uv sync/add/remove/pip install — allowed for project-local environment management.
    if tokens[1] in {"sync", "add", "remove", "lock"}:
        return True

    if starts_with(tokens, ["uv", "pip", "install"]):
        return True

    if starts_with(tokens, ["uv", "pip", "uninstall"]):
        return True

    # uv tool install runs in an isolated env, but still allow.
    if starts_with(tokens, ["uv", "tool", "install"]):
        return True

    if starts_with(tokens, ["uv", "venv"]):
        return True

    return False


def safe_readonly_shell_command(tokens: List[str]) -> bool:
    if not tokens:
        return False

    base = tokens[0]

    trivial_safe = {
        "pwd",
        "date",
        "whoami",
        "uname",
        "hostname",
        "which",
        "command",
        "type",
        "true",
        "false",
    }

    if base in trivial_safe:
        return True

    read_only_commands = {
        "ls",
        "tree",
        "cat",
        "head",
        "tail",
        "wc",
        "du",
        "df",
        "file",
        "stat",
        "find",
        "fd",
        "rg",
        "grep",
    }

    if base in read_only_commands:
        # find can mutate via -delete / -exec.
        if base == "find" and any(t in tokens for t in {"-delete", "-exec", "-execdir", "-ok", "-okdir"}):
            return False

        # grep/rg/fd are read-only, but command payload may still be sensitive;
        # sensitive references were checked earlier.
        return True

    return False


def classify_bash(command: str) -> Tuple[Optional[str], str]:
    """
    Return:
      ("allow", reason), ("ask", reason), or (None, reason)

    None means use LLM fallback.
    """
    stripped = command.strip()

    if not stripped:
        return None, "Empty Bash command."

    if contains_sensitive_reference(stripped):
        return None, "Command references potentially sensitive files or tokens."

    if has_shell_control_operator(stripped):
        # Conservative: let LLM/user inspect pipelines, redirects, chaining, command substitution.
        return None, "Command contains shell control operators."

    tokens = shlex_split(stripped)
    if not tokens:
        return None, "Could not parse Bash command safely."

    if safe_git_command(tokens):
        return "allow", "Safe read-only git command."

    if safe_uv_command(tokens):
        return "allow", "Safe uv/Python validation or introspection command."

    if safe_python_command(tokens):
        return "allow", "Safe Python validation command."

    if safe_readonly_shell_command(tokens):
        return "allow", "Safe read-only shell command."

    if safe_npm_command(tokens):
        return "allow", "Safe npm project environment command."

    if safe_pnpm_yarn_command(tokens):
        return "allow", f"Safe {tokens[0]} project environment command."

    # Obvious risky operations: do not deny; ask or LLM fallback.
    risky_bases = {
        "rm",
        "mv",
        "cp",
        "chmod",
        "chown",
        "sudo",
        "su",
        "ssh",
        "scp",
        "rsync",
        "curl",
        "wget",
        "docker",
        "kubectl",
        "terraform",
        "git",
        "pip",
        "pipx",
        "make",
    }

    if tokens[0] in risky_bases:
        return None, f"{tokens[0]} command is not in the deterministic allowlist."

    return None, "Unknown Bash command."


def safe_npm_command(tokens: List[str]) -> bool:
    """Allow npm commands for project-local environment management."""
    if not tokens or tokens[0] != "npm":
        return False
    if len(tokens) < 2:
        return False

    safe_subcmds = {
        "install", "ci", "run", "exec", "start", "test",
        "build", "lint", "format", "info", "version", "list", "ls",
        "outdated", "view", "pack", "init",
    }
    if tokens[1] in safe_subcmds:
        return True

    return False


def safe_pnpm_yarn_command(tokens: List[str]) -> bool:
    """Allow pnpm/yarn commands for project-local environment management."""
    if not tokens:
        return False
    base = tokens[0]
    if base not in {"pnpm", "yarn"}:
        return False
    if len(tokens) < 2:
        return False

    safe_subcmds = {
        "install", "add", "remove", "run", "exec", "start", "test",
        "build", "lint", "format", "info", "version", "list", "ls",
        "outdated", "pack", "init",
    }
    if tokens[1] in safe_subcmds:
        return True

    return False


# ---------------------------------------------------------------------------
# LLM fallback
# ---------------------------------------------------------------------------

LLM_SYSTEM_PROMPT = """You are a strict permission classifier for Claude Code PreToolUse hooks.

You must return only compact JSON:
{"decision":"allow"|"ask","reason":"short reason"}

Policy:
- Prefer "allow" only when the tool call is clearly local, reversible, non-sensitive, and routine.
- Use "ask" when the action writes or overwrites files, changes git state, touches secrets, uses network from shell, deploys, changes permissions, deletes/moves files, runs unknown scripts, or is ambiguous.
- Code file modifications (Edit/Write) within the working directory that are related to the current task are ALLOW.
- Modifications to files outside the working directory are generally NOT allowed (ask), except for /tmp which is safe.
- Project-local environment commands (uv sync, uv add, uv pip install, npm install, npm ci, pnpm add, yarn install) are ALLOW — they only affect the current project's local environment.
- Running local Python scripts (e.g. python script.py, uv run python script.py) is generally ALLOW as long as it doesn't touch sensitive paths or credentials.
- WebFetch and WebSearch are allowed by user policy, but they should normally be handled before you see them.
- MCP tools are allowed only by explicit allowlist; if you see an unallowlisted MCP tool, prefer ask.
- The user prefers not to directly deny. Do not output deny.
- Tests, read-only lint checks, type checks, git status/diff/log/show, and non-sensitive file listing are usually allow.
- Commands like git push, git reset, docker, kubectl, terraform, sudo should be ask.
"""


def extract_text_from_anthropic_message(message: Any) -> str:
    parts: List[str] = []
    for block in getattr(message, "content", []) or []:
        text = getattr(block, "text", None)
        if text:
            parts.append(text)
    return "\n".join(parts).strip()


def parse_llm_json(text: str) -> Optional[Dict[str, Any]]:
    try:
        return json.loads(text)
    except Exception:
        pass

    match = re.search(r"\{.*\}", text, flags=re.DOTALL)
    if not match:
        return None

    try:
        return json.loads(match.group(0))
    except Exception:
        return None


def _read_transcript_file(path: str) -> List[Dict[str, Any]]:
    """Read a JSONL transcript file and return the list of message dicts."""
    try:
        messages = []
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                stripped = line.strip()
                if not stripped:
                    continue
                try:
                    messages.append(json.loads(stripped))
                except json.JSONDecodeError:
                    continue
        return messages
    except Exception:
        return []


def _get_msg_role(msg: Dict[str, Any]) -> Optional[str]:
    """Get message role, handling both flat {role:...} and nested {message:{role:...}}."""
    role = msg.get("role")
    if role:
        return role
    inner = msg.get("message")
    if isinstance(inner, dict):
        role = inner.get("role")
        if role:
            return role
    return None


def _get_msg_content(msg: Dict[str, Any]) -> Any:
    """Get message content, handling both flat and nested message formats."""
    content = msg.get("content")
    if content is not None and content != "":
        return content
    inner = msg.get("message")
    if isinstance(inner, dict):
        return inner.get("content", "")
    return ""


def extract_user_inputs(event: Dict[str, Any]) -> Tuple[Optional[Tuple[int, str]], Optional[List[Tuple[int, str]]]]:
    """Extract the first and most recent 3 user inputs from the conversation transcript.

    Returns ((turn, first_message), [(turn, recent_msg), ...]) where turn is the
    message index (1-based) in the transcript, so the LLM can distinguish rounds.
    """
    transcript = event.get("transcript") or event.get("messages") or event.get("conversation")
    if transcript is None:
        # Try reading from transcript_path (JSONL file)
        transcript_path = event.get("transcript_path")
        if transcript_path:
            transcript = _read_transcript_file(transcript_path)
    if not isinstance(transcript, list) or not transcript:
        log_debug("[EXTRACT] No transcript/messages/conversation found in event.")
        return None, None

    user_messages: List[Tuple[int, str]] = []
    turn = 0
    for msg in transcript:
        if not isinstance(msg, dict):
            continue
        turn += 1  # count every message to get the real conversation turn number
        if _get_msg_role(msg) != "user":
            continue
        content = _get_msg_content(msg)
        if isinstance(content, str) and content.strip():
            user_messages.append((turn, content.strip()))
        elif isinstance(content, list):
            text_parts = []
            for block in content:
                if isinstance(block, dict) and block.get("type") == "text":
                    text = block.get("text", "").strip()
                    if text:
                        text_parts.append(text)
            if text_parts:
                user_messages.append((turn, "\n".join(text_parts)))

    if not user_messages:
        log_debug("[EXTRACT] Transcript exists but no user messages found.")
        return None, None

    first = (user_messages[0][0], user_messages[0][1][:2000])
    recent = [(t, msg[:2000]) for t, msg in user_messages[-3:]]
    return first, recent


def llm_decide(event: Dict[str, Any], preliminary_reason: str) -> Tuple[str, str]:
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        return "ask", "No ANTHROPIC_API_KEY configured for LLM fallback."

    try:
        from anthropic import Anthropic
    except Exception as e:
        return "ask", f"Anthropic SDK unavailable: {e}"

    compact_event = {
        "tool_name": event.get("tool_name"),
        "tool_input": event.get("tool_input"),
        "cwd": event.get("cwd"),
        "preliminary_reason": preliminary_reason,
    }

    first_user, recent_users = extract_user_inputs(event)
    prompt_parts = ["Classify this Claude Code tool call.\n"]

    # Tell the LLM which round the conversation is currently at.
    current_turn = None
    if recent_users:
        current_turn = recent_users[-1][0]
    elif first_user:
        current_turn = first_user[0]
    if current_turn is not None:
        prompt_parts.append(f"Current conversation round: {current_turn}\n")
    if event.get("cwd"):
        prompt_parts.append(f"Project working directory: {event['cwd']}\n")

    if first_user:
        turn, msg_text = first_user
        prompt_parts.append(f'<user_message turn="{turn}">\n' + msg_text + "\n</user_message>\n")
    if recent_users:
        for turn, msg_text in recent_users:
            if first_user and msg_text == first_user[1]:
                continue
            prompt_parts.append(f'<user_message turn="{turn}">\n' + msg_text + "\n</user_message>\n")
    prompt_parts.append("<tool_request>\n" + json.dumps(compact_event, ensure_ascii=False, indent=2)[:12000] + "\n</tool_request>")
    prompt = "\n".join(prompt_parts)

    log_debug(f"[LLM] system prompt:\n{LLM_SYSTEM_PROMPT}")
    log_debug(f"[LLM] user prompt:\n{prompt}")

    try:
        client = Anthropic(api_key=api_key, base_url=BASE_URL, timeout=LLM_TIMEOUT, max_retries=0)
        response = client.messages.create(
            model=MODEL,
            max_tokens=512,
            temperature=0,
            system=LLM_SYSTEM_PROMPT,
            messages=[{"role": "user", "content": prompt}],
        )
        text = extract_text_from_anthropic_message(response)
        data = parse_llm_json(text)

        if not data:
            return "ask", "LLM fallback returned non-JSON output."

        decision = str(data.get("decision", "")).strip().lower()
        reason = str(data.get("reason", "LLM fallback decision.")).strip()

        if decision == "deny" and not ENABLE_DENY:
            return "ask", f"LLM suggested deny; downgraded to ask. Reason: {reason}"

        if decision not in {"allow", "ask", "deny"}:
            return "ask", f"Invalid LLM decision {decision!r}; asking user."

        if decision == "deny":
            return "deny", reason

        return decision, reason

    except Exception as e:
        return "ask", f"LLM fallback failed: {type(e).__name__}: {e}"


# ---------------------------------------------------------------------------
# Main decision flow
# ---------------------------------------------------------------------------

def decide(event: Dict[str, Any]) -> Tuple[str, str]:
    config = load_config()

    tool_name = str(event.get("tool_name", ""))
    tool_input = event.get("tool_input") or {}

    if not isinstance(tool_input, dict):
        return llm_decide(event, "Unexpected tool_input format.")

    # 1. Internal tools: always allow (no filesystem impact).
    if tool_name in INTERNAL_TOOLS:
        return "allow", f"{tool_name} is a purely internal tool, always safe."

    # 2. Web access: always allow.
    if tool_name in WEB_TOOLS:
        return "allow", "Web access is allowed by policy."

    # 3. MCP allowlist.
    if is_mcp_tool(tool_name):
        if mcp_allowed(tool_name, config):
            return "allow", f"MCP tool {tool_name} is in the allowlist."
        # Not in deterministic allowlist — let LLM decide.
        return llm_decide(event, f"MCP tool {tool_name} is not in the deterministic allowlist.")

    # 3. Read-only built-in tools.
    builtin_decision, builtin_reason = classify_builtin_read_tool(tool_name, tool_input)
    if builtin_decision:
        return builtin_decision, builtin_reason

    # 4. Bash command deterministic allowlist.
    if tool_name == "Bash":
        command = str(tool_input.get("command", ""))
        bash_decision, bash_reason = classify_bash(command)
        if bash_decision:
            return bash_decision, bash_reason

        # 5. Uncertain Bash: LLM fallback.
        return llm_decide(event, bash_reason)

    # 6. For edits/writes/agents/unknown tools, use LLM fallback.
    return llm_decide(event, "Tool is not covered by deterministic policy.")


def main() -> None:
    log_separator()
    try:
        raw = sys.stdin.read()
        event = json.loads(raw)
    except Exception as e:
        ask(f"Could not parse hook input JSON: {e}")
        return

    log_debug(f"[INPUT] {json.dumps(event, ensure_ascii=False)[:8000]}")

    try:
        decision, reason = decide(event)
    except Exception as e:
        decision, reason = "ask", f"Permission gate internal error: {type(e).__name__}: {e}"

    log_debug(f"[OUTPUT] decision={decision} reason={reason}")

    if decision == "allow":
        allow(reason)

    if decision == "deny":
        if ENABLE_DENY:
            emit("deny", reason)
        ask(f"Deny disabled; asking user instead. Reason: {reason}")

    ask(reason)


if __name__ == "__main__":
    main()
