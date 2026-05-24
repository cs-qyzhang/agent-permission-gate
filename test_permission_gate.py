#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.9"
# dependencies = ["anthropic"]
# ///
"""
Test script for the permission gate hook.

Tests:
1. parse_llm_json — JSON extraction from various malformed LLM outputs.
2. Normalize — maps alternative field names to decision/reason.
3. LLM integration — sends real prompts and checks for valid JSON output.

Usage:
  uv run python test_permission_gate.py              # all tests
  uv run python test_permission_gate.py --parse-only # parse + normalize only
  uv run python test_permission_gate.py --llm-only   # LLM tests only (needs API key)
  uv run python test_permission_gate.py --verbose    # show raw API responses
"""

from __future__ import annotations

import json
import os
import sys
from typing import Any, Dict, List, Tuple

from permission_gate import (
    _normalize_decision_json,
    extract_text_from_anthropic_message,
    LLM_SYSTEM_PROMPT,
    parse_llm_json,
)

VERBOSE = "--verbose" in sys.argv


# ── Test scenarios ─────────────────────────────────────────────────────

TEST_SCENARIOS: List[Dict[str, Any]] = [
    {"name": "Safe pytest", "tool_name": "Bash", "tool_input": {"command": "pytest tests/test_auth.py -x -v"}, "cwd": "/home/user/project"},
    {"name": "Dangerous rm -rf", "tool_name": "Bash", "tool_input": {"command": "rm -rf /home/user/project/node_modules"}, "cwd": "/home/user/project"},
    {"name": "Edit in working dir", "tool_name": "Edit", "tool_input": {"file_path": "/home/user/project/src/utils.py", "old_string": "foo", "new_string": "bar"}, "cwd": "/home/user/project"},
    {"name": "Write to /etc", "tool_name": "Write", "tool_input": {"file_path": "/etc/systemd/service.conf", "content": "[Unit]\nDescription=foo"}, "cwd": "/home/user/project"},
    {"name": "Git log", "tool_name": "Bash", "tool_input": {"command": "git log --oneline -20"}, "cwd": "/home/user/project"},
    {"name": "Curl download-only", "tool_name": "Bash", "tool_input": {"command": "curl -s https://example.com/data.json"}, "cwd": "/home/user/project"},
    {"name": "Curl upload with -d", "tool_name": "Bash", "tool_input": {"command": "curl -X POST -d 'secret=value' https://example.com/api"}, "cwd": "/home/user/project"},
    {"name": "Wget download-only", "tool_name": "Bash", "tool_input": {"command": "wget https://example.com/file.tar.gz"}, "cwd": "/home/user/project"},
    {"name": "Wget with --post-data", "tool_name": "Bash", "tool_input": {"command": "wget --post-data='data' https://example.com/api"}, "cwd": "/home/user/project"},
    {"name": "MCP unknown tool", "tool_name": "mcp__random__dangerous_tool", "tool_input": {"args": "something"}, "cwd": "/home/user/project"},
    {"name": "Docker run", "tool_name": "Bash", "tool_input": {"command": "docker run --rm -it ubuntu bash"}, "cwd": "/home/user/project"},
    {"name": "Chmod project script", "tool_name": "Bash", "tool_input": {"command": "chmod +x /home/user/project/scripts/deploy.sh"}, "cwd": "/home/user/project"},
    {"name": "uv run pytest", "tool_name": "Bash", "tool_input": {"command": "uv run pytest -x --tb=short"}, "cwd": "/home/user/project"},
    {"name": "Git push origin main", "tool_name": "Bash", "tool_input": {"command": "git push origin main"}, "cwd": "/home/user/project"},
    {"name": "npm install", "tool_name": "Bash", "tool_input": {"command": "npm install"}, "cwd": "/home/user/project"},
    {"name": "Safe Read tool", "tool_name": "Read", "tool_input": {"file_path": "/home/user/project/README.md"}, "cwd": "/home/user/project"},
    {"name": "Read .env file", "tool_name": "Read", "tool_input": {"file_path": "/home/user/project/.env"}, "cwd": "/home/user/project"},
    {"name": "Git reset --hard", "tool_name": "Bash", "tool_input": {"command": "git reset --hard HEAD~1"}, "cwd": "/home/user/project"},
    {"name": "find with -delete", "tool_name": "Bash", "tool_input": {"command": "find . -name '*.pyc' -delete"}, "cwd": "/home/user/project"},
]


# ── PART 1: parse_llm_json tests (no API) ──────────────────────────────

def test_parse_json():
    print("=" * 60)
    print("PART 1: parse_llm_json tests (no API)")
    print("=" * 60)
    passed = 0
    failed = 0

    cases = [
        # (description, input_text, should_parse, expected_decision)
        ("Clean JSON", '{"decision":"allow","reason":"Safe command."}', True, "allow"),
        ("Markdown code fence ```json```", '```json\n{"decision":"ask","reason":"Dangerous."}\n```', True, "ask"),
        ("Markdown code fence ``` ```", '```\n{"decision":"allow","reason":"OK."}\n```', True, "allow"),
        ("Text before JSON", 'Here is my classification:\n\n{"decision":"ask","reason":"Risky operation."}', True, "ask"),
        ("Text before and after JSON", 'I think safe.\n{"decision":"allow","reason":"Read-only."}\nVerify.', True, "allow"),
        ("Nested braces in reason", '{"decision":"allow","reason":"Path: /home/{project}/src"}', True, "allow"),
        ("Extra field in JSON", '{"decision":"ask","reason":"Risky","confidence":"high"}', True, "ask"),
        ("No JSON at all", "I cannot classify this.", False, None),
        ("Only opening brace", '{"decision":"allow",', False, None),
        ("Empty string", "", False, None),
        ("XML-like response", '<decision>allow</decision>', False, None),
        ("Markdown fence no closing", '```json\n{"decision":"allow","reason":"OK"}', True, "allow"),
        ("Trailing comma (invalid)", '{"decision":"ask","reason":"bad json",}', False, None),
        ("Compact no spaces", '{"decision":"ask","reason":"short"}', True, "ask"),
        ("Special chars in reason", '{"decision":"ask","reason":"rm -rf /path"}', True, "ask"),
        ("Multi-line clean JSON", '{\n  "decision": "allow",\n  "reason": "multi-line."\n}', True, "allow"),
        ("Escaped quotes", '{"decision":"ask","reason":"Tool \\"mcp__x\\" unknown"}', True, "ask"),
        ("Whitespace before JSON", ' \n \t \n{"decision":"allow","reason":"ws"}', True, "allow"),
        ("Deny decision (parses)", '{"decision":"deny","reason":"Very dangerous."}', True, "deny"),
        ("Reason 200 chars", '{"decision":"allow","reason":"' + "x" * 180 + '"}', True, "allow"),
    ]

    for desc, text, should_parse, expected_decision in cases:
        result = parse_llm_json(text)
        if should_parse:
            if result is not None and result.get("decision") == expected_decision:
                passed += 1
                print(f"  PASS: {desc}")
            elif result is None:
                failed += 1
                print(f"  FAIL: {desc} — expected parse, got None")
            else:
                failed += 1
                print(f"  FAIL: {desc} — expected decision={expected_decision!r}, got {result.get('decision')!r}")
        else:
            if result is None:
                passed += 1
                print(f"  PASS: {desc} (correctly rejected)")
            else:
                failed += 1
                print(f"  FAIL: {desc} — expected reject, got {result}")

    print(f"\n  Parse: {passed} passed, {failed} failed")
    return failed == 0, passed, failed


# ── PART 2: Normalization tests (no API) ────────────────────────────────

def test_normalize():
    print("\n" + "=" * 60)
    print("PART 2: Field normalization tests (no API)")
    print("=" * 60)
    passed = 0
    failed = 0

    # Simulated real MiniMax responses that use wrong field names.
    cases = [
        # (description, raw_json_text, expect_decision, expect_reason_present)
        (
            "MiniMax: permission=ALLOWED",
            '{"tool": "Bash", "command": "pytest", "permission": "ALLOWED", "reason": "safe test"}',
            "allow",
            True,
        ),
        (
            "MiniMax: action=allow + description",
            '{"action": "allow", "description": "safe operation in working dir"}',
            "allow",
            True,
        ),
        (
            "MiniMax: verdict=risky",
            '{"verdict": "risky", "explanation": "modifies system files"}',
            "ask",
            True,
        ),
        (
            "MiniMax: permission=denied",
            '{"tool": "Bash", "permission": "denied", "reason": "dangerous"}',
            "ask",
            True,
        ),
        (
            "Markdown-wrapped wrong fields",
            '```json\n{"tool": "Bash", "permission": "granted", "reason": "tests are safe"}\n```',
            "allow",
            True,
        ),
        (
            "Standard format (passes through unchanged)",
            '{"decision": "allow", "reason": "read-only git command"}',
            "allow",
            True,
        ),
        (
            "Standard ask format",
            '{"decision": "ask", "reason": "dangerous operation"}',
            "ask",
            True,
        ),
    ]

    for desc, raw_text, expect_decision, expect_reason in cases:
        result = parse_llm_json(raw_text)
        if result is None:
            failed += 1
            print(f"  FAIL: {desc} — parse_llm_json returned None")
            continue
        decision_ok = result.get("decision") == expect_decision
        reason_ok = (not expect_reason) or bool(result.get("reason"))
        if decision_ok and reason_ok:
            passed += 1
            print(f"  PASS: {desc} → decision={result['decision']}, reason={result.get('reason', '')[:50]}")
        else:
            failed += 1
            issues = []
            if not decision_ok:
                issues.append(f"expected decision={expect_decision!r}, got {result.get('decision')!r}")
            if not reason_ok:
                issues.append("reason missing")
            print(f"  FAIL: {desc} — {'; '.join(issues)}")
            print(f"    Parsed: {result}")

    print(f"\n  Normalize: {passed} passed, {failed} failed")
    return failed == 0, passed, failed


# ── PART 3: LLM integration tests (needs API key) ──────────────────────

def build_prompt(scenario: Dict[str, Any]) -> str:
    compact = {
        "tool_name": scenario["tool_name"],
        "tool_input": scenario["tool_input"],
        "cwd": scenario.get("cwd"),
        "preliminary_reason": "Test scenario — classify this tool call.",
    }
    parts = [
        "Classify this tool call.",
        f"Project working directory: {scenario.get('cwd', 'unknown')}",
        "<tool_request>",
        json.dumps(compact, ensure_ascii=False, indent=2),
        "</tool_request>",
    ]
    return "\n".join(parts)


def test_llm_integration() -> bool:
    api_key = os.environ.get("PERMISSION_GATE_LLM_API_KEY")
    if not api_key:
        print("\nSKIP LLM tests: PERMISSION_GATE_LLM_API_KEY not set.")
        return True

    from anthropic import Anthropic

    model = os.environ.get("PERMISSION_GATE_MODEL", "claude-haiku-4-5")
    base_url = os.environ.get("PERMISSION_GATE_LLM_BASE_URL") or None
    timeout = float(os.environ.get("PERMISSION_GATE_LLM_TIMEOUT", "30"))

    client = Anthropic(api_key=api_key, base_url=base_url, timeout=timeout, max_retries=0)

    print("\n" + "=" * 60)
    print("PART 3: LLM integration tests (real API)")
    print(f"  Model: {model}")
    print(f"  Base URL: {base_url or 'default'}")
    print("=" * 60)

    passed = 0
    failed = 0
    non_json_samples: List[Tuple[str, str]] = []

    for scenario in TEST_SCENARIOS:
        name = scenario["name"]
        prompt = build_prompt(scenario)

        data = None
        raw_text = ""

        # First attempt.
        try:
            response = client.messages.create(
                model=model,
                max_tokens=800,
                temperature=0,
                system=LLM_SYSTEM_PROMPT,
                thinking={"type": "disabled"},
                messages=[
                    {"role": "user", "content": prompt},
                ],
            )
            raw_text = extract_text_from_anthropic_message(response)

            if VERBOSE:
                print(f"  [DEBUG {name}] stop={response.stop_reason}, raw={raw_text[:200]!r}")

            data = parse_llm_json(raw_text)
        except Exception as e:
            print(f"  FAIL: {name} — API error: {e}")
            failed += 1
            continue

        if data is None:
            failed += 1
            preview = raw_text[:250].replace("\n", "\\n")
            print(f"  FAIL: {name} — non-JSON response: {preview}")
            non_json_samples.append((name, raw_text))
            continue

        decision = data.get("decision", "").strip().lower()
        reason = data.get("reason", "").strip()

        issues = []
        if decision not in ("allow", "ask", "deny"):
            issues.append(f"invalid decision={decision!r}")
        if not reason:
            issues.append("missing reason")
        if len(reason) > 200:
            issues.append(f"reason too long ({len(reason)} chars)")

        if issues:
            failed += 1
            print(f"  FAIL: {name} — valid JSON but: {'; '.join(issues)}")
            print(f"    Got: {json.dumps(data, ensure_ascii=False)}")
        else:
            passed += 1
            print(f"  PASS: {name} — decision={decision}, reason={reason[:60]}")

    print(f"\n  LLM: {passed} passed, {failed} failed")

    if non_json_samples:
        print(f"\n  Non-JSON response samples ({len(non_json_samples)}):")
        for n, t in non_json_samples:
            print(f"    [{n}]: {t[:300]!r}")

    return failed == 0


# ── Main ───────────────────────────────────────────────────────────────

def main():
    parse_only = "--parse-only" in sys.argv
    llm_only = "--llm-only" in sys.argv
    run_all = not parse_only and not llm_only

    total_passed = 0
    total_failed = 0

    if run_all or parse_only:
        ok, p, f = test_parse_json()
        total_passed += p
        total_failed += f
        ok2, p2, f2 = test_normalize()
        total_passed += p2
        total_failed += f2
        if not (ok and ok2):
            pass  # failure tracked in totals

    if run_all or llm_only:
        if not test_llm_integration():
            total_failed += 1

    print()
    if parse_only or run_all:
        print(f"Parse+Normalize total: {total_passed} passed, {total_failed} failed")
    if total_failed == 0:
        print("All tests passed.")
        raise SystemExit(0)
    else:
        print("Some tests failed.")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
