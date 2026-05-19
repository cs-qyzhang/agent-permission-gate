#!/bin/bash
# Status line: model | directory | git branch | context remaining

input=$(cat)

# Check if jq is available; if not, use python as fallback
if command -v jq &>/dev/null; then
  model=$(echo "$input" | jq -r '.model.display_name // empty')
  cwd=$(echo "$input" | jq -r '.workspace.current_dir // empty')
  remaining=$(echo "$input" | jq -r '.context_window.remaining_percentage // 100')
else
  model=$(echo "$input" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('model',{}).get('display_name',''))" 2>/dev/null)
  cwd=$(echo "$input" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('workspace',{}).get('current_dir',''))" 2>/dev/null)
  remaining=$(echo "$input" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('context_window',{}).get('remaining_percentage',100))" 2>/dev/null)
fi

sep="\033[0;37m|\033[0m"
parts=""

add_part() {
  local label="$1" color="$2" value="$3"
  if [ -n "$value" ]; then
    if [ -n "$parts" ]; then
      parts="${parts} ${sep} "
    fi
    parts="${parts}\033[1;${color}m${label}${value}\033[0m"
  fi
}

if [ -n "$model" ]; then
  add_part "" "36" "$model"
fi

if [ -n "$cwd" ]; then
  dir=$(basename "$cwd")
  add_part "" "34" "$dir"
  branch=$(git -C "$cwd" --no-optional-locks rev-parse --abbrev-ref HEAD 2>/dev/null)
  add_part "" "33" "$branch"
fi

# Default to 100 if missing, null, or the literal string "None"
if [ -z "$remaining" ] || [ "$remaining" = "None" ] || [ "$remaining" = "null" ]; then
  remaining=100
fi
add_part "context left: " "32" "${remaining}%"

printf '%b' "$parts"

