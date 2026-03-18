#!/bin/bash
# ABOUTME: PostToolUse hook that auto-formats Vue/TypeScript files after Edit/Write.
# ABOUTME: Runs prettier using the web/ project config for consistent formatting.

set -euo pipefail

INPUT=$(cat)
FILE=$(echo "$INPUT" | jq -r '.tool_input.file_path // empty')

# Skip if no file path
[[ -z "$FILE" ]] && exit 0

# Only format frontend file types
case "$FILE" in
  *.vue|*.ts|*.tsx|*.js|*.jsx|*.css) ;;
  *) exit 0 ;;
esac

# Skip if file doesn't exist (deleted or failed write)
[[ ! -f "$FILE" ]] && exit 0

# Resolve the web directory relative to the project
PROJECT_DIR="${CLAUDE_PROJECT_DIR:-/c/Users/Sam/Code/CVErt-Ops}"
WEB_DIR="$PROJECT_DIR/web"

# Only format files within the web/ directory (don't run prettier on backend JS configs)
# Normalize both paths for comparison
REAL_FILE=$(cd "$(dirname "$FILE")" 2>/dev/null && pwd)/$(basename "$FILE") || exit 0
if [[ "$REAL_FILE" != "$WEB_DIR"* ]]; then
  exit 0
fi

# Run prettier from web/ so it picks up the project's prettier config
cd "$WEB_DIR"
npx prettier --write "$FILE" 2>/dev/null || true

exit 0
