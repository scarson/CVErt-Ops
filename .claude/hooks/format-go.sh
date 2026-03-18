#!/bin/bash
# ABOUTME: PostToolUse hook that auto-formats Go files after Edit/Write.
# ABOUTME: Runs goimports to fix import ordering and apply gofmt formatting.

set -euo pipefail

INPUT=$(cat)
FILE=$(echo "$INPUT" | jq -r '.tool_input.file_path // empty')

# Skip if no file path or not a .go file
[[ -z "$FILE" ]] && exit 0
[[ "$FILE" != *.go ]] && exit 0

# Skip if file doesn't exist (deleted or failed write)
[[ ! -f "$FILE" ]] && exit 0

# Format in place — goimports is a superset of gofmt
goimports -w "$FILE" 2>/dev/null || true

exit 0
