#!/bin/bash
# ABOUTME: Pre-tool-use hook that blocks destructive MCP GitHub operations.
# ABOUTME: Companion to bash-guard.sh for unattended overnight runs.

set -euo pipefail

INPUT=$(cat)
TOOL=$(echo "$INPUT" | jq -r '.tool_name')

block() {
  echo "BLOCKED by mcp-github-guard: $1" >&2
  exit 2
}

case "$TOOL" in
  # Destructive — never unattended
  mcp__github__merge_pull_request)
    block "merge PR — requires human review" ;;
  mcp__github__fork_repository)
    block "fork repo — requires human decision" ;;
  mcp__github__create_repository)
    block "create repo — requires human decision" ;;

  # Allow safe read/write operations
  # mcp__github__create_pull_request  — allowed (agents create PRs)
  # mcp__github__create_pull_request_review — allowed (agents review)
  # mcp__github__add_issue_comment — allowed
  # mcp__github__create_issue — allowed
  # mcp__github__create_branch — allowed
  # mcp__github__get_* / mcp__github__list_* / mcp__github__search_* — allowed
  # mcp__github__update_issue — allowed (labels, assignees)
  # mcp__github__push_files — allowed (agents push code)
  # mcp__github__create_or_update_file — allowed
  # mcp__github__get_pull_request_* — allowed (read-only)
  # mcp__github__update_pull_request_branch — allowed (sync with base)
esac

exit 0
