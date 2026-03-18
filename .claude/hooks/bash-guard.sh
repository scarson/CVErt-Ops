#!/bin/bash
# ABOUTME: Pre-tool-use hook that blocks destructive Bash commands outside the project.
# ABOUTME: Designed for unattended overnight Agent Team runs with Bash(*) permission.

set -euo pipefail

PROJECT_DIR="${CLAUDE_PROJECT_DIR:?CLAUDE_PROJECT_DIR must be set}"
INPUT=$(cat)
CMD=$(echo "$INPUT" | jq -r '.tool_input.command')

# Normalize: collapse whitespace, trim
CMD_NORM=$(echo "$CMD" | tr -s '[:space:]' ' ' | sed 's/^ //;s/ $//')

block() {
  echo "BLOCKED by bash-guard: $1" >&2
  exit 2
}

# ── 1. Force-push protection ──────────────────────────────────────────────
if echo "$CMD_NORM" | grep -qiE 'git\s+push\s+.*--force|git\s+push\s+-f\b'; then
  block "force-push is never allowed unattended"
fi

# ── 2. Destructive git operations ─────────────────────────────────────────
if echo "$CMD_NORM" | grep -qiE 'git\s+reset\s+--hard'; then
  block "git reset --hard — use git stash or ask the user"
fi
if echo "$CMD_NORM" | grep -qiE 'git\s+clean\s+-[a-zA-Z]*f' && ! echo "$CMD_NORM" | grep -qiE 'git\s+clean\s+-[a-zA-Z]*n'; then
  block "git clean -f without -n (dry-run) — too destructive unattended"
fi
if echo "$CMD_NORM" | grep -qiE 'git\s+checkout\s+\.\s*$|git\s+restore\s+\.\s*$'; then
  block "git checkout/restore . discards all changes — too broad unattended"
fi
# Block branch deletion (git branch -D / -d, git push --delete)
# Allow: git worktree remove (worktree cleanup is fine)
if echo "$CMD_NORM" | grep -qiE 'git\s+branch\s+-[dD]\s'; then
  block "git branch -d/-D — branch deletion requires human decision"
fi
if echo "$CMD_NORM" | grep -qiE 'git\s+push\s+\S+\s+--delete\s'; then
  block "git push --delete — remote branch deletion requires human decision"
fi
if echo "$CMD_NORM" | grep -qiE 'git\s+push\s+\S+\s+:\S'; then
  block "git push origin :branch — remote branch deletion requires human decision"
fi

# ── 3. Dangerous rm patterns ─────────────────────────────────────────────
# Block rm -rf on root, home, or anything outside the project
if echo "$CMD_NORM" | grep -qE 'rm\s+-[a-zA-Z]*r[a-zA-Z]*f|rm\s+-[a-zA-Z]*f[a-zA-Z]*r'; then
  # Extract the path argument(s) after rm flags
  # Allow rm -rf only within the project directory
  RM_TARGETS=$(echo "$CMD_NORM" | grep -oE 'rm\s+-[a-zA-Z]+\s+(.+)' | sed 's/rm\s\+-[a-zA-Z]\+\s\+//')
  for target in $RM_TARGETS; do
    # Resolve relative paths
    case "$target" in
      /*|~*|C:*|/c/*)
        # Absolute path — check it's within project
        RESOLVED=$(echo "$target" | sed 's|\\|/|g; s|^C:|/c|i')
        if [[ "$RESOLVED" != "$PROJECT_DIR"* ]]; then
          block "rm -rf outside project directory: $target"
        fi
        ;;
      ..|../*)
        block "rm -rf with .. traversal: $target"
        ;;
      # Relative paths within CWD are fine (agent runs from project dir)
    esac
  done
fi

# Block rm on critical system paths regardless of flags
if echo "$CMD_NORM" | grep -qE 'rm\s+.*(/etc/|/usr/|/bin/|/sbin/|/var/|/tmp/\.\.|/home/|~/)'; then
  block "rm targeting system directory"
fi

# ── 4. Docker destruction (allow compose, block direct) ───────────────────
if echo "$CMD_NORM" | grep -qiE 'docker\s+system\s+prune'; then
  block "docker system prune — too destructive unattended"
fi
if echo "$CMD_NORM" | grep -qiE 'docker\s+(rm|rmi)\s' && ! echo "$CMD_NORM" | grep -qiE 'docker\s+compose'; then
  block "direct docker rm/rmi — use docker compose instead"
fi

# ── 5. System modification ───────────────────────────────────────────────
if echo "$CMD_NORM" | grep -qiE '^\s*sudo\s'; then
  block "sudo is never allowed unattended"
fi
# Block chmod/chown only when targeting absolute paths outside the project.
# Relative paths are fine — agent CWD is the project directory.
if echo "$CMD_NORM" | grep -qiE 'chmod\s|chown\s'; then
  CHMOD_TARGET=$(echo "$CMD_NORM" | grep -oiE '(chmod|chown)\s+\S+\s+(.+)' | awk '{print $NF}')
  case "$CHMOD_TARGET" in
    /*|~*|C:*|/c/*)
      RESOLVED=$(echo "$CHMOD_TARGET" | sed 's|\\|/|g; s|^C:|/c|i')
      if [[ "$RESOLVED" != "$PROJECT_DIR"* ]]; then
        block "chmod/chown outside project directory: $CHMOD_TARGET"
      fi
      ;;
  esac
fi

# ── 6. Process killing (allow specific, block broad) ─────────────────────
if echo "$CMD_NORM" | grep -qiE 'kill\s+-9\s|killall\s'; then
  block "kill -9 / killall — too dangerous unattended"
fi

# ── 7. Redirect overwrite outside project ────────────────────────────────
if echo "$CMD_NORM" | grep -qE '>\s*/(etc|usr|bin|home|var)/'; then
  block "redirect overwrite to system directory"
fi

# ── 8. GitHub CLI destructive operations ──────────────────────────────────
# Allow: gh pr create, gh pr view, gh pr list, gh api (read), gh run view
# Block: repo/branch deletion, PR merge, issue close, release delete
if echo "$CMD_NORM" | grep -qiE 'gh\s+repo\s+delete'; then
  block "gh repo delete — never allowed unattended"
fi
if echo "$CMD_NORM" | grep -qiE 'gh\s+pr\s+merge'; then
  block "gh pr merge — requires human review"
fi
if echo "$CMD_NORM" | grep -qiE 'gh\s+pr\s+close'; then
  block "gh pr close — requires human decision"
fi
if echo "$CMD_NORM" | grep -qiE 'gh\s+issue\s+close'; then
  block "gh issue close — requires human decision"
fi
if echo "$CMD_NORM" | grep -qiE 'gh\s+issue\s+delete'; then
  block "gh issue delete — never allowed unattended"
fi
if echo "$CMD_NORM" | grep -qiE 'gh\s+release\s+delete'; then
  block "gh release delete — never allowed unattended"
fi
if echo "$CMD_NORM" | grep -qiE 'gh\s+api\s+-X\s+(DELETE|PUT|PATCH)'; then
  block "gh api with mutating HTTP method — too risky unattended"
fi

# ── 9. curl | bash / eval patterns ───────────────────────────────────────
if echo "$CMD_NORM" | grep -qiE 'curl\s.*\|\s*(bash|sh|zsh)|wget\s.*\|\s*(bash|sh|zsh)'; then
  block "piping remote content to shell — too risky unattended"
fi

# ── 10. Python / scripting interpreters ───────────────────────────────────
# Pattern-matching python is a losing game — block it outright for unattended runs.
# The remediation tasks don't need python. Remove this rule if a future plan does.
if echo "$CMD_NORM" | grep -qiE '(^|\s|&&|\|\||;)\s*(python3?|python3\.exe)\s'; then
  block "python interpreter — too powerful to guard via pattern matching; not needed for current tasks"
fi

# All checks passed
exit 0
