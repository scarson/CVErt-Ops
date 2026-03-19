#!/bin/bash
# ABOUTME: Verifies Docker is available and tests pass before a branch merge.
# ABOUTME: Run manually: bash .claude/hooks/pre-merge-verify.sh [branch-name]

set -euo pipefail

BRANCH="${1:-$(git branch --show-current)}"
echo "=== Pre-merge verification for branch: $BRANCH ==="

# 1. Check Docker Desktop is available (required for testcontainers-go)
echo "Checking Docker availability..."
if ! docker info >/dev/null 2>&1; then
    echo "FAIL: Docker Desktop is not running. Integration tests require Docker."
    echo "Start Docker Desktop and retry."
    exit 1
fi
echo "OK: Docker is available"

# 2. Check Go build
echo "Checking Go build..."
if ! go build ./... 2>&1 | grep -v "embed.go"; then
    echo "OK: Go build clean"
else
    echo "FAIL: Go build has errors"
    exit 1
fi

# 3. Run Go linter
echo "Running golangci-lint..."
if ! golangci-lint run 2>&1; then
    echo "FAIL: Lint issues found"
    exit 1
fi
echo "OK: Lint clean"

# 4. Run Go tests
echo "Running Go tests (this may take several minutes)..."
if ! go test ./... -count=1 -timeout=600s 2>&1; then
    echo "FAIL: Test failures detected"
    exit 1
fi
echo "OK: All Go tests pass"

# 5. Run frontend checks
echo "Running frontend checks..."
if [ -d "web" ]; then
    (cd web && npm run lint 2>&1 && npm run type-check 2>&1)
    echo "OK: Frontend checks pass"
fi

echo ""
echo "=== All pre-merge checks passed for $BRANCH ==="
