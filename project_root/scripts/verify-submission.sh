#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$PROJECT_ROOT/.." && pwd)"
REQUIRED_TAG="v1.0-submission"

echo "==> project root: $PROJECT_ROOT"

require_file() {
  local target="$1"
  if [ ! -e "$PROJECT_ROOT/$target" ]; then
    echo "MISSING: $target"
    return 1
  fi
  echo "OK: $target"
  return 0
}

require_dir() {
  local target="$1"
  if [ ! -d "$PROJECT_ROOT/$target" ]; then
    echo "MISSING: $target/"
    return 1
  fi
  echo "OK: $target/"
  return 0
}

run_check() {
  local label="$1"
  shift
  local log_file
  log_file="$(mktemp /tmp/zt-verifier-XXXXXX.log)"

  if "$@" >"$log_file" 2>&1; then
    echo "PASS: $label"
    rm -f "$log_file"
  else
    echo "WARN: $label (manual follow-up required)"
    echo "      see log: $log_file"

    if rg -q "snap-confine is packaged without necessary permissions|required permitted capability cap_dac_override" "$log_file"; then
      echo "      note: this environment blocks Docker permission checks (common in sandboxed setups)."
    elif rg -q "permission denied\\|Operation not permitted" "$log_file"; then
      echo "      note: permission issue while validating compose configuration."
    fi
  fi
}

require_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "MISSING_CMD: $cmd"
    return 1
  fi
  return 0
}

resolve_compose_cmd() {
  if command -v docker-compose >/dev/null 2>&1; then
    echo "docker-compose"
    return 0
  fi

  if command -v docker >/dev/null 2>&1; then
    if docker compose version >/dev/null 2>&1; then
      echo "docker compose"
      return 0
    fi
  fi

  return 1
}

count=0
missing=0

for artifact in \
  "Timeline.md" \
  "docs/quickstart.md" \
  "docs/demo-script.md" \
  "docs/submission-evidence-matrix.md" \
  "ext_authz/main.go" \
  "ext_authz/internal/auth/jwt.go" \
  "ext_authz/internal/cache/replay.go" \
  "tests/run-all.sh" \
  "tests/security/run-all-security.sh" \
  "tests/functional/run-all-resilience.sh" \
  "docs/report/final-report.md" \
  "docs/security-evaluation.md" \
  "infra/docker-compose.yml" \
  "infra/services/echo/Dockerfile" \
  "infra/services/protected-api/Dockerfile"; do
  count=$((count + 1))
  require_file "$artifact" || missing=$((missing + 1))
done

if [ -f "$REPO_ROOT/docker-compose.yml" ]; then
  echo "OK: docker-compose.yml"
else
  echo "MISSING: docker-compose.yml"
  missing=$((missing + 1))
fi
count=$((count + 1))

for dir in \
  "ext_authz/internal/cache" \
  "docs/report" \
  "benchmarks/results" \
  "benchmarks/plots" \
  "benchmarks/scripts" ; do
  count=$((count + 1))
  require_dir "$dir" || missing=$((missing + 1))
done

if [ "$missing" -ne 0 ]; then
  echo
  echo "Missing required project artifacts: $missing/$count"
  exit 1
fi

echo
echo "==> checking compose validity"
if COMPOSE_CMD="$(resolve_compose_cmd)"; then
  run_check "root compose file syntax ($COMPOSE_CMD)" $COMPOSE_CMD -f "$REPO_ROOT/docker-compose.yml" config
  run_check "infra compose file syntax ($COMPOSE_CMD)" $COMPOSE_CMD -f "$PROJECT_ROOT/infra/docker-compose.yml" config
else
  echo "WARN: docker compose command not available; skipping compose syntax checks."
fi

echo
echo "==> Timeline status summary"
if command -v rg >/dev/null 2>&1; then
  pending=$(rg -n "^\\s*- \\[ \\]" "$PROJECT_ROOT/Timeline.md" | wc -l | tr -d " ")
  in_progress=$(rg -n "^\\s*- \\[~\\]" "$PROJECT_ROOT/Timeline.md" | wc -l | tr -d " ")
  echo "Checklist pending : $pending"
  echo "Checklist partial : $in_progress"
else
  echo "WARN: rg not installed; cannot summarize Timeline checklist."
fi

echo
echo "==> Release gate"
if require_cmd git; then
  if [ ! -w "$REPO_ROOT/.git" ]; then
    echo "WARN: git metadata directory is read-only in this environment."
    echo "      create the release tag in a writable workspace."
  fi
  if (cd "$REPO_ROOT" && git rev-parse --is-inside-work-tree >/dev/null 2>&1 && \
      git -C "$REPO_ROOT" tag -l "$REQUIRED_TAG" | tr -d '[:space:]' | grep -qx "$REQUIRED_TAG"); then
    echo "PASS: release tag $REQUIRED_TAG exists"
  else
    echo "WARN: release tag $REQUIRED_TAG not found"
    echo "      create with: git tag -a $REQUIRED_TAG -m \"Zero-Trust API Auth submission\""
  fi
else
  echo "WARN: git not installed; cannot verify release tag."
fi

echo
echo "==> Optional runtime verification commands"
echo "For clean-environment verification:"
echo "  cd \"$REPO_ROOT\" && ./project_root/scripts/run-clean-submission-checks.sh"
echo "Run: cd \"$REPO_ROOT\" && ${COMPOSE_CMD:-docker-compose} up --build -d"
echo "Run: cd \"$PROJECT_ROOT\" && ./tests/run-all.sh"
echo "Run: cd \"$PROJECT_ROOT\" && ./tests/security/run-all-security.sh"
echo "Run: cd \"$REPO_ROOT\" && ${COMPOSE_CMD:-docker-compose} down"

echo
echo "==> recommendation"
echo "Tag with: git tag -a v1.0-submission -m \"Zero-Trust API Auth submission\""
echo "Then push if required."
