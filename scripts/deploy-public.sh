#!/bin/bash
set -euo pipefail

# === Zero-Trust Public Deploy (EC2-1) ===
# Deploys frontend, backend, and Envoy from docker-compose.public.yml
# Usage: ./deploy-public.sh [--skip-certs]

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
LOG_FILE="/var/log/zero-trust-deploy-public.log"
COMPOSE_FILE="$PROJECT_ROOT/infrastructure/docker/docker-compose.public.yml"

S3_BUCKET="${S3_BUCKET:-zero-trust-certs-$(date +%Y%m%d)}"
CERT_DIR="$PROJECT_ROOT/envoy/certs"

mkdir -p "$(dirname "$LOG_FILE")"
exec > >(tee -a "$LOG_FILE") 2>&1

log()  { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"; }
err()  { log "ERROR: $*"; }
info() { log "INFO: $*"; }

cleanup() {
  local exit_code=$?
  if [ $exit_code -ne 0 ]; then
    err "Deployment failed with exit code $exit_code"
  fi
  exit $exit_code
}
trap cleanup EXIT

# --- 1. Prerequisites ---
info "=== Step 1: Installing prerequisites ==="

if ! command -v docker &>/dev/null; then
  info "Installing Docker..."
  curl -fsSL https://get.docker.com | sh
  sudo usermod -aG docker "$USER"
  info "Docker installed. You may need to log out and back in for group changes."
fi

if ! docker compose version &>/dev/null; then
  info "Installing docker-compose-plugin..."
  sudo apt-get update -qq && sudo apt-get install -y -qq docker-compose-plugin
fi

# --- 2. Clone or update repo ---
info "=== Step 2: Ensuring repository is present ==="
if [ -d "$PROJECT_ROOT/.git" ]; then
  info "Repository exists, pulling latest..."
  git -C "$PROJECT_ROOT" pull --ff-only
else
  info "Cloning repository..."
  git clone <repo-url> "$PROJECT_ROOT"
fi

# --- 3. Fetch certificates from S3 ---
if [ "${1:-}" != "--skip-certs" ]; then
  info "=== Step 3: Fetching certificates from S3 ==="
  mkdir -p "$CERT_DIR"

  if aws s3 ls "s3://$S3_BUCKET/" &>/dev/null; then
    aws s3 sync "s3://$S3_BUCKET/" "$CERT_DIR/" --exclude "*" \
      --include "server.crt" \
      --include "server.key" \
      --include "server-chain.crt" \
      --include "root-ca.crt" \
      --include "intermediate-ca.crt" \
      --include "ca-chain.crt" \
      --include "client.crt" \
      --include "client.key" \
      --include "client-chain.crt"
    info "Certificates synced from s3://$S3_BUCKET/"
  else
    err "S3 bucket s3://$S3_BUCKET/ not found or not accessible"
    err "Run deploy-private.sh on EC2-2 first, or pass --skip-certs to deploy without certs"
    exit 1
  fi
else
  info "=== Step 3: Skipping certificate fetch (--skip-certs) ==="
fi

# --- 4. Deploy with Docker Compose ---
info "=== Step 4: Deploying services ==="
docker compose -f "$COMPOSE_FILE" pull
docker compose -f "$COMPOSE_FILE" up -d --build --remove-orphans

# --- 5. Health check ---
info "=== Step 5: Running health checks ==="
sleep 10

check_service() {
  local name="$1"
  local url="$2"
  local max_retries="${3:-12}"
  for i in $(seq 1 "$max_retries"); do
    if curl -sf --connect-timeout 2 --max-time 5 "$url" > /dev/null 2>&1; then
      info "  $name is healthy"
      return 0
    fi
    sleep 5
  done
  err "$name failed health check after $((max_retries * 5)) seconds"
  return 1
}

check_service "Envoy"    "http://localhost:10002/health" 12
check_service "Backend"  "http://localhost:8080/health"  12
check_service "Frontend" "http://localhost:3000"          6

info "=== Deployment complete ==="
info "Envoy mTLS endpoint: https://$(curl -sf http://169.254.169.254/latest/meta-data/public-hostname 2>/dev/null || echo 'localhost'):443"
