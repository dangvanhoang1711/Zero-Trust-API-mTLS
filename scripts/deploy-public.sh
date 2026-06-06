#!/bin/bash
set -euo pipefail

# === Zero-Trust Edge Deploy (EC2-Envoy) ===
# Deploys frontend, backend, and Envoy from docker-compose.public.yml
# Usage: ./deploy-public.sh [--skip-certs]

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
LOG_FILE="${LOG_FILE:-$HOME/zero-trust-deploy-public.log}"
COMPOSE_FILE="$PROJECT_ROOT/infrastructure/docker/docker-compose.public.yml"

S3_BUCKET="${S3_BUCKET:-zero-trust-certs-$(date +%Y%m%d)}"
CERT_DIR="$PROJECT_ROOT/envoy/certs"
PRIVATE_EC2_PRIVATE_IP="${PRIVATE_EC2_PRIVATE_IP:-}"
KEYCLOAK_HTTPS_HOST_PORT="${KEYCLOAK_HTTPS_HOST_PORT:-8443}"
EXT_AUTHZ_PORT="${EXT_AUTHZ_PORT:-50051}"
KEYCLOAK_URL="${KEYCLOAK_URL:-}"
JWT_ISSUER="${JWT_ISSUER:-}"
JWKS_URL="${JWKS_URL:-}"

if [ -n "$PRIVATE_EC2_PRIVATE_IP" ]; then
  : "${KEYCLOAK_URL:=https://$PRIVATE_EC2_PRIVATE_IP:$KEYCLOAK_HTTPS_HOST_PORT}"
  : "${JWT_ISSUER:=$KEYCLOAK_URL/realms/zero-trust}"
  : "${JWKS_URL:=$KEYCLOAK_URL/realms/zero-trust/protocol/openid-connect/certs}"
fi

if [ -z "$KEYCLOAK_URL" ] || [ -z "$JWT_ISSUER" ] || [ -z "$JWKS_URL" ]; then
  err "KEYCLOAK_URL, JWT_ISSUER, and JWKS_URL must be set for public deployment"
  err "Set PRIVATE_EC2_PRIVATE_IP or export the URLs explicitly"
  exit 1
fi

export PRIVATE_EC2_PRIVATE_IP KEYCLOAK_HTTPS_HOST_PORT EXT_AUTHZ_PORT
export KEYCLOAK_URL JWT_ISSUER JWKS_URL

mkdir -p "$(dirname "$LOG_FILE")"
exec > >(tee -a "$LOG_FILE") 2>&1

log()  { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"; }
err()  { log "ERROR: $*"; }
info() { log "INFO: $*"; }

DOCKER_CMD=(docker)

configure_docker_cmd() {
  if docker info >/dev/null 2>&1; then
    DOCKER_CMD=(docker)
    return
  fi

  if sudo docker info >/dev/null 2>&1; then
    DOCKER_CMD=(sudo docker)
    info "Using sudo docker for this session"
    return
  fi

  err "Docker is installed but not reachable by the current session"
  exit 1
}

docker_compose() {
  "${DOCKER_CMD[@]}" compose "$@"
}

cleanup() {
  local exit_code=$?
  if [ $exit_code -ne 0 ]; then
    err "Deployment failed with exit code $exit_code"
  fi
  exit $exit_code
}
trap cleanup EXIT

render_envoy_config() {
  local template="$PROJECT_ROOT/envoy/envoy.public.yaml.template"
  local output="$PROJECT_ROOT/envoy/envoy.public.yaml"
  local ext_authz_host="${EXT_AUTHZ_HOST:-$PRIVATE_EC2_PRIVATE_IP}"
  local ext_authz_port="${EXT_AUTHZ_PORT:-50051}"

  if [ -z "$ext_authz_host" ]; then
    err "EXT_AUTHZ_HOST or PRIVATE_EC2_PRIVATE_IP is required for public deployment"
    exit 1
  fi

  if [ ! -f "$template" ]; then
    err "Missing Envoy public template: $template"
    exit 1
  fi

  python3 - "$template" "$output" "$ext_authz_host" "$ext_authz_port" <<'PY'
from pathlib import Path
import sys

template = Path(sys.argv[1]).read_text()
rendered = template.replace("__EXT_AUTHZ_HOST__", sys.argv[3]).replace("__EXT_AUTHZ_PORT__", sys.argv[4])
Path(sys.argv[2]).write_text(rendered)
PY
}

# --- 1. Prerequisites ---
info "=== Step 1: Installing prerequisites ==="

if ! command -v docker &>/dev/null; then
  info "Installing Docker..."
  curl -fsSL https://get.docker.com | sh
  sudo usermod -aG docker "$USER"
  info "Docker installed. You may need to log out and back in for group changes."
fi

if ! docker compose version &>/dev/null && ! sudo docker compose version &>/dev/null; then
  info "Installing docker-compose-plugin..."
  sudo apt-get update -qq && sudo apt-get install -y -qq docker-compose-plugin
fi

configure_docker_cmd

# --- 2. Clone or update repo ---
info "=== Step 2: Ensuring repository is present ==="
if [ -d "$PROJECT_ROOT/.git" ]; then
  info "Repository exists, pulling latest..."
  git -C "$PROJECT_ROOT" pull --ff-only
elif [ -f "$PROJECT_ROOT/docker-compose.yml" ] || [ -f "$COMPOSE_FILE" ]; then
  info "Using staged project files in $PROJECT_ROOT"
else
  if [ -n "${REPO_URL:-}" ]; then
    info "Cloning repository from $REPO_URL..."
    git clone "$REPO_URL" "$PROJECT_ROOT"
  else
    err "Repository metadata not present and REPO_URL is not set"
    exit 1
  fi
fi

# --- 3. Fetch certificates from S3 ---
if [ "${1:-}" != "--skip-certs" ]; then
  info "=== Step 3: Fetching certificates from S3 ==="
  mkdir -p "$CERT_DIR"

  if aws s3 ls "s3://$S3_BUCKET/" &>/dev/null; then
    mkdir -p "$CERT_DIR/trust"
    aws s3 sync "s3://$S3_BUCKET/" "$CERT_DIR/" --exclude "*" \
      --include "server.crt" \
      --include "server.key" \
      --include "server-chain.crt" \
      --include "tls.crt" \
      --include "tls.key" \
      --include "root-ca.crt" \
      --include "intermediate-ca.crt" \
      --include "ca-chain.crt" \
      --include "ca.crt" \
      --include "client.crt" \
      --include "client.key" \
      --include "client-chain.crt" \
      --include "attacker-client.crt" \
      --include "attacker-client.key" \
      --include "attacker-client-chain.crt" \
      --include "trust/root-ca.crt" \
      --include "trust/intermediate-ca.crt"

    if [ ! -f "$CERT_DIR/trust/root-ca.crt" ] && [ -f "$CERT_DIR/root-ca.crt" ]; then
      cp "$CERT_DIR/root-ca.crt" "$CERT_DIR/trust/root-ca.crt"
    fi
    if [ ! -f "$CERT_DIR/trust/intermediate-ca.crt" ] && [ -f "$CERT_DIR/intermediate-ca.crt" ]; then
      cp "$CERT_DIR/intermediate-ca.crt" "$CERT_DIR/trust/intermediate-ca.crt"
    fi
    info "Certificates synced from s3://$S3_BUCKET/"
  else
    err "S3 bucket s3://$S3_BUCKET/ not found or not accessible"
    err "Run deploy-private.sh on EC2-Services first, or pass --skip-certs to deploy without certs"
    exit 1
  fi
else
  info "=== Step 3: Skipping certificate fetch (--skip-certs) ==="
fi

render_envoy_config

# --- 4. Deploy with Docker Compose ---
info "=== Step 4: Deploying services ==="
docker_compose -f "$COMPOSE_FILE" pull
docker_compose -f "$COMPOSE_FILE" up -d --build --remove-orphans
docker_compose -f "$COMPOSE_FILE" restart envoy

# --- 5. Health check ---
info "=== Step 5: Running health checks ==="
sleep 10

check_service() {
  local name="$1"
  local url="$2"
  local max_retries="${3:-12}"
  shift 3
  for i in $(seq 1 "$max_retries"); do
    if curl -sf --connect-timeout 2 --max-time 5 "$@" "$url" > /dev/null 2>&1; then
      info "  $name is healthy"
      return 0
    fi
    sleep 5
  done
  err "$name failed health check after $((max_retries * 5)) seconds"
  return 1
}

check_service "Envoy"      "https://localhost:10001/health" 12 --cacert "$CERT_DIR/root-ca.crt"
check_service "Frontend"   "https://localhost/login"        12 --cacert "$CERT_DIR/root-ca.crt"
check_service "Public API" "https://localhost/api/public"   12 --cacert "$CERT_DIR/root-ca.crt"

info "=== Deployment complete ==="
info "Envoy HTTPS entrypoint: https://$(curl -sf http://169.254.169.254/latest/meta-data/public-hostname 2>/dev/null || echo 'localhost'):443"
