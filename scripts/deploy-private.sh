#!/bin/bash
set -euo pipefail

# === Zero-Trust Services Deploy (EC2-Services) ===
# Deploys Keycloak, Vault, Redis, ext-authz, and pki-init from docker-compose.private.yml
# Usage: ./deploy-private.sh [--skip-pki]

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
LOG_FILE="${LOG_FILE:-$HOME/zero-trust-deploy-private.log}"
COMPOSE_FILE="$PROJECT_ROOT/infrastructure/docker/docker-compose.private.yml"

S3_BUCKET="${S3_BUCKET:-zero-trust-certs-$(date +%Y%m%d)}"
CERT_DIR="$PROJECT_ROOT/envoy/certs"
VAULT_ARTIFACTS="$PROJECT_ROOT/vault/artifacts"
PRIVATE_EC2_PRIVATE_IP="${PRIVATE_EC2_PRIVATE_IP:-$(curl -sf http://169.254.169.254/latest/meta-data/local-ipv4 2>/dev/null || hostname -I | awk '{print $1}')}"
KEYCLOAK_HOSTNAME="${KEYCLOAK_HOSTNAME:-$PRIVATE_EC2_PRIVATE_IP}"
KEYCLOAK_HTTP_HOST_PORT="${KEYCLOAK_HTTP_HOST_PORT:-8080}"
KEYCLOAK_HTTPS_HOST_PORT="${KEYCLOAK_HTTPS_HOST_PORT:-8443}"
KEYCLOAK_INTERNAL_URL="${KEYCLOAK_INTERNAL_URL:-https://keycloak:8443}"
JWT_ISSUER="${JWT_ISSUER:-https://$KEYCLOAK_HOSTNAME:$KEYCLOAK_HTTPS_HOST_PORT/realms/zero-trust}"
JWKS_URL="${JWKS_URL:-https://keycloak:8443/realms/zero-trust/protocol/openid-connect/certs}"
KEYCLOAK_URL="${KEYCLOAK_URL:-https://localhost:$KEYCLOAK_HTTPS_HOST_PORT}"
KEYCLOAK_CA_CERT="${KEYCLOAK_CA_CERT:-$CERT_DIR/root-ca.crt}"
SERVER_CERT_EXTRA_IP_SANS="${SERVER_CERT_EXTRA_IP_SANS:-}"
SERVER_CERT_EXTRA_DNS="${SERVER_CERT_EXTRA_DNS:-}"

for ip_candidate in "${PRIVATE_EC2_PRIVATE_IP:-}" "${PUBLIC_EC2_PRIVATE_IP:-}" "${PUBLIC_EC2_PUBLIC_IP:-}"; do
  if [ -n "$ip_candidate" ]; then
    if [ -n "$SERVER_CERT_EXTRA_IP_SANS" ]; then
      SERVER_CERT_EXTRA_IP_SANS="$SERVER_CERT_EXTRA_IP_SANS,$ip_candidate"
    else
      SERVER_CERT_EXTRA_IP_SANS="$ip_candidate"
    fi
  fi
done

export PRIVATE_EC2_PRIVATE_IP KEYCLOAK_HOSTNAME KEYCLOAK_HTTP_HOST_PORT KEYCLOAK_HTTPS_HOST_PORT
export KEYCLOAK_INTERNAL_URL JWT_ISSUER JWKS_URL KEYCLOAK_URL KEYCLOAK_CA_CERT
export SERVER_CERT_EXTRA_DNS SERVER_CERT_EXTRA_IP_SANS

mkdir -p "$(dirname "$LOG_FILE")" "$CERT_DIR"
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

docker_cli() {
  "${DOCKER_CMD[@]}" "$@"
}

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

# --- 3. Deploy with Docker Compose ---
info "=== Step 3: Deploying private infrastructure ==="
docker_compose -f "$COMPOSE_FILE" pull
docker_compose -f "$COMPOSE_FILE" up -d --build --remove-orphans

# --- 4. Wait for Keycloak health ---
info "=== Step 4: Waiting for Keycloak ==="
for i in $(seq 1 24); do
  if curl -sf --connect-timeout 3 --max-time 5 \
    --cacert "$CERT_DIR/root-ca.crt" \
    "https://localhost:${KEYCLOAK_HTTPS_HOST_PORT}/realms/zero-trust/.well-known/openid-configuration" > /dev/null 2>&1; then
    info "  Keycloak is healthy"
    break
  fi
  if [ "$i" -eq 24 ]; then
    err "Keycloak failed to become healthy within 120 seconds"
    docker_compose -f "$COMPOSE_FILE" logs keycloak --tail=30
    exit 1
  fi
  info "  Waiting for Keycloak... ($i/24)"
  sleep 5
done

# --- 5. Wait for Vault health ---
info "=== Step 5: Waiting for Vault ==="
for i in $(seq 1 18); do
  if curl -sf --connect-timeout 3 --max-time 5 \
    --cacert "$CERT_DIR/vault-ca.crt" \
    "https://localhost:8200/v1/sys/health" > /dev/null 2>&1; then
    info "  Vault is healthy"
    break
  fi
  if [ "$i" -eq 18 ]; then
    err "Vault failed to become healthy within 90 seconds"
    docker_compose -f "$COMPOSE_FILE" logs vault --tail=30
    exit 1
  fi
  info "  Waiting for Vault... ($i/18)"
  sleep 5
done

# --- 6. Wait for pki-init to complete ---
info "=== Step 6: Waiting for pki-init to complete ==="
PKI_CONTAINER=$(docker_compose -f "$COMPOSE_FILE" ps -q pki-init 2>/dev/null || true)
if [ -n "$PKI_CONTAINER" ]; then
  for i in $(seq 1 30); do
    status="$(docker_cli inspect "$PKI_CONTAINER" --format '{{.State.Status}}' 2>/dev/null || echo 'missing')"
    if [ "$status" = "exited" ]; then
      container_exit_code="$(docker_cli inspect "$PKI_CONTAINER" --format '{{.State.ExitCode}}' 2>/dev/null || echo 1)"
      if [ "$container_exit_code" -eq 0 ]; then
        info "  pki-init completed successfully"
      else
        err "pki-init failed with exit code $container_exit_code"
        docker_cli logs "$PKI_CONTAINER" --tail=40
        exit 1
      fi
      break
    fi
    if [ "$i" -eq 30 ]; then
      err "pki-init did not complete within 150 seconds"
      docker_cli logs "$PKI_CONTAINER" --tail=40
      exit 1
    fi
    sleep 5
  done
else
  info "  pki-init container not found (already completed or not started)"
fi

# --- 7. Run certificate generation ---
if [ "${1:-}" != "--skip-pki" ]; then
  info "=== Step 7: Running certificate generation ==="
  if [ -f "$SCRIPT_DIR/generate-certs.sh" ]; then
    bash "$SCRIPT_DIR/generate-certs.sh"
  else
    info "  generate-certs.sh not found, running Vault PKI inline..."
    VAULT_ADDR="https://localhost:8200" VAULT_TOKEN="root" VAULT_CACERT="$CERT_DIR/vault-ca.crt" \
      bash "$PROJECT_ROOT/vault/scripts/gen-pki-vault.sh"
  fi
else
  info "=== Step 7: Skipping PKI generation (--skip-pki) ==="
fi

# --- 8. Upload certs to S3 for EC2-Envoy ---
info "=== Step 8: Uploading certificates to S3 ==="
if command -v aws &>/dev/null; then
  if ! aws s3 ls "s3://$S3_BUCKET/" &>/dev/null 2>&1; then
    info "  Creating S3 bucket: s3://$S3_BUCKET"
    aws s3 mb "s3://$S3_BUCKET" --region "${AWS_REGION:-$(curl -sf http://169.254.169.254/latest/meta-data/placement/region 2>/dev/null || echo 'us-east-1')}"
  fi

  aws s3 sync "$CERT_DIR/" "s3://$S3_BUCKET/" --exclude "*" \
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
  info "  Certificates uploaded to s3://$S3_BUCKET/"

  # Also upload vault artifacts for reference
  if [ -d "$VAULT_ARTIFACTS" ]; then
    aws s3 sync "$VAULT_ARTIFACTS/" "s3://$S3_BUCKET/vault-artifacts/"
    info "  Vault artifacts uploaded to s3://$S3_BUCKET/vault-artifacts/"
  fi
else
  info "  AWS CLI not found. Skipping S3 upload."
  info "  Manually copy certs from $CERT_DIR to EC2-Envoy."
fi

info "=== Deployment complete ==="
info "Keycloak admin console: https://localhost:${KEYCLOAK_HTTPS_HOST_PORT}/admin (username: admin)"
info "Vault UI:              https://localhost:8200/ui    (token: root)"
info "Certs synced to:       s3://$S3_BUCKET/"
