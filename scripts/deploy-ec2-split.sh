#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

PUBLIC_HOST="${PUBLIC_HOST:-3.106.242.241}"
PUBLIC_PRIVATE_IP="${PUBLIC_PRIVATE_IP:-10.0.5.131}"
PRIVATE_HOST="${PRIVATE_HOST:-10.0.2.27}"
PUBLIC_USER="${PUBLIC_USER:-ubuntu}"
PRIVATE_USER="${PRIVATE_USER:-ubuntu}"
PUBLIC_KEY="${PUBLIC_KEY:-$PROJECT_ROOT/my_private.pem}"
PRIVATE_KEY="${PRIVATE_KEY:-$PROJECT_ROOT/ec2_key.pem}"
PUBLIC_REMOTE_DIR="${PUBLIC_REMOTE_DIR:-/home/$PUBLIC_USER/zero-trust}"
PRIVATE_REMOTE_DIR="${PRIVATE_REMOTE_DIR:-/home/$PRIVATE_USER/zero-trust}"
S3_BUCKET="${S3_BUCKET:-zero-trust-certs-$(date +%Y%m%d)}"

SSH_PUBLIC=(
  ssh
  -i "$PUBLIC_KEY"
  -o StrictHostKeyChecking=no
  -o UserKnownHostsFile=/dev/null
  "$PUBLIC_USER@$PUBLIC_HOST"
)

SCP_PUBLIC=(
  scp
  -i "$PUBLIC_KEY"
  -o StrictHostKeyChecking=no
  -o UserKnownHostsFile=/dev/null
)

log() {
  printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*"
}

require_file() {
  local path="$1"
  if [ ! -f "$path" ]; then
    echo "missing required file: $path" >&2
    exit 1
  fi
}

remote_public() {
  "${SSH_PUBLIC[@]}" "$1"
}

remote_private_via_public() {
  local cmd="$1"
  local encoded_cmd
  encoded_cmd="$(printf '%s' "$cmd" | base64 -w0)"
  remote_public "ssh -i ~/.ssh/ec2_key.pem -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null $PRIVATE_USER@$PRIVATE_HOST 'echo $encoded_cmd | base64 -d | bash'"
}

require_file "$PUBLIC_KEY"
require_file "$PRIVATE_KEY"
chmod 600 "$PUBLIC_KEY" "$PRIVATE_KEY"

ARCHIVE="$(mktemp /tmp/zero-trust-ec2-XXXXXX.tar.gz)"
trap 'rm -f "$ARCHIVE"' EXIT

log "Creating project archive"
tar -czf "$ARCHIVE" \
  --exclude='.git' \
  --exclude='node_modules' \
  --exclude='envoy/certs' \
  --exclude='ec2_key.pem' \
  --exclude='my_private.pem' \
  -C "$PROJECT_ROOT" .

log "Checking SSH access to EC2-Envoy"
remote_public "echo public-ok"

log "Uploading archive and service-hop key to EC2-Envoy"
"${SCP_PUBLIC[@]}" "$ARCHIVE" "$PUBLIC_USER@$PUBLIC_HOST:/tmp/zero-trust.tar.gz"
"${SCP_PUBLIC[@]}" "$PRIVATE_KEY" "$PUBLIC_USER@$PUBLIC_HOST:/tmp/ec2_key.pem"

log "Preparing EC2-Envoy workspace"
remote_public "mkdir -p '$PUBLIC_REMOTE_DIR' ~/.ssh && chmod 700 ~/.ssh && install -m 600 /tmp/ec2_key.pem ~/.ssh/ec2_key.pem && rm -f /tmp/ec2_key.pem && tar -xzf /tmp/zero-trust.tar.gz -C '$PUBLIC_REMOTE_DIR'"

log "Checking SSH access from EC2-Envoy to EC2-Services"
remote_private_via_public "echo private-ok"

log "Copying project archive from EC2-Envoy to EC2-Services"
remote_private_via_public "mkdir -p '$PRIVATE_REMOTE_DIR'"
remote_public "cat /tmp/zero-trust.tar.gz | ssh -i ~/.ssh/ec2_key.pem -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null $PRIVATE_USER@$PRIVATE_HOST 'tar -xzf - -C $PRIVATE_REMOTE_DIR'"

log "Deploying service stack on $PRIVATE_HOST"
remote_private_via_public "cd '$PRIVATE_REMOTE_DIR' && PUBLIC_EC2_PRIVATE_IP='$PUBLIC_PRIVATE_IP' PUBLIC_EC2_PUBLIC_IP='$PUBLIC_HOST' PRIVATE_EC2_PRIVATE_IP='$PRIVATE_HOST' KEYCLOAK_HOSTNAME='keycloak' KEYCLOAK_HTTP_HOST_PORT='8080' KEYCLOAK_HTTPS_HOST_PORT='8443' JWT_ISSUER='https://keycloak:8443/realms/zero-trust' S3_BUCKET='$S3_BUCKET' bash scripts/deploy-private.sh --skip-pki"

log "Syncing certificates from EC2-Services to EC2-Envoy"
remote_public "mkdir -p '$PUBLIC_REMOTE_DIR/envoy/certs/trust' && ssh -i ~/.ssh/ec2_key.pem -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null $PRIVATE_USER@$PRIVATE_HOST 'cd $PRIVATE_REMOTE_DIR && tar -czf - envoy/certs/server.crt envoy/certs/server.key envoy/certs/server-chain.crt envoy/certs/tls.crt envoy/certs/tls.key envoy/certs/root-ca.crt envoy/certs/intermediate-ca.crt envoy/certs/ca-chain.crt envoy/certs/ca.crt envoy/certs/client.crt envoy/certs/client.key envoy/certs/client-chain.crt envoy/certs/attacker-client.crt envoy/certs/attacker-client.key envoy/certs/attacker-client-chain.crt envoy/certs/trust/root-ca.crt envoy/certs/trust/intermediate-ca.crt' | tar -xzf - -C '$PUBLIC_REMOTE_DIR'"

log "Deploying edge stack on $PUBLIC_HOST"
remote_public "cd '$PUBLIC_REMOTE_DIR' && PRIVATE_EC2_PRIVATE_IP='$PRIVATE_HOST' KEYCLOAK_HTTPS_HOST_PORT='8443' KEYCLOAK_URL='https://$PRIVATE_HOST:8443' JWT_ISSUER='https://$PRIVATE_HOST:8443/realms/zero-trust' JWKS_URL='https://$PRIVATE_HOST:8443/realms/zero-trust/protocol/openid-connect/certs' KEYCLOAK_CLIENT_ID='web-app' JWT_AUDIENCE='api-gateway' S3_BUCKET='$S3_BUCKET' bash scripts/deploy-public.sh --skip-certs"

log "Verifying public baseline health endpoint"
remote_public "cd '$PUBLIC_REMOTE_DIR' && curl --silent --show-error --cacert envoy/certs/root-ca.crt https://localhost:10001/health"

log "Verifying public HTTPS frontend"
remote_public "cd '$PUBLIC_REMOTE_DIR' && curl --silent --show-error --cacert envoy/certs/root-ca.crt https://localhost/login > /dev/null"

log "Verifying public API through Envoy"
remote_public "cd '$PUBLIC_REMOTE_DIR' && curl --silent --show-error --cacert envoy/certs/root-ca.crt https://localhost/api/public > /dev/null"

log "Split-host deployment complete"
