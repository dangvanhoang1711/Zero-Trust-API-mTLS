#!/bin/sh
set -eu

thumbprint_for_cert() {
  cert_path="$1"
  openssl x509 -in "${cert_path}" -outform DER \
    | python3 -c 'import hashlib,sys; print(hashlib.sha256(sys.stdin.buffer.read()).hexdigest())'
}

SERVER_CERT_DNS_NAMES="${SERVER_CERT_DNS_NAMES:-localhost,envoy,backend,protected-api,ext-authz,keycloak}"
SERVER_CERT_IP_SANS="${SERVER_CERT_IP_SANS:-127.0.0.1}"

if [ -n "${SERVER_CERT_EXTRA_DNS:-}" ]; then
  SERVER_CERT_DNS_NAMES="${SERVER_CERT_DNS_NAMES},${SERVER_CERT_EXTRA_DNS}"
fi

if [ -n "${SERVER_CERT_EXTRA_IP_SANS:-}" ]; then
  SERVER_CERT_IP_SANS="${SERVER_CERT_IP_SANS},${SERVER_CERT_EXTRA_IP_SANS}"
fi

sync_keycloak_realm_export() {
  template_path="/keycloak/realm-export.json.template"
  output_path="/keycloak/realm-export.json"
  default_mismatch_thumbprint="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

  if [ ! -f "${template_path}" ]; then
    echo "=== PKI Init: Keycloak template not found, skipping realm export sync ==="
    return 0
  fi

  if [ ! -f /certs/client.crt ]; then
    echo "=== PKI Init: primary client cert missing, skipping realm export sync ==="
    return 0
  fi

  primary_thumbprint="$(thumbprint_for_cert /certs/client.crt)"
  mismatch_thumbprint="${default_mismatch_thumbprint}"
  if [ -f /certs/attacker-client.crt ]; then
    mismatch_thumbprint="$(thumbprint_for_cert /certs/attacker-client.crt)"
  fi

  sed \
    -e "s/__CLIENT_CERT_THUMBPRINT__/${primary_thumbprint}/g" \
    -e "s/__CLIENT_MISMATCH_THUMBPRINT__/${mismatch_thumbprint}/g" \
    "${template_path}" > "${output_path}"

  echo "=== PKI Init: synced Keycloak realm export ==="
  echo "    demo-client thumbprint: ${primary_thumbprint}"
  echo "    demo-client-mismatch thumbprint: ${mismatch_thumbprint}"
}

echo "=== PKI Init: check existing certs ==="
if [ -f /certs/tls.crt ] && [ -f /certs/client-chain.crt ] && [ -f /certs/ca-chain.crt ]; then
  if openssl x509 -in /certs/tls.crt -noout -subject > /dev/null 2>&1; then
    sync_keycloak_realm_export
    echo "Certs valid, skipping regeneration"
    exit 0
  fi
fi
echo "Regenerating certs..."

echo "=== PKI Init: wait for Vault ==="
for try in 1 2 3 4 5 6 7 8 9 10 15; do
  if vault status > /dev/null 2>&1; then
    echo "Vault ready (unsealed)"
    break
  fi
  if vault status -format=json 2>/dev/null | python3 -c 'import json,sys; d=json.load(sys.stdin); raise SystemExit(0 if d.get("sealed") else 1)' 2>/dev/null; then
    echo "Vault reachable but sealed"
    break
  fi
  echo "Waiting for Vault..."
  sleep 3
done

echo "=== PKI Init: check initialized ==="
CREDS_FILE="/certs/vault-creds.json"
if vault status -format=json 2>/dev/null | python3 -c 'import json,sys; d=json.load(sys.stdin); raise SystemExit(0 if d.get("initialized") else 1)' 2>/dev/null; then
  echo "Vault already initialized"
  if vault status -format=json 2>/dev/null | python3 -c 'import json,sys; d=json.load(sys.stdin); raise SystemExit(0 if d.get("sealed") else 1)' 2>/dev/null; then
    echo "Vault sealed -- reading creds from ${CREDS_FILE}"
    if [ -f "${CREDS_FILE}" ]; then
      UNSEAL_KEY="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["unseal_key"])' "${CREDS_FILE}")"
      ROOT_TOKEN="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["root_token"])' "${CREDS_FILE}")"
      vault operator unseal "${UNSEAL_KEY}" > /dev/null 2>&1
      vault login "${ROOT_TOKEN}" > /dev/null 2>&1
      export VAULT_TOKEN="${ROOT_TOKEN}"
      echo "Vault unsealed"
    else
      echo "ERROR: ${CREDS_FILE} not found, cannot unseal"
      exit 1
    fi
  fi
else
  echo "Vault not initialized -- init + unseal + save creds"
  INIT_OUT="$(vault operator init -key-shares=1 -key-threshold=1 -format=json 2>/dev/null)"
  UNSEAL_KEY="$(printf '%s' "${INIT_OUT}" | python3 -c 'import json,sys; print(json.load(sys.stdin)["unseal_keys_b64"][0])')"
  ROOT_TOKEN="$(printf '%s' "${INIT_OUT}" | python3 -c 'import json,sys; print(json.load(sys.stdin)["root_token"])')"
  python3 -c 'import json,sys; json.dump({"unseal_key":sys.argv[1], "root_token":sys.argv[2]}, sys.stdout)' "${UNSEAL_KEY}" "${ROOT_TOKEN}" > "${CREDS_FILE}"
  chmod 600 "${CREDS_FILE}"
  vault operator unseal "${UNSEAL_KEY}" > /dev/null 2>&1
  vault login "${ROOT_TOKEN}" > /dev/null 2>&1
  export VAULT_TOKEN="${ROOT_TOKEN}"
  echo "Vault init + unseal complete"
fi

echo "=== PKI Init: engines ==="
vault secrets enable -path=pki-root pki 2>/dev/null || true
vault secrets tune -max-lease-ttl=87600h pki-root

vault write -field=certificate pki-root/root/generate/internal common_name="Zero Trust Root CA" ttl=87600h > /certs/root-ca.crt
printf '\n' >> /certs/root-ca.crt

vault secrets disable pki-int 2>/dev/null || true
vault secrets enable -path=pki-int pki
vault secrets tune -max-lease-ttl=43800h pki-int

vault write -format=json pki-int/intermediate/generate/internal common_name="Zero Trust Intermediate CA" ttl=43800h > /tmp/int.json
python3 -c 'import json; d=json.load(open("/tmp/int.json")); print(d["data"]["csr"])' > /tmp/int.csr
vault write -format=json pki-root/root/sign-intermediate csr=@/tmp/int.csr format=pem_bundle ttl=43800h > /tmp/int-signed.json
python3 -c 'import json; d=json.load(open("/tmp/int-signed.json")); print(d["data"]["certificate"])' > /tmp/int.crt
vault write pki-int/intermediate/set-signed certificate=@/tmp/int.crt

cp /certs/root-ca.crt /certs/ca-chain.crt
printf '\n' >> /certs/ca-chain.crt
cat /tmp/int.crt >> /certs/ca-chain.crt
printf '\n' >> /certs/ca-chain.crt
cat /certs/vault-ca.crt >> /certs/ca-chain.crt

cp /tmp/int.crt /certs/intermediate-ca.crt
mkdir -p /certs/trust /certs/vault-tls
cp /certs/intermediate-ca.crt /certs/trust/intermediate-ca.crt
cp /certs/root-ca.crt /certs/trust/root-ca.crt
cp /certs/root-ca.crt /certs/ca.crt

echo "=== PKI Init: roles ==="
vault write pki-int/roles/server-cert allow_any_name=true max_ttl=730h ttl=730h key_type=ec key_bits=256 server_flag=true
vault write pki-int/roles/client-cert allow_any_name=true max_ttl=730h ttl=730h key_type=ec key_bits=256 client_flag=true

echo "=== PKI Init: server cert ==="
echo "    DNS SANs: ${SERVER_CERT_DNS_NAMES}"
echo "    IP SANs:  ${SERVER_CERT_IP_SANS}"
vault write -format=json pki-int/issue/server-cert common_name=localhost alt_names="${SERVER_CERT_DNS_NAMES}" ip_sans="${SERVER_CERT_IP_SANS}" ttl=730h > /tmp/server.json
python3 -c 'import json; d=json.load(open("/tmp/server.json")); print(d["data"]["certificate"])' > /certs/server.crt
python3 -c 'import json; d=json.load(open("/tmp/server.json")); print(d["data"]["private_key"])' > /certs/server.key
cp /certs/server.crt /certs/server-chain.crt
printf '\n' >> /certs/server-chain.crt
cat /tmp/int.crt >> /certs/server-chain.crt
cp /certs/server-chain.crt /certs/tls.crt
cp /certs/server.key /certs/tls.key

echo "=== PKI Init: primary client cert ==="
vault write -format=json pki-int/issue/client-cert common_name=demo-client ttl=730h > /tmp/client.json
python3 -c 'import json; d=json.load(open("/tmp/client.json")); print(d["data"]["certificate"])' > /certs/client.crt
python3 -c 'import json; d=json.load(open("/tmp/client.json")); print(d["data"]["private_key"])' > /certs/client.key
cp /certs/client.crt /certs/client-chain.crt
printf '\n' >> /certs/client-chain.crt
cat /tmp/int.crt >> /certs/client-chain.crt

echo "=== PKI Init: alternate valid client cert ==="
vault write -format=json pki-int/issue/client-cert common_name=attacker-client ttl=730h > /tmp/attacker-client.json
python3 -c 'import json; d=json.load(open("/tmp/attacker-client.json")); print(d["data"]["certificate"])' > /certs/attacker-client.crt
python3 -c 'import json; d=json.load(open("/tmp/attacker-client.json")); print(d["data"]["private_key"])' > /certs/attacker-client.key
cp /certs/attacker-client.crt /certs/attacker-client-chain.crt
printf '\n' >> /certs/attacker-client-chain.crt
cat /tmp/int.crt >> /certs/attacker-client-chain.crt

sync_keycloak_realm_export

echo "=== PKI Init: fix permissions ==="
chmod 644 /certs/*.crt /certs/*.key 2>/dev/null || true
chmod 644 /certs/trust/*.crt 2>/dev/null || true

echo "=== PKI Init Complete ==="
