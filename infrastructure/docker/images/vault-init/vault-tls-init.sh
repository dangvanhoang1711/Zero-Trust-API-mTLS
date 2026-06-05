#!/bin/sh
set -eu

echo "=== Vault TLS Init: check existing ==="
if [ -f /certs/vault-ca.crt ] && [ -f /certs/vault-tls/cert.pem ] && [ -f /certs/vault-tls/privkey.pem ]; then
  if openssl x509 -in /certs/vault-tls/cert.pem -noout -subject > /dev/null 2>&1; then
    echo "Vault TLS certs valid, skipping"
    exit 0
  fi
fi

echo "=== Vault TLS Init: generate CA ==="
mkdir -p /certs/vault-tls
openssl genrsa -out /certs/vault-tls/ca.key 2048 2>/dev/null
openssl req -x509 -new -nodes -key /certs/vault-tls/ca.key -sha256 \
  -days 3650 -out /certs/vault-ca.crt \
  -subj "/CN=Vault Bootstrap CA"

echo "=== Vault TLS Init: generate server cert ==="
openssl genrsa -out /certs/vault-tls/privkey.pem 2048 2>/dev/null
openssl req -new -key /certs/vault-tls/privkey.pem \
  -out /tmp/vault.csr \
  -subj "/CN=vault"
printf 'subjectAltName=DNS:vault,DNS:localhost,IP:127.0.0.1\n' > /tmp/vault_ext.cnf
openssl x509 -req -in /tmp/vault.csr \
  -CA /certs/vault-ca.crt -CAkey /certs/vault-tls/ca.key \
  -CAcreateserial -out /certs/vault-tls/cert.pem \
  -days 3650 -extfile /tmp/vault_ext.cnf

echo "=== Vault TLS Init: generate config ==="
cp /vault-config/vault.hcl /certs/vault.hcl

echo "=== Vault TLS Init: permissions ==="
chmod 644 /certs/vault-ca.crt /certs/vault.hcl 2>/dev/null || true
chmod 644 /certs/vault-tls/cert.pem /certs/vault-tls/privkey.pem 2>/dev/null || true

echo "=== Vault TLS Init Complete ==="
