# PKI Architecture

## 1. Vault PKI topology

Phase 2 uses a two-tier PKI managed by Vault:

1. `pki-root`: self-signed Root CA kept for signing the intermediate only.
2. `pki-int`: Intermediate CA used to issue short-lived leaf certificates.
3. Leaf certificates:
   - `server-cert` role for Envoy server TLS certificates.
   - `client-cert` role for workload and test-client mTLS certificates.

This keeps the Root CA isolated while the Intermediate CA handles daily issuance and revocation.

## 2. Certificate chain

The chain is always validated as:

`Root CA -> Intermediate CA -> Leaf cert`

Envoy serves its leaf certificate and validates client certificates against the Intermediate CA bundle plus CRL data. The exported `chain.pem` file contains the Intermediate CA followed by the Root CA so clients can build the full chain without storing private material in Git.

## 3. Vault CLI commands

Run these commands after Vault is reachable over HTTPS and `VAULT_ADDR` / `VAULT_TOKEN` are set for an administrator session.

```bash
vault secrets enable -path=pki-root pki
vault secrets tune -max-lease-ttl=87600h pki-root

vault write -field=certificate pki-root/root/generate/internal \
  common_name="Zero Trust Root CA" \
  issuer_name="zero-trust-root" \
  ttl=87600h > root_ca.crt

vault write pki-root/config/urls \
  issuing_certificates="https://vault.example.com:8200/v1/pki-root/ca" \
  crl_distribution_points="https://vault.example.com:8200/v1/pki-root/crl"

vault secrets enable -path=pki-int pki
vault secrets tune -max-lease-ttl=43800h pki-int

vault write -format=json pki-int/intermediate/generate/internal \
  common_name="Zero Trust Intermediate CA" \
  issuer_name="zero-trust-intermediate" \
  | jq -r '.data.csr' > pki_int.csr

vault write -format=json pki-root/root/sign-intermediate \
  csr=@pki_int.csr \
  format=pem_bundle \
  ttl=43800h | jq -r '.data.certificate' > pki_int.pem

vault write pki-int/intermediate/set-signed certificate=@pki_int.pem

vault write pki-int/config/urls \
  issuing_certificates="https://vault.example.com:8200/v1/pki-int/ca" \
  crl_distribution_points="https://vault.example.com:8200/v1/pki-int/crl"

vault write pki-int/roles/server-cert \
  allowed_domains="envoy-service.default.svc.cluster.local" \
  allow_subdomains=true \
  allow_bare_domains=false \
  max_ttl=24h \
  ttl=24h \
  key_type="rsa" \
  key_bits=2048 \
  server_flag=true \
  client_flag=false

vault write pki-int/roles/client-cert \
  allow_any_name=true \
  max_ttl=24h \
  ttl=24h \
  key_type="rsa" \
  key_bits=2048 \
  server_flag=false \
  client_flag=true

cat pki_int.pem root_ca.crt > chain.pem

vault lease revoke -prefix pki-int/certs/client-cert
curl -fsS "$VAULT_ADDR/v1/pki-int/crl/pem" -o ca.crl
```

## 4. cert-manager integration

`infra/cert-manager/issuer.yaml` uses Kubernetes auth instead of a static root token.

1. cert-manager requests a projected token for `cert-manager-vault-issuer`.
2. Vault maps that service account to the `cert-manager-issuer` auth role.
3. cert-manager signs requests through `pki-int/sign/server-cert` or `pki-int/sign/client-cert` depending on the `ClusterIssuer` used.

Use a second issuer path or a second `ClusterIssuer` if you want to split server and client issuance more strictly at the Kubernetes API layer.

## 5. Envoy TLS files

`envoy_config/tls/` is intentionally documentation-only in Git. At deploy time, mount:

1. `tls.crt`: Envoy server certificate.
2. `tls.key`: Envoy private key.
3. `intermediate-ca.crt`: client trust anchor bundle.
4. `ca.crl`: current CRL from Vault.
5. `chain.pem`: exported Intermediate + Root bundle for distribution.

Never commit real private keys or live certificates.
