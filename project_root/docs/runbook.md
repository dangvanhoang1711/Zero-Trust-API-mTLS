# PKI Runbook

## Certificate issuance

1. Bootstrap Vault PKI with the commands in `docs/pki-architecture.md`.
2. Or run `infra/vault/bootstrap-pki.sh` to enable the PKI engines, create roles, issue the Envoy server certificate, export `chain.pem`, and fetch `ca.crl`.
3. Apply `infra/cert-manager/issuer.yaml`.
4. Apply `infra/cert-manager/certificate.yaml`.
5. Confirm Secrets `envoy-server-tls` and `client-mtls` exist.

## CRL refresh

1. Revoke the target certificate serial in Vault.
2. Download the latest CRL from `pki-int/crl/pem`.
3. Update the Kubernetes Secret mounted at `/etc/envoy/tls/ca.crl`.
4. Restart or hot-reload Envoy so the latest CRL is used.

## Phase 2 test scripts

1. `tests/functional/phase2-valid-cert.sh`: valid client certificate succeeds.
2. `tests/functional/phase2-expired-cert.sh`: expired certificate is rejected.
3. `tests/functional/phase2-revoked-cert.sh`: revoked certificate is rejected.
4. `tests/functional/phase2-renewal.sh`: records the secret version so you can verify renewal after the `renewBefore` window.

## Test expectations

1. Valid client cert signed by the Intermediate CA: TLS handshake succeeds.
2. Expired client cert: TLS handshake fails before the request reaches the backend.
3. Revoked client cert present in CRL: TLS handshake fails.
