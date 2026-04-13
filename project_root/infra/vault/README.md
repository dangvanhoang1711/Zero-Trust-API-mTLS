# Vault PKI Bootstrap

This folder contains the Vault-side automation for Phase 2.

## Files

1. `bootstrap-pki.sh`: enables the Root and Intermediate PKI engines, creates `server-cert` and `client-cert` roles, issues the Envoy server certificate, exports `chain.pem`, and fetches the current CRL.

## Usage

```bash
export VAULT_ADDR=https://vault.example.com:8200
export VAULT_TOKEN=<admin-token>
export VAULT_PUBLIC_ADDR=https://vault.example.com:8200

./infra/vault/bootstrap-pki.sh
```

The script writes runtime artifacts into `./artifacts/`. Do not commit the generated private key.
