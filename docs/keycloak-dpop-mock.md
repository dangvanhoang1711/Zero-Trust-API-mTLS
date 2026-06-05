# Keycloak DPoP Mock/Extend Path for This Project

This repository’s default Keycloak realm is configured for RFC 8705 `cnf.x5t#S256` (mTLS-bound tokens).  
For the Keycloak version in this local stack, native DPoP-bound access tokens are not assumed to be available by default.

To still complete the project DPoP path, this project uses an **explicit mock/extend configuration**:

- Added client `demo-client-dpop` in `infra/keycloak/realm-export.json`
- Added hardcoded `cnf.jkt` claim mapper for that client (`demo-client-dpop`)
- Added local mock key pair in `clients/keys/dpop-mock/`
- Added request helper script `clients/curl-scripts/06-ok-dpop-mock.sh`

## What this mode demonstrates

1. `demo-client-dpop` receives tokens containing `cnf.jkt`.
2. `ext_authz` validates DPoP proof `DPoP` header and checks:
   - `htm` / `htu` match current request
   - DPoP JWS signature is valid
   - DPoP `jwk` thumbprint matches token `cnf.jkt`
3. `demo-client-dpop` token + proof are accepted by gateway when policy/replay checks pass.

## Limitation

- This is a **mocked DPoP emission path** using hardcoded claim mapping in Keycloak.
- It is suitable for coursework verification and integration testing.
- For production, DPoP must be emitted end-to-end by OAuth client flows (or a Keycloak extension/SPi that maps runtime `cnf.jkt`) and key material should be managed securely per client/session.

## Running

```bash
cd project_root
source clients/curl-scripts/lib-keycloak.sh
wait_for_keycloak
./clients/curl-scripts/06-ok-dpop-mock.sh
```

## Files

- `clients/keys/dpop-mock/dpop-mock-private.pem` (mock private key)
- `clients/keys/dpop-mock/dpop-mock-public.pem` (mock public key)
- `clients/keys/dpop-mock/dpop-mock-jwk.json` (mock JWK header payload)
- `clients/keys/dpop-mock/dpop-mock-jkt.txt` (expected `cnf.jkt` value for mapper)
- `infra/keycloak/realm-export.json` (`demo-client-dpop`)
