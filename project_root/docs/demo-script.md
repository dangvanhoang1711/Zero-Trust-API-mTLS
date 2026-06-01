# Demo Script (Live Presentation)

## 1) Start environment

```bash
docker-compose up --build -d
docker-compose ps
docker-compose logs -f --tail=80 keycloak ext_authz envoy
```

## 2) Wait for IdP + issue token

```bash
cd project_root
source clients/curl-scripts/lib-keycloak.sh
wait_for_keycloak
TOKEN="$(get_access_token demo-client)"
echo "token_prefix=${TOKEN:0:20}..."
```

## 3) Successful call to protected service

```bash
curl --cert infra/certs/client.crt --key infra/certs/client.key --cacert infra/certs/root-ca.crt \
  -H "Authorization: Bearer $TOKEN" \
  https://localhost:10000/protected
```

## 4) Attack scenario: stolen token reuse without cert binding

```bash
# Use same token with wrong cert (wrong certificate binding)
curl --silent \
  --cert tests/functional/fixtures/revoked-client.crt --key tests/functional/fixtures/revoked-client.key \
  --cacert tests/functional/fixtures/chain.pem \
  -H "Authorization: Bearer $TOKEN" \
  -o /tmp/demo-stolen.txt -w "%{http_code}\n" https://localhost:10000/protected
```

## 5) Attack scenario: replay token (same jti)

```bash
# Replayed by clients script
cd project_root
./clients/curl-scripts/05-fail-replay-jti.sh
```

## 6) Scope check demo (if enabled)

```bash
REQUIRED_SCOPE="api:read" docker-compose up -d --force-recreate ext_authz

# token without scope should now be rejected with 403/401 by ext_authz
./clients/curl-scripts/01-ok-mtls-valid-header.sh
```

## 7) Run standard test suites

```bash
./tests/run-all.sh
./tests/security/run-all-security.sh
```
