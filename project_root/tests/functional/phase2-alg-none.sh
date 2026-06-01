#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

: "${BASE_URL:=https://localhost:10000/}"
: "${CLIENT_CERT:=$PROJECT_ROOT/../infra/certs/client.crt}"
: "${CLIENT_KEY:=$PROJECT_ROOT/../infra/certs/client.key}"
: "${CA_CERT:=$PROJECT_ROOT/../infra/certs/root-ca.crt}"

token=$(python3 - <<'PY'
import base64
import json
import time

def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

header = {"alg": "none", "typ": "JWT"}
payload = {
    "iss": "https://localhost:10000/realms/zero-trust",
    "aud": "api-gateway",
    "sub": "alg-none-user",
    "jti": "alg-none-demo",
    "iat": int(time.time()),
    "nbf": int(time.time()) - 30,
    "exp": int(time.time()) + 300,
    "cnf": {"x5t#S256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
}

print(
    f"{b64url(json.dumps(header).encode())}.{b64url(json.dumps(payload).encode())}."
)
PY
)

status_code=$(curl --silent --show-error \
  --output /tmp/zt_case_h.out \
  --write-out "%{http_code}" \
  --cert "$CLIENT_CERT" \
  --key "$CLIENT_KEY" \
  --cacert "$CA_CERT" \
  -H "Authorization: Bearer $token" \
  "$BASE_URL")

cat /tmp/zt_case_h.out

if [ "$status_code" != "401" ]; then
  echo "FAIL: expected HTTP 401, got $status_code" >&2
  exit 1
fi

echo "PASS: alg:none token rejected"
