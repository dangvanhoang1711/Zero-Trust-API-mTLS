#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

source "$SCRIPT_DIR/lib-keycloak.sh"

: "${BASE_URL:=https://localhost:10000}"
: "${DPoP_TARGET_PATH:=/protected}"
: "${CLIENT_CERT:=$PROJECT_ROOT/infra/certs/client.crt}"
: "${CLIENT_KEY:=$PROJECT_ROOT/infra/certs/client.key}"
: "${CA_CERT:=$PROJECT_ROOT/infra/certs/root-ca.crt}"
: "${DPOP_PRIVATE_KEY:=$PROJECT_ROOT/clients/keys/dpop-mock/dpop-mock-private.pem}"
: "${DPOP_JWK_PATH:=$PROJECT_ROOT/clients/keys/dpop-mock/dpop-mock-jwk.json}"

echo "[CASE 6] DPoP mock flow (ext_authz expects cnf.jkt + DPoP proof)"

wait_for_keycloak
token=$(get_access_token "demo-client-dpop")

target_url="${BASE_URL%/}${DPoP_TARGET_PATH}"
dpop=$(python3 - "$DPOP_PRIVATE_KEY" "$DPOP_JWK_PATH" "$target_url" <<'PY'
import base64
import hashlib
import json
import os
import sys
import time
import uuid
from urllib.parse import urlparse

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

private_key_path, jwk_path, target_url = sys.argv[1:4]

with open(jwk_path, "r", encoding="utf-8") as fp:
    jwk = json.load(fp)

with open(private_key_path, "rb") as fp:
    private_key = serialization.load_pem_private_key(
        fp.read(),
        password=None,
    )

parsed = urlparse(target_url)
if not (parsed.scheme and parsed.netloc):
    raise SystemExit("invalid DPoP htu URL")

htu = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

header = {
    "alg": "RS256",
    "typ": "dpop+jwt",
    "jwk": jwk,
}

claims = {
    "htu": htu,
    "htm": "GET",
    "jti": uuid.uuid4().hex,
    "iat": int(time.time()),
}

def b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")

protected_b64 = b64url(json.dumps(header, separators=(",", ":")).encode("utf-8"))
payload_b64 = b64url(json.dumps(claims, separators=(",", ":")).encode("utf-8"))
signing_input = f"{protected_b64}.{payload_b64}".encode("utf-8")
signature = private_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())

print(f"{protected_b64}.{payload_b64}.{b64url(signature)}")
PY
)

status_code=$(curl --silent --show-error \
  --output /tmp/zt_case6.out \
  --write-out "%{http_code}" \
  --cert "$CLIENT_CERT" \
  --key "$CLIENT_KEY" \
  --cacert "$CA_CERT" \
  -H "Authorization: Bearer $token" \
  -H "DPoP: $dpop" \
  "$target_url")

cat /tmp/zt_case6.out

if [ "$status_code" != "200" ]; then
  echo "FAIL: expected HTTP 200, got $status_code"
  echo "Run with set -x or inspect generated request if needed."
  exit 1
fi

echo
echo "PASS: DPoP mock request allowed"
