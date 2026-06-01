#!/usr/bin/env python3
"""
Update cnf.x5t#S256 thumbprint in Keycloak via Admin REST API.
Usage: python3 update_keycloak_thumbprint.py <thumbprint_hex>
"""
import json, os, sys, urllib.request, urllib.parse

THUMBPRINT = sys.argv[1] if len(sys.argv) > 1 else ""
if not THUMBPRINT:
    print("ERROR: thumbprint argument required")
    sys.exit(1)

BASE = os.environ.get("KEYCLOAK_URL", "http://localhost:18080")
ADMIN_USER = os.environ.get("KEYCLOAK_ADMIN", "admin")
ADMIN_PASS = os.environ.get("KEYCLOAK_ADMIN_PASSWORD", "admin")
REALM = "zero-trust"
CLIENT_ID = "demo-client"
MAPPER_NAME = "cnf-thumbprint"

def req(method, path, data=None, token=None, form=False):
    url = f"{BASE}{path}"
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if form:
        body = urllib.parse.urlencode(data).encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    else:
        headers["Content-Type"] = "application/json"
        body = json.dumps(data).encode() if data else None
    r = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(r) as resp:
            ct = resp.headers.get("Content-Type", "")
            if "application/json" in ct or "json" in ct:
                return json.loads(resp.read().decode())
            return resp.read().decode()
    except urllib.error.HTTPError as e:
        err_body = e.read().decode()
        print(f"  HTTP {e.code}: {err_body[:200]}")
        return None

# 1. Get admin token
print("  Getting admin token...")
token_data = req("POST", "/realms/master/protocol/openid-connect/token",
    data={"client_id": "admin-cli", "username": ADMIN_USER,
          "password": ADMIN_PASS, "grant_type": "password"}, form=True)
if not token_data or "access_token" not in token_data:
    print("  FAILED: Cannot get admin token. Check KEYCLOAK_URL and admin credentials.")
    sys.exit(1)
token = token_data["access_token"]

# 2. Find demo-client UUID
print("  Finding demo-client UUID...")
clients = req("GET", f"/admin/realms/{REALM}/clients?clientId={CLIENT_ID}", token=token)
if not clients or len(clients) == 0:
    print(f"  FAILED: Client '{CLIENT_ID}' not found")
    sys.exit(1)
client_uuid = clients[0]["id"]
print(f"  Client UUID: {client_uuid}")

# 3. Find cnf-thumbprint mapper
print(f"  Finding mapper '{MAPPER_NAME}'...")
mappers = req("GET", f"/admin/realms/{REALM}/clients/{client_uuid}/protocol-mappers/models", token=token)
if not mappers:
    print(f"  FAILED: Cannot list mappers")
    sys.exit(1)
mapper = next((m for m in mappers if m.get("name") == MAPPER_NAME), None)
if not mapper:
    print(f"  FAILED: Mapper '{MAPPER_NAME}' not found")
    print(f"  Available mappers: {[m.get('name') for m in mappers]}")
    sys.exit(1)
mapper_uuid = mapper["id"]
print(f"  Mapper UUID: {mapper_uuid}")

# 4. Update claim.value
new_value = json.dumps({"x5t#S256": THUMBPRINT})
mapper["config"]["claim.value"] = new_value
print(f"  New claim.value: {new_value}")

result = req("PUT", f"/admin/realms/{REALM}/clients/{client_uuid}/protocol-mappers/models/{mapper_uuid}",
    data=mapper, token=token)
if result is None:
    print(f"  FAILED: Update request returned error")
    sys.exit(1)

print(f"  SUCCESS: Thumbprint updated in Keycloak (no restart needed)")
