# Demo Guide — Zero Trust API Gateway

## Prerequisites

- Deployed system (see [deployment-guide.md](deployment-guide.md))
- **Postman** installed (for mTLS scenarios)
- **OpenSSL** installed
- Client certificates available in `vault/artifacts/`

---

## Scenario 1: Browser Login & Register Flow

**Goal**: Demonstrate user registration and login through the web UI.

### Steps

1. Open browser to `https://<ec2-1-public-ip>:10000`
2. Click **"Đăng ký"** (Register)
3. Fill in:
   - Username: `demo-user`
   - Email: `demo@example.com`
   - Password: `demo-pass`
   - Confirm password: `demo-pass`
4. Click **"Đăng ký"** → expect success flash message
5. Click **"Đăng nhập"** (Login)
6. Enter username `demo-user`, password `demo-pass`
7. Click **"Đăng nhập"**

### Expected Result

- Redirected to **Dashboard**
- Shows **"Xin chào, demo-user"** with `user` role tag
- JWT token info displayed (issuer, subject, audience, scope)
- API demo buttons visible

---

## Scenario 2: Dashboard & API Buttons (Role-Based Access)

**Goal**: Test role-based API access from the dashboard.

### Steps

1. **Login as `admin`** (username: `admin`, password: `admin`)
2. Click each API button and observe results:

| Button | Expected HTTP Status | Expected Content |
|--------|---------------------|------------------|
| 🌐 Public | `200 ✅` | `"Public endpoint"` |
| 👤 Profile | `200 ✅` | User info with roles |
| 📄 User Data | `200 ✅` | 3 mock data items |
| 🔐 Admin Data | `200 ✅` | System config, user list, audit log |
| 🎫 JWT Info | `200 ✅` | Full JWT payload |

3. **Login as `demo-user`** and re-test:

| Button | Expected HTTP Status | Expected Content |
|--------|---------------------|------------------|
| 🌐 Public | `200 ✅` | `"Public endpoint"` |
| 👤 Profile | `200 ✅` | User info |
| 📄 User Data | `200 ✅` | 3 mock data items |
| 🔐 Admin Data | `403 ❌` | `"Forbidden — cần role 'admin'"` |
| 🎫 JWT Info | `200 ✅` | Full JWT payload |

### Expected Result

- Role-based access control working correctly
- `admin` can access all endpoints
- `demo-user` gets `403 Forbidden` on admin data

---

## Scenario 3: Postman mTLS Setup

**Goal**: Configure Postman for mTLS API calls.

### Steps

1. **Open Postman**
2. Create a new request or collection
3. **Settings → Certificates**:
   - **Add Client Certificate**
   - Host: `<ec2-1-public-ip>`
   - Port: `10000`
   - CRT file: `vault/artifacts/client.crt`
   - KEY file: `vault/artifacts/client.key`
4. **Disable SSL verification** (or add Root CA to trusted roots):
   - Settings → General → SSL certificate verification: **OFF**
5. Save the certificate configuration

### Expected Result

- Postman is now configured for mTLS connections to the gateway
- All requests to `https://<ec2-1-public-ip>:10000` will include the client certificate

---

## Scenario 4: Postman API Calls (Valid JWT)

**Goal**: Demonstrate successful authenticated API calls from Postman.

### Step 4a: Get JWT Token

Create a POST request:

| Field | Value |
|-------|-------|
| **URL** | `http://<ec2-2-private-ip>:8080/realms/zero-trust/protocol/openid-connect/token` |
| **Method** | POST |
| **Body** (x-www-form-urlencoded) | `grant_type=password&client_id=web-app&username=admin&password=admin` |

Copy the `access_token` from the response.

### Step 4b: Call Protected API

Create a GET request:

| Field | Value |
|-------|-------|
| **URL** | `https://<ec2-1-public-ip>:10000/protected` |
| **Method** | GET |
| **Headers** | `Authorization: Bearer <access_token>` |
| **Certificates** | mTLS cert configured in Scenario 3 |

### Expected Result

```json
{
  "authenticated": true,
  "user": "admin",
  "roles": ["admin", "user"],
  "method": "GET",
  "path": "/protected"
}
```

### Step 4c: Call User Data API

| Field | Value |
|-------|-------|
| **URL** | `https://<ec2-1-public-ip>:10000/api/user-data` |
| **Method** | GET |
| **Headers** | `Authorization: Bearer <access_token>` |

### Expected Result

```json
{
  "data": [
    {"id": 1, "title": "Báo cáo tài chính Q1", "content": "..."},
    {"id": 2, "title": "Tài liệu dự án", "content": "..."},
    {"id": 3, "title": "Hồ sơ nhân viên", "content": "..."}
  ],
  "message": "Dữ liệu người dùng — yêu cầu role 'user'",
  "your_roles": ["admin", "user"]
}
```

---

## Scenario 5: Failure Scenarios

**Goal**: Demonstrate security controls rejecting invalid requests.

### Scenario 5a: No Client Certificate

**Steps**:
1. In Postman, disable the client certificate for the host
2. Send GET to `https://<ec2-1-public-ip>:10000/protected`
3. OR use curl:
   ```bash
   curl --insecure https://<ec2-1-public-ip>:10000/protected
   ```

**Expected Result**: `curl: (35) error:1401E410:SSL routines:CONNECT_CR_FINISHED:sslv3 alert handshake failure`
- Connection **refused at TLS level** — Envoy requires client certificate

### Scenario 5b: Valid Certificate, No JWT

**Steps**:
```bash
curl --cert vault/artifacts/client.crt \
     --key vault/artifacts/client.key \
     --cacert vault/artifacts/root_ca.crt \
     https://<ec2-1-public-ip>:10000/protected
```

**Expected Result**: `401 Unauthorized`
- mTLS handshake succeeds (valid cert) but ext_authz rejects (no JWT)

### Scenario 5c: Valid Certificate, Wrong JWT (Binding Mismatch)

**Steps**:
```bash
# Get a valid token
TOKEN=$(curl -sf -X POST http://<ec2-2-ip>:8080/realms/zero-trust/protocol/openid-connect/token \
  -d "grant_type=password&client_id=web-app&username=admin&password=admin" | \
  python3 -c "import json,sys;print(json.load(sys.stdin)['access_token'])")

# Use token with a DIFFERENT client certificate (e.g., a second client cert)
curl --cert vault/artifacts/mismatch-client.crt \
     --key vault/artifacts/mismatch-client.key \
     --cacert vault/artifacts/root_ca.crt \
     -H "Authorization: Bearer $TOKEN" \
     https://<ec2-1-public-ip>:10000/protected
```

**Expected Result**: `403 Forbidden`
- Token signature valid, but `cnf.x5t#S256` thumbprint does not match the presented certificate

### Scenario 5d: Replay Attack (Same JWT Used Twice)

**Steps**:
```bash
TOKEN=$(curl -sf -X POST http://<ec2-2-ip>:8080/realms/zero-trust/protocol/openid-connect/token \
  -d "grant_type=password&client_id=web-app&username=admin&password=admin" | \
  python3 -c "import json,sys;print(json.load(sys.stdin)['access_token'])")

# First request — should succeed
curl --cert vault/artifacts/client.crt \
     --key vault/artifacts/client.key \
     --cacert vault/artifacts/root_ca.crt \
     -H "Authorization: Bearer $TOKEN" \
     https://<ec2-1-public-ip>:10000/protected

# Second request with same token — should be rejected
curl --cert vault/artifacts/client.crt \
     --key vault/artifacts/client.key \
     --cacert vault/artifacts/root_ca.crt \
     -H "Authorization: Bearer $TOKEN" \
     https://<ec2-1-public-ip>:10000/protected
```

**Expected Result**:
- First request: `200 OK`
- Second request: `403 Forbidden` — JTI already in replay cache

### Scenario 5e: Revoked Certificate

**Steps**:
```bash
curl --cert vault/artifacts/revoked-client.crt \
     --key vault/artifacts/revoked-client.key \
     --cacert vault/artifacts/root_ca.crt \
     -H "Authorization: Bearer $TOKEN" \
     https://<ec2-1-public-ip>:10000/protected
```

**Expected Result** (if CRL checking enabled): `403 Forbidden`
- Certificate is revoked and listed in CRL
- Note: CRL checking must be configured in Envoy validation context

### Scenario 5f: Expired JWT

**Steps**:
```bash
# Wait for token to expire (or craft an expired token)
# Use a token with past `exp`
curl --cert vault/artifacts/client.crt \
     --key vault/artifacts/client.key \
     --cacert vault/artifacts/root_ca.crt \
     -H "Authorization: Bearer <expired_token>" \
     https://<ec2-1-public-ip>:10000/protected
```

**Expected Result**: `401 Unauthorized`
- ext_authz rejects expired JWT (`exp` claim validation)

---

## Summary of Expected Results

| Scenario | Input | Expected HTTP Status | Security Layer |
|----------|-------|---------------------|----------------|
| 1. Browser login | Valid credentials | 200 (redirect) | JWT auth |
| 2. Dashboard admin | Admin JWT | 200 all endpoints | RBAC |
| 2. Dashboard user | User JWT | 403 on admin-data | RBAC |
| 4. Postman valid | Cert + JWT | 200 | mTLS + JWT + binding |
| 5a. No cert | None | SSL handshake fail | mTLS |
| 5b. Cert, no JWT | Cert only | 401 | JWT verify |
| 5c. Wrong binding | Cert A + JWT for Cert B | 403 | Cert binding |
| 5d. Replay | Same JWT twice | 200 then 403 | Replay cache |
| 5e. Revoked cert | Revoked cert + valid JWT | 403 (if CRL enabled) | CRL |
| 5f. Expired JWT | Expired token | 401 | Claim validation |
