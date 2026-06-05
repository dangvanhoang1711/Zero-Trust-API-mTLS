---
title: literature-review

---

# 📚 Literature Review — Zero-Trust API Authentication

**Project:** Zero-Trust API Authentication Proxy (mTLS + DPoP)
**Course:** NT219 — Cryptography

---

# 1. OAuth 2.0 Authorization Framework (RFC 6749)

## 1.1 Overview

OAuth 2.0 là một **authorization framework** cho phép ứng dụng bên thứ ba truy cập tài nguyên thay mặt người dùng mà không cần chia sẻ trực tiếp thông tin xác thực (username/password).

Trong mô hình này:

* **Access Token** đóng vai trò là bằng chứng ủy quyền
* Token được cấp bởi **Authorization Server (IdP)** như Keycloak
* Client sử dụng token để truy cập **Resource Server (API)**

---

## 1.2 Bearer Token Problem & Zero-Trust Perspective

Theo RFC 6750, Access Token mặc định là **Bearer Token**, nghĩa là:

> “Whoever holds the token can use it”

### ⚠️ Rủi ro:

* Token bị lộ qua:
  * Log
  * MITM attack
  * XSS
* Không có cơ chế ràng buộc token với client

---

## 1.3 Zero-Trust Solution: Sender-Constrained Tokens

Để khắc phục, hệ thống chuyển sang:

### Proof-of-Possession (PoP) Tokens

* Token chỉ hợp lệ nếu client **chứng minh được sở hữu private key**
* Kẻ tấn công có token nhưng **không có key → vô dụng**

---

# 2. JWT (RFC 7519) & JWS (RFC 7515)

## 2.1 JSON Web Token (JWT)

JWT là chuẩn để biểu diễn thông tin dưới dạng JSON, được encode thành:

```
Header.Payload.Signature
```

### Thành phần:

* **Header**: thuật toán (alg), kiểu (typ)
* **Payload**: chứa claims
* **Signature**: chữ ký số

### Các claim quan trọng:

| Claim | Ý nghĩa                     |
| ----- | --------------------------- |
| sub   | Subject (user)              |
| exp   | Expiration                  |
| iat   | Issued time                 |
| iss   | Issuer                      |
| aud   | Audience                    |
| cnf   | Confirmation (dùng cho PoP) |

---

## 2.2 JSON Web Signature (JWS)

JWS đảm bảo:
* Tính toàn vẹn (Integrity)
* Xác thực nguồn (Authenticity)

Trong hệ thống này:
* Thuật toán chính: **ES256 (ECDSA + SHA-256)**

---

# 3. Cryptographic Foundation — ECDSA (ES256)

## 3.1 Elliptic Curve (P-256)

Hệ thống sử dụng đường cong NIST P-256:

$$
y^2 \equiv x^3 + ax + b \pmod{p}
$$

### Tham số:

* $p$: số nguyên tố lớn (~256-bit)
* $a = -3$
* $G$: base point
* $n$: order của $G$

---

## 3.2 Key Generation

* Private key: $d \in [1, n-1]$
* Public key: $Q = d \cdot G$

Bảo mật dựa trên:

> Elliptic Curve Discrete Logarithm Problem (ECDLP)

---

## 3.3 Signing Process (JWS)

Với message $M$:

1. $e = \text{SHA-256}(M)$
2. Chọn random $k$
3. $(x_1, y_1) = kG$
4. $r = x_1 \mod n$
5. $s = k^{-1}(z + r \cdot d) \mod n$

-> Signature: $(r, s)$

---

## 3.4 Verification Process

1. Tính:

   * $u_1 = z \cdot s^{-1}$
   * $u_2 = r \cdot s^{-1}$
2. Tính:
   $$
   (x_1, y_1) = u_1 G + u_2 Q
   $$
3. Hợp lệ nếu:
   $$
   r \equiv x_1 \mod n
   $$

---

# 4. OAuth 2.0 mTLS (RFC 8705)

## 4.1 Certificate-Bound Tokens

mTLS cung cấp:

* Mutual authentication (client + server)
* Binding token với certificate

---

## 4.2 Binding Mechanism

Token chứa:

```
cnf.x5t#S256 = SHA-256(cert)
```

### Công thức:

$$
x5t.S256 = \text{Base64Url}(\text{SHA-256}(\text{Certificate}))
$$

-> Proxy sẽ:

* Lấy cert từ TLS handshake
* Hash lại
* So sánh với token

---

## 4.3 Security Benefit

* Token bị leak →  không reused được
* Vì attacker không có private key của cert

---

# 5. DPoP — Proof-of-Possession (RFC 9449)

## 5.1 Application-layer Binding

DPoP hoạt động ở Layer 7:

* Không cần mTLS
* Phù hợp web/mobile

---

## 5.2 DPoP Proof Structure

Mỗi request gửi kèm:

* JWT (DPoP proof)
* Signed bằng private key

### Payload gồm:

* `htm` (HTTP method)
* `htu` (URL)
* `iat` (timestamp)
* `jti` (unique ID)

---

## 5.3 Binding Mechanism

Token chứa:

```
cnf.jkt = SHA-256(public key)
```

-> Proxy verify:

* Signature của DPoP
* Key match với token

---

## 5.4 Security

* Chống replay attack
* Chống token theft
* Mỗi request có signature riêng

---

# 6. Holder-of-Key JWT & HTTP Signatures

## 6.1 cnf Claim

Claim quan trọng nhất:

* Xác định **key** mà client sở hữu

---

## 6.2 HTTP Message Signatures (RFC 9421)

Cho phép ký toàn bộ HTTP request:

### Signature Base gồm:

* Method
* Path
* Headers
* Body hash

---

## 6.3 Security Benefit

* Ngăn chặn:

  * Data tampering
  * Proxy injection
* Đảm bảo integrity end-to-end

---

# 7. OWASP API Security & NIST PKI

## 7.1 OWASP API Top 10

| Risk                  | Mitigation  |
| --------------------- | ----------- |
| Broken Authentication | mTLS + DPoP |
| Token Theft           | PoP binding |
| Replay Attack         | jti + nonce |

---

## 7.2 NIST SP 800-57 (PKI)

### Key Management:

* Key rotation
* Key revocation
* Short-lived certificates

### Implementation:

* Vault = PKI backend
* cert-manager = automation

---

# 8. Summary Table

| Standard | Crypto        | Purpose         | Tech       |
| -------- | ------------- | --------------- | ---------- |
| RFC 7515 | ECDSA         | Token integrity | Keycloak   |
| RFC 8705 | SHA-256       | mTLS binding    | Envoy      |
| RFC 9449 | PoP           | Anti-replay     | Go + Redis |
| RFC 9421 | HTTP Sig      | Integrity       | Custom     |
| NIST     | PKI lifecycle | Key mgmt        | Vault      |

---

# 9. Conclusion

Hệ thống mô hình **Defense-in-Depth**:

* Layer 4: mTLS
* Layer 7: PoP (DPoP)
* Token layer: JWT (JWS)

-> Không chỉ xác thực **identity**, mà còn xác thực:

> “Client có thực sự sở hữu key hay không”

Điều này đáp ứng đầy đủ yêu cầu của **Zero-Trust Security Model** trong môi trường cloud-native.

---
