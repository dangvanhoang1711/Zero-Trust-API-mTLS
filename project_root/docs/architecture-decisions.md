---
title: architecture-decisions

---

# Architecture Decisions & Rationale (ADR)

**Project:** Zero-Trust API Authentication Proxy (mTLS + PoP)  
**Course:** NT219 — Cryptography  
**Objective:** Lựa chọn và biện giải stack công nghệ dựa trên yêu cầu bảo mật, hiệu năng, và nguyên lý mật mã học trong mô hình Zero-Trust.

---

# 1. API Gateway / Edge Proxy

## 1.1 So sánh các giải pháp

| Tiêu chí       | Envoy Proxy                   | Kong Gateway             | NGINX                      |
| -------------- | ----------------------------- | ----------------------- | -------------------------- |
| Kiến trúc      | Cloud-native (Sidecar / Edge) | Centralized Gateway     | Web Server / Reverse Proxy |
| ext_authz      | Rất mạnh (gRPC/HTTP native)  | Trung bình (Lua plugin) | Hạn chế                    |
| mTLS Support   | Native + tối ưu mesh          | Tốt                     | Tốt                        |
| Dynamic Config | XDS API / YAML                | DB / Admin API          | Static config              |
| Hiệu năng TLS  | Rất cao (C++)                 | Cao                     | Cao                        |

## 1.2 Quyết định: Envoy Proxy

### Lý do kỹ thuật

1. **External Authorization (ext_authz)**  
   - Envoy hỗ trợ filter `ext_authz` native, giao tiếp qua gRPC.  
   - Cho phép tách riêng logic xác thực ra service bên ngoài, hỗ trợ các cơ chế phức tạp:  
     - JWT verification  
     - mTLS certificate binding  
     - DPoP verification  
   - Đây là yêu cầu cốt lõi của mô hình Zero-Trust, nơi mọi request phải được xác thực đầy đủ trước khi tiếp cận dịch vụ.

2. **X.509 Metadata Extraction**  
   - Envoy trích xuất thông tin certificate từ TLS handshake (Subject, SAN, fingerprint).  
   - Forward metadata qua header chuẩn `x-forwarded-client-cert (XFCC)`.  
   - ext_authz service có thể tính hash certificate và so khớp với token để đảm bảo PoP/mTLS binding.

3. **Hiệu năng và bảo mật**  
   - Viết bằng C++ → tối ưu TLS termination, connection pooling.  
   - Phù hợp cho môi trường microservices có throughput cao, yêu cầu latency thấp.  
   - Hỗ trợ dynamic configuration, dễ tích hợp trong cloud-native environment.

---

# 2. Identity Provider (IdP)

## 2.1 So sánh

| Tiêu chí        | Keycloak (Self-hosted) | Auth0 (SaaS)        |
| --------------- | ---------------------- | ------------------- |
| Key Control     | Full control           | Phụ thuộc vendor    |
| RFC 8705 (mTLS) | Native support         | Limited             |
| DPoP Support    | Có thể mở rộng         | Hạn chế             |
| Chi phí         | Free (OSS)             | Paid                |
| Customization   | Rất cao (SPI)          | Trung bình          |

## 2.2 Quyết định: Keycloak

### Lý do kỹ thuật

1. **Quản lý khóa mật mã (Key Ownership)**  
   - Quản lý private key cho JWT signing và public key (JWKS) cho verification.  
   - Hỗ trợ thuật toán ES256, key rotation.  
   - Đáp ứng nguyên tắc **không phụ thuộc bên thứ ba** trong quản lý khóa mật mã.

2. **Hỗ trợ token binding**  
   - mTLS: `cnf.x5t#S256`  
   - DPoP: `cnf.jkt`  
   - Cho phép implement PoP tokens, tăng cường Zero-Trust authentication.

3. **Self-hosted**  
   - Deploy bằng Docker, chạy nội bộ, không phụ thuộc kết nối internet.  
   - Dễ tích hợp với các công cụ quản lý PKI và orchestrator (Kubernetes).

---

# 3. ext_authz Service — Ngôn ngữ

## 3.1 So sánh

| Tiêu chí    | Go         | Python  | NodeJS     |
| ----------- | ---------- | ------- | ---------- |
| Hiệu năng   | Rất cao    | Thấp    | Trung bình |
| Concurrency | Goroutines | Threads | Event loop |
| gRPC        | Native     | Tốt     | Trung bình |
| Crypto      | Rất mạnh   | Tốt     | Tốt        |
| Typing      | Static     | Dynamic | Dynamic    |

## 3.2 Quyết định: Go (Golang)

### Lý do kỹ thuật

1. **Hiệu năng (Critical Path)**  
   - ext_authz service nằm trên mọi request → low latency, high throughput là yêu cầu bắt buộc.  
   - Go xử lý concurrency với goroutines hiệu quả, phù hợp môi trường API-intensive.

2. **Thư viện mật mã chuẩn hóa**  
   - `crypto/x509` → xử lý certificate  
   - `crypto/ecdsa` → verify ES256 signature  
   - `crypto/sha256` → hashing  
   - Giảm thiểu rủi ro implementation bug, đáp ứng yêu cầu cryptography-level security.

3. **Triển khai đơn giản**  
   - Compile thành 1 binary → không cần runtime interpreter.  
   - Dễ dàng containerize và deploy trên Kubernetes hoặc Docker Swarm.

---

# 4. Token Binding Strategy

## 4.1 Lý do

Không có một cơ chế duy nhất phù hợp cho mọi loại client:

| Client Type | Constraint               |
| ----------- | ------------------------ |
| Server      | Hỗ trợ mTLS              |
| Mobile      | TLS không ổn định        |
| Browser     | Không expose private key |

## 4.2 Quyết định: Hybrid Model

1. **mTLS-bound Token (RFC 8705)**  
   - Server ↔ Server  
   - Bảo mật mạnh: Layer 4 + Layer 7

2. **DPoP (RFC 9449)**  
   - Mobile / SPA  
   - Mỗi request có signature riêng  
   - Không cần mTLS

3. **Holder-of-Key JWT**  
   - Dựa trên `cnf` claim  
   - Nền tảng chung cho mTLS và DPoP

---

# 5. Supporting Components

1. **PKI — HashiCorp Vault**  
   - Root CA, issue certificate, manage lifecycle  
   - Hỗ trợ key rotation, revocation  
   - Mô phỏng HSM cho môi trường tự quản lý.

2. **cert-manager**  
   - Tự động issue & renew certificate  
   - Tích hợp Kubernetes, giảm thao tác thủ công.

3. **Redis (Replay Protection)**  
   - Lưu `jti`, nonce  
   - TTL-based cache  
   - Ngăn replay attack, tăng cường security.

---

# 6. Final Stack Summary

| Component    | Technology     | Role                   |
| ------------ | -------------- | ---------------------- |
| Gateway      | Envoy          | TLS termination + routing          |
| Auth Service | Go (ext_authz) | Verify token & PoP binding |
| IdP          | Keycloak       | Issue JWT, manage keys |
| PKI          | Vault          | Certificate lifecycle  |
| Cache        | Redis          | Replay protection      |

---

# 7. Security Justification

## Multi-layer Security

| Layer       | Mechanism |
| ----------- | --------- |
| Transport   | mTLS      |
| Application | DPoP      |
| Token       | JWT (JWS) |

## Defense-in-Depth

- Token bị leak → không sử dụng được  
- Request replay → bị chặn  
- Payload bị sửa → signature verification fail  

---

# 8. Conclusion

Kiến trúc được lựa chọn dựa trên:

- Nguyên lý mật mã học (ECDSA, PKI, certificate binding)  
- Mô hình Zero-Trust: mọi request đều phải được xác thực, client phải chứng minh quyền sở hữu khóa  
- Yêu cầu thực tế: hỗ trợ Web, Mobile, Backend

Hệ thống không chỉ xác thực **identity**, mà còn xác thực:

> “Client có thực sự sở hữu khóa mật mã tương ứng hay không”

Điều này cung cấp nền tảng vững chắc cho **hệ thống API an toàn trong môi trường cloud-native hiện đại**.