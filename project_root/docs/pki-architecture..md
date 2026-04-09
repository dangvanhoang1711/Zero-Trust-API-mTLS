# PKI Architecture & Secrets Management

Hệ thống triển khai hạ tầng khóa công khai (PKI) phân cấp để đảm bảo tính xác thực, toàn vẹn và bảo mật dữ liệu trên đường truyền (Data-in-transit) theo nguyên tắc **Zero Trust**.

## 1. Cấu trúc phân cấp (CA Hierarchy)

Hệ thống sử dụng mô hình PKI 2 tầng được quản lý tập trung bởi **HashiCorp Vault**:

1.  **Root CA (Level 1)**: 
    - Là điểm tin cậy gốc (Trust Anchor).
    - Được lưu trữ biệt lập trong Vault (`pki_root`).
    - Vai trò: Chỉ dùng để ký và xác thực cho Intermediate CA.
2.  **Intermediate CA (Level 2)**:
    - Được ký bởi Root CA.
    - Lưu trữ tại đường dẫn `pki_int`.
    - Vai trò: Trực tiếp cấp phát và quản lý vòng đời chứng chỉ (Certificate Lifecycle) cho các thực thể cuối (End-entities).
3.  **End-entity Certificates (Level 3)**:
    - Các chứng chỉ TLS cấp cho: **Envoy Gateway**, **Keycloak**, và các **Microservices**.



## 2. Công nghệ sử dụng
- **Cơ chế lưu trữ**: HashiCorp Vault (PKI Secrets Engine).
- **Thuật toán ký số**: RSA 2048-bit (hoặc ECDSA P-256).
- **Giao thức**: TLS 1.3 / HTTP/2 (với ALPN).

## 3. Quy trình cấp phát (Provisioning Workflow)
1. **Khởi tạo**: Admin cấu hình PKI Engine trên Vault và thiết lập `zero-trust-role`.
2. **Yêu cầu**: Các dịch vụ (như Envoy) gửi yêu cầu cấp chứng chỉ dựa trên định danh (Common Name).
3. **Phân phối**: Chứng chỉ (`.crt`) và khóa riêng (`.key`) được xuất dưới dạng JSON và mount trực tiếp vào container thông qua Docker Volumes.
4. **Thực thi**: Envoy sử dụng bộ chứng chỉ này để thực hiện **TLS Termination**, chuyển đổi lưu lượng từ HTTP sang HTTPS an toàn.

## 4. Bảo mật khóa riêng (Private Key Security)
- Khóa riêng của CA được lưu trữ an toàn trong vùng nhớ của Vault.
- Khóa riêng của dịch vụ (Envoy) chỉ tồn tại trong bộ nhớ tạm và thư mục cấu hình được bảo vệ, không được chia sẻ qua mạng.