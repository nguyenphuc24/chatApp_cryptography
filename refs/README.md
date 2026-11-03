# Danh mục tài liệu tham khảo và mã nguồn mở sử dụng (Refs)

Thư mục này tổng hợp toàn bộ các tiêu chuẩn mật mã quốc tế (RFC, NIST) và các thư viện mã nguồn mở được nghiên cứu, áp dụng trong đồ án **"Hệ thống Chat & Truyền tệp Mã hoá Đầu cuối kết hợp Hạ tầng PKI Nội bộ"**.

---

## 1. Tiêu chuẩn mật mã quốc tế (RFC & NIST Standards)

1. **RFC 5280:** *Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile.*
   - Sử dụng cho: Định dạng chứng chỉ số X.509v3, quy tắc kiểm tra đường dẫn tin cậy (certificate path validation), cấu trúc danh sách thu hồi chứng chỉ (CRL) với các trường `thisUpdate`, `nextUpdate`, `revokedCertificates`, `reasonCode`.
   - Áp dụng trong: `src/pki.py`, `src/crl.py`, `tools/make_pki.py`.

2. **RFC 6960:** *X.509 Internet Public Key Infrastructure Online Certificate Status Protocol - OCSP.*
   - Sử dụng cho: Giao thức kiểm tra trạng thái chứng chỉ trực tuyến thời gian thực (OCSP Responder), cấu trúc `OCSPRequest` và `OCSPResponse` (GOOD, REVOKED, UNKNOWN) mã hoá DER.
   - Áp dụng trong: `src/ocsp_server.py`, `src/pki.py` (`verify_cert_with_ocsp`).

3. **RFC 8017 (PKCS #1 v2.2):** *RSA Cryptography Specifications.*
   - Sử dụng cho: Lược đồ mã hoá bất đối xứng RSA-OAEP (Optimal Asymmetric Encryption Padding) với SHA-256 dùng để bọc khoá phiên (Key Wrapping) và chữ ký số RSA-PSS (Probabilistic Signature Scheme) với salt ngẫu nhiên chống giả mạo chữ ký.
   - Áp dụng trong: `src/crypto_utils.py`, `src/handshake.py`, `src/e2e.py`.

4. **NIST SP 800-38A:** *Recommendation for Block Cipher Modes of Operation: Methods and Techniques.*
   - Sử dụng cho: Chế độ mã hóa khối AES-CBC (Advanced Encryption Standard - Cipher Block Chaining) 256-bit với IV ngẫu nhiên 16 bytes sinh bằng CSPRNG (`os.urandom` / `secrets.token_bytes`).
   - Áp dụng trong: `src/crypto_utils.py`.

5. **RFC 2104:** *HMAC: Keyed-Hashing for Message Authentication.*
   - Sử dụng cho: Mã xác thực thông điệp HMAC-SHA256 kết hợp cùng AES theo mô hình **Encrypt-then-MAC (EtM)** — bảo vệ tính toàn vẹn và tính xác thực cho cả IV và Ciphertext.
   - Áp dụng trong: `src/crypto_utils.py`, `src/session.py`.

6. **RFC 5652 (CMS):** *Cryptographic Message Syntax.*
   - Sử dụng cho: Kỹ thuật bọc khóa nhiều người nhận (Multi-recipient key encapsulation) cho phòng chat chung E2E.
   - Áp dụng trong: `src/e2e.py`.

---

## 2. Thư viện mã nguồn mở chính (Open-Source Libraries)

1. **`cryptography` (Python Cryptographic Authority - PyCA):**
   - Phiên bản: $\ge 43.0.0$ (Khuyến nghị 50.0.2)
   - Giấy phép: Apache License 2.0 / BSD 3-Clause
   - Kho lưu trữ: https://github.com/pyca/cryptography
   - Tài liệu: https://cryptography.io/
   - Vai trò trong dự án: Cung cấp các nguyên hàm mật mã bậc thấp (AES, SHA-256, HMAC, RSA-OAEP, RSA-PSS, X.509 Certificates, CRL, OCSP).

2. **`pycryptodome`:**
   - Phiên bản: $\ge 3.20.0$ (Khuyến nghị 4.2.0)
   - Giấy phép: Public Domain / BSD
   - Kho lưu trữ: https://github.com/Legrandin/pycryptodome
   - Tài liệu: https://www.pycryptodome.org/
   - Vai trò trong dự án: Hỗ trợ đối chiếu chéo (cross-validation) tính tương thích của các thuật toán mã hoá.

3. **Python Standard Library (Zero-Dependency Utilities):**
   - `socket`, `select`, `struct`: Tầng truyền thông mạng TCP socket, đóng khung nhị phân Big-Endian 4-byte.
   - `threading`: Xử lý tương tranh đa luồng, đồng bộ hoá socket an toàn với `threading.Lock`.
   - `hashlib`, `hmac`, `secrets`: Băm SHA-256, sinh entropy ngẫu nhiên bảo mật chuẩn CSPRNG.
   - `http.server`, `urllib`: Máy chủ HTTP phục vụ OCSP Responder và HTTP client truy vấn trạng thái chứng chỉ trực tuyến.
   - `unittest`: Khung kiểm thử tự động toàn diện bao phủ 77 ca kiểm định.

