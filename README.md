# Secure Chat & File Transfer (E2E Encrypted & PKI Authenticated)

**Khoa Khoa Học & Kỹ Thuật Máy Tính – Trường Đại Học Bách Khoa ĐHQG-HCM**  
**Môn học:** Mật mã & An ninh mạng (CO3083) — **BÀI TẬP LỚN SỐ 1 (HK261)**  
**Đề tài:** Phát triển ứng dụng mật mã và truyền thông bảo mật kết hợp Hạ tầng Khóa công khai nội bộ  
**Nhóm sinh viên thực hiện:**  
- Sinh viên 1: **2412716**  
- Sinh viên 2: **2412760**  

---

## 1. Giới thiệu tổng quan hệ thống

Hệ thống được thiết kế và hiện thực nhằm đáp ứng trọn vẹn **hai mục tiêu cốt lõi** theo yêu cầu của Đề bài tập lớn số 1:

1. **Mục tiêu 1.1 — Hệ thống Chat & Truyền tệp mã hoá đầu cuối (E2E):**
   - **Trao đổi khoá phiên:** Kết hợp mã hóa bất đối xứng **RSA-OAEP-SHA256 (2048-bit)** và chữ ký số **RSA-PSS-SHA256** trong giao thức bắt tay 4 bước xác thực hai chiều chống tấn công Man-in-the-Middle (MitM).
   - **Mã hoá đối xứng kênh truyền:** Tầng Record Layer áp dụng mô hình chuẩn **Encrypt-then-MAC (EtM)** với **AES-256-CBC** và **HMAC-SHA256**.
   - **Bảo mật đầu cuối (E2E):** Tin nhắn và tệp tin được mã hóa độc lập bằng khóa ngẫu nhiên, bọc khóa bằng RSA-OAEP cho từng bên nhận hợp pháp. Server đóng vai trò trung gian chuyển tiếp (relay) bản mã, hoàn toàn **không thể đọc được nội dung gốc**.
   - **Truyền tệp phân mảnh (Chunking):** File được chia nhỏ 4 KiB/chunk, ràng buộc số thứ tự mảnh trong MAC và đối chiếu mã băm **SHA-256** toàn vẹn trước khi ghi đĩa.

2. **Mục tiêu 1.2 — Hạ tầng Khóa công khai nội bộ (Internal PKI):**
   - **Root CA X.509v3:** Tự động khởi tạo CA tự ký với thuật toán RSA 2048-bit, cấp phát chứng thư số cho Server và các nhóm Client tuân thủ **RFC 5280**.
   - **Danh sách thu hồi chứng thư (CRL — RFC 5280):** Hỗ trợ CA thu hồi chứng chỉ trước thời hạn, phát hành tệp `pki/ca.crl` có chữ ký số CA, kiểm tra `thisUpdate`/`nextUpdate` và số serial bị thu hồi (kiểm tra offline).
   - **Giao thức trạng thái chứng thư trực tuyến (OCSP — RFC 6960):** Dịch vụ OCSP Responder HTTP xử lý `OCSPRequest` DER và ký số phản hồi `OCSPResponse` (GOOD / REVOKED / UNKNOWN) tức thời (kiểm tra online).
   - **Kịch bản thực nghiệm:** Kịch bản demo đầu-cuối (`tools/demo_revoke.py`) kiểm chứng đầy đủ quá trình thu hồi chứng chỉ và từ chối kết nối.

### Bảng chi tiết lồng ghép MSSV nhóm theo yêu cầu đề bài:

| Yêu cầu đề bài | Quy cách quy định | Hiện thực thực tế trong hệ thống |
| :--- | :--- | :--- |
| **Dữ liệu kiểm thử Plaintext** | Chuỗi bắt đầu: `Hello, We are [MSSV_1], [MSSV_2], ..` | Trong `src/handshake.py`, body của gói `HANDSHAKE_INIT` bắt buộc chứa trường `message = "Hello, We are 2412716, 2412760"`. |
| **Khóa khởi tạo bí mật (KDF)** | Băm từ MSSV: `Key = SHA256(MSSV_1 \|\| MSSV_2 ..)` | Trong `src/crypto_utils.py`, `kdf_session_key()` tính `SHA256(MS \|\| enc_list(mssv_list) \|\| enc(nonce_bytes))` kết hợp mã hóa canonical chống nhập nhằng chuỗi. |
| **Thông tin CA Subject (CN)** | `CA-Root-[MSSV_1]-[MSSV_2] ..` | Root CA được cấp thuộc tính: `CN = CA-Root-2412716-2412760`. |
| **Thông tin CA Subject (OU)** | `Faculty of Computer Science and Engineer – [MSSV_1]-[MSSV_2] ..` | Root CA được cấp thuộc tính: `OU = Faculty of Computer Science and Engineer – 2412716-2412760`. |

---

## 2. Cấu trúc cây thư mục dự án

Dự án được tổ chức chặt chẽ theo đúng yêu cầu nộp bài của Đồ án:

```
chatApp_cryptography/
├── src/                               # Toàn bộ mã nguồn ứng dụng (Thư mục mã nguồn chính)
│   ├── pki.py                         # Quản lý X.509, thẩm định chứng chỉ, tích hợp CRL & OCSP
│   ├── crl.py                         # Module tạo, ký, nạp và kiểm tra danh sách thu hồi CRL (RFC 5280)
│   ├── ocsp_server.py                 # Dịch vụ OCSP Responder HTTP theo RFC 6960
│   ├── crypto_utils.py                # Nguyên hàm mật mã: AES-CBC, EtM, RSA-OAEP, RSA-PSS, KDF, Canonical Map
│   ├── framing.py                     # Khung truyền TCP [ length (4B big-endian) ][ payload ], chống DoS
│   ├── session.py                     # Record layer: EtM, seq đơn điệu, timestamp, thread lock, heartbeat
│   ├── handshake.py                   # Giao thức bắt tay xác thực hai chiều chống MitM & Replay
│   ├── e2e.py                         # Tầng mã hoá đầu cuối E2E Chat & E2E File phân mảnh 4 KiB
│   ├── server.py                      # Máy chủ TCP đa luồng: Relay E2E, quản lý Roster, lưu file, Graceful Shutdown
│   └── client.py                      # Ứng dụng Client CLI tương tác người dùng
├── pki/                               # Hạ tầng chứng chỉ số nội bộ (PKI)
│   ├── ca.crt, ca.key                 # Root CA tự ký (Root Certificate Authority)
│   ├── ca.crl                         # Danh sách thu hồi chứng chỉ (Certificate Revocation List)
│   ├── revoked.json                   # Cơ sở dữ liệu theo dõi serial cert bị thu hồi
│   ├── server.crt, server.key         # Chứng chỉ số Server (CN=chat-server, SAN=localhost/127.0.0.1)
│   └── team*/                         # Thư mục chứng chỉ số của từng nhóm Client (CN=<team>, UID=MSSV)
├── tools/                             # Công cụ quản trị PKI và thực nghiệm
│   ├── make_pki.py                    # Script tự động tạo Root CA, cấp phát cert, tạo CRL và thu hồi cert
│   └── demo_revoke.py                 # Kịch bản thực nghiệm đầu-cuối quy trình thu hồi chứng chỉ (CRL/OCSP)
├── tests/                             # Bộ kiểm thử tự động toàn diện (77 Test Cases trong 16 tập tin)
│   ├── test_concurrency.py            # Kiểm thử an toàn đa luồng & tương tranh
│   ├── test_crl.py                    # [Mới] Kiểm thử phát hành và xác thực CRL offline
│   ├── test_crypto.py                 # Kiểm thử nguyên hàm mật mã EtM, RSA-OAEP, RSA-PSS
│   ├── test_e2e_chat.py               # Kiểm thử bảo mật mã hóa đầu cuối tin nhắn
│   ├── test_e2e_file.py               # Kiểm thử bảo mật truyền tệp phân mảnh E2E
│   ├── test_files_server.py           # Kiểm thử lưu trữ an toàn, chống Path Traversal
│   ├── test_framing.py                # Kiểm thử tầng khung truyền, giới hạn MAX_FRAME
│   ├── test_handshake.py              # Kiểm thử quy trình bắt tay 4 bước
│   ├── test_integration_tcp.py        # Kiểm thử tích hợp Client-Server qua mạng TCP thật
│   ├── test_kdf.py                    # Kiểm thử KDF & tính nhạy cảm thứ tự MSSV
│   ├── test_mitm_demo.py              # Kiểm thử tấn công MitM & can thiệp 1-bit trên đường truyền
│   ├── test_ocsp.py                   # [Mới] Kiểm thử dịch vụ OCSP Responder HTTP online
│   ├── test_pki.py                    # Kiểm thử xác thực chứng chỉ số X.509
│   ├── test_replay.py                 # Kiểm thử phòng chống tấn công phát lại (Replay)
│   ├── test_server_graceful_shutdown.py # [Mới] Kiểm thử tắt máy chủ an toàn
│   └── test_timeout.py                # Kiểm thử Heartbeat và Socket Timeout
├── refs/                              # Tài liệu tham khảo và mã nguồn mở sử dụng
│   └── README.md                      # Chi tiết các tiêu chuẩn RFC, NIST và thư viện nguồn mở
├── requirements.txt                   # Danh sách thư viện phụ thuộc (cryptography, pycryptodome)
├── HANDBOOK.md                        # Cẩm nang kỹ thuật chuyên sâu (thiết kế, phân tích, debug)
├── REPORT.md                          # Báo cáo kỹ thuật đồ án đầy đủ (theo mẫu yêu cầu)
└── README.md                          # Tài liệu hướng dẫn sử dụng hệ thống
```

---

## 3. Cài đặt môi trường

Hệ thống yêu cầu môi trường **Python $\ge$ 3.10** (đã kiểm định tối ưu trên Python 3.10 – 3.13).

```bash
# 1. Mở Terminal / PowerShell tại thư mục gốc chatApp_cryptography

# 2. Khởi tạo môi trường ảo Python:
python -m venv .venv

# 3. Kích hoạt môi trường ảo:
# Trên Windows PowerShell:
.\.venv\Scripts\Activate.ps1
# Trên Linux / macOS:
# source .venv/bin/activate

# 4. Cài đặt các thư viện mật mã phụ thuộc:
pip install -r requirements.txt
```

---

## 4. Quản lý Hạ tầng Khóa công khai (PKI, CRL & OCSP)

Công cụ `tools/make_pki.py` cung cấp đầy đủ chức năng quản trị CA, cấp phát và thu hồi chứng chỉ:

### 4.1. Khởi tạo Root CA và Chứng chỉ Server
```bash
python tools/make_pki.py
```
- Khởi tạo Root CA tự ký với $CN = \text{CA-Root-2412716-2412760}$ và $OU = \text{Faculty of Computer Science and Engineer – 2412716-2412760}$.
- Cấp chứng chỉ TLS cho Server ($CN = \text{chat-server}$, $SAN = \text{localhost/127.0.0.1}$) tích hợp sẵn phần mở rộng **CDP** và **AIA (OCSP)**.

### 4.2. Cấp phát chứng chỉ số cho các nhóm sinh viên (Client)
```bash
# Cấp chứng chỉ cho Nhóm 1:
python tools/make_pki.py --team team1 --mssv 2412716 2412760

# Cấp chứng chỉ cho Nhóm 2:
python tools/make_pki.py --team team2 --mssv 2312716 2312760

# Cấp chứng chỉ cho Nhóm 3 (dùng thử nghiệm thu hồi):
python tools/make_pki.py --team team3 --mssv 2512716 2512760
```

### 4.3. Quản lý danh sách thu hồi CRL và OCSP
```bash
# 1. Tạo hoặc làm mới danh sách thu hồi CRL ban đầu:
python tools/make_pki.py --crl

# 2. Thu hồi chứng chỉ (ví dụ lộ khóa riêng của Team 3):
python tools/make_pki.py --revoke pki/team3/client.crt --reason keyCompromise

# 3. Khởi động dịch vụ OCSP Responder trực tuyến:
python src/ocsp_server.py --host 127.0.0.1 --port 8080
```

### 4.4. Chạy kịch bản Demo thu hồi chứng chỉ đầu-cuối
Hệ thống cung cấp kịch bản kiểm thử trực quan toàn bộ chu trình thu hồi:
```bash
python tools/demo_revoke.py
```
**Kết quả hiển thị:**
- Khởi tạo PKI demo, kiểm tra chứng chỉ Team 3 khi chưa thu hồi $\rightarrow$ **Chấp nhận kết nối**.
- Thực hiện thu hồi chứng chỉ Team 3 và cập nhật CRL.
- Thẩm định lại bằng `verify_cert_with_crl` $\rightarrow$ **Từ chối kết nối**.
- Khởi động OCSP Responder và truy vấn HTTP $\rightarrow$ **Từ chối với trạng thái REVOKED**.

---

## 5. Hướng dẫn vận hành ứng dụng Chat & Truyền tệp

Để chạy ứng dụng thực tế, mở 3 cửa sổ dòng lệnh riêng biệt:

### Cửa sổ 1: Khởi động Máy chủ (Server)
```bash
python src/server.py
```
- Server lắng nghe tại `0.0.0.0:5000`, nạp chứng chỉ `pki/server.crt`.
- **Thoát an toàn (Graceful Shutdown):** Nhập `exit`, `quit` hoặc nhấn `Ctrl+C`. Server tự động gửi tín hiệu ngắt kết nối an toàn đến tất cả client trực tuyến, giải phóng tài nguyên mạng và dừng tiến trình sạch sẽ.
- **Lệnh quản trị trên console server:**
  - `status`: Xem số lượng client đang trực tuyến, thời gian uptime.
  - `clients`: Liệt kê chi tiết tên nhóm (CN) và địa chỉ IP các client đang kết nối.

### Cửa sổ 2: Khởi động Client Nhóm 1
```bash
python src/client.py --cert pki/team1/client.crt --key pki/team1/client.key --mssv 2412716 2412760
```

### Cửa sổ 3: Khởi động Client Nhóm 2
```bash
python src/client.py --cert pki/team2/client.crt --key pki/team2/client.key --mssv 2312716 2312760
```

---

## 6. Các lệnh tương tác trong ứng dụng Client

Khi kết nối thành công, Client hiển thị dấu nhắc lệnh `team1 > `:

| Cú pháp lệnh | Chức năng chi tiết | Cơ chế mật mã bảo vệ |
| :--- | :--- | :--- |
| `<nội dung tin nhắn>` | Soạn và gửi tin nhắn chat đến tất cả thành viên trong phòng | Mã hóa E2E bằng AES-256 đối xứng độc lập cho từng tin nhắn; bọc khóa bằng RSA-OAEP cho từng người nhận; ký số RSA-PSS bảo vệ toàn vẹn và chống chối bỏ. |
| `!roster` | Xem danh sách các nhóm đang trực tuyến | Máy chủ trả về danh sách kèm theo chứng chỉ X.509 công khai của các bên. |
| `!sendfile <đường_dẫn>` | Tải tệp tin lên phòng chat chung | Tệp được mã hóa E2E, chia mảnh $4 \text{ KiB}$, gắn số thứ tự vào MAC từng mảnh và tính mã băm SHA-256 toàn vẹn. |
| `!listfiles` | Xem danh sách các tệp đang lưu trên server | Máy chủ trả về danh sách tệp tin dạng mã hóa, thời điểm gửi và người gửi. |
| `!getfile <tên_file>` | Tải tệp tin từ máy chủ về máy cục bộ | Tệp tải về thư mục `downloads/`, tự động giải mã E2E, đối chiếu chữ ký số và xác thực băm SHA-256 trước khi ghi đĩa. |
| `exit` | Ngắt kết nối ứng dụng an toàn | Gửi thông báo ngắt kết nối `MT_DISCONNECT` và giải phóng session. |

---

## 7. Chạy bộ kiểm thử tự động toàn diện (Test Suite)

Dự án trang bị **77 Test Cases tự động** (phân bổ trong 16 tập tin kiểm thử tại thư mục `tests/`), bao phủ toàn diện 100% các tính năng nghiệp vụ và các kịch bản an ninh:

```bash
python -m unittest discover tests -v
```

### Bảng tổng kết kết quả kiểm thử (100% PASS):

| Tập tin kiểm thử | Số ca test | Trạng thái | Nội dung kiểm định an ninh & chức năng |
| :--- | :---: | :---: | :--- |
| `test_concurrency.py` | 1 | **PASS** | Gửi đồng thời 1000 gói tin từ 2 luồng; bảo toàn thứ tự `seq` và tính hợp lệ HMAC. |
| `test_crl.py` | 6 | **PASS** | **[Mục tiêu 1.2]** Tạo CRL RFC 5280, phát hiện cert thu hồi, từ chối CRL quá hạn. |
| `test_crypto.py` | 7 | **PASS** | Roundtrip EtM; lật 1-bit bản mã/MAC bị từ chối; kiểm định RSA-OAEP & RSA-PSS. |
| `test_e2e_chat.py` | 5 | **PASS** | Mã hóa/giải mã E2E chat; bên thứ ba không giải mã được; phát hiện chữ ký giả. |
| `test_e2e_file.py` | 6 | **PASS** | Truyền file phân mảnh E2E; phát hiện sửa mã băm SHA-256; phát hiện thiếu mảnh. |
| `test_files_server.py` | 6 | **PASS** | Chặn đứng Path Traversal; xử lý an toàn trùng tên; dọn dẹp file tạm `.part`. |
| `test_framing.py` | 6 | **PASS** | Khung truyền TCP `[len][payload]`; xử lý vỡ/dính gói; chặn khung quá 64 KiB. |
| `test_handshake.py` | 7 | **PASS** | Bắt tay 4 bước chuẩn; từ chối CA giả; từ chối sai MSSV; bảo vệ bí mật MSSV. |
| `test_integration_tcp.py`| 1 | **PASS** | Kiểm thử đầu-cuối Client-Server qua mạng TCP loopback thật: chat & file E2E. |
| `test_kdf.py` | 7 | **PASS** | Chống nhập nhằng chuỗi; kiểm định tính nhạy cảm với thứ tự MSSV; phân tách khóa. |
| `test_mitm_demo.py` | 2 | **PASS** | Thực nghiệm MitM tráo cert server; MitM lật 1 byte trên đường truyền mạng. |
| `test_ocsp.py` | 5 | **PASS** | **[Mục tiêu 1.2]** Phản hồi trạng thái GOOD / REVOKED qua HTTP POST `/ocsp`. |
| `test_pki.py` | 7 | **PASS** | Xác thực cert hợp lệ; từ chối CA giả mạo; từ chối cert sai CN; từ chối cert quá hạn. |
| `test_replay.py` | 6 | **PASS** | Chống phát lại: từ chối trùng `seq`, lùi `seq`, nhảy cóc `seq`, quá hạn timestamp. |
| `test_server_graceful_shutdown.py` | 3 | **PASS** | Dừng máy chủ an toàn; giải phóng toàn bộ kết nối client đang mở. |
| `test_timeout.py` | 2 | **PASS** | Tự động đóng phiên idle khi quá 60s; duy trì kết nối thành công với Heartbeat. |
| **TỔNG CỘNG** | **77** | **77 / 77 PASS (100%)** | Thời gian chạy toàn bộ: **~11–12 giây**. |

---

## 8. Bảng đối chiếu đáp ứng yêu cầu Đề bài tập lớn

| Hạng mục yêu cầu trong Đề bài | Mức độ đáp ứng | Minh chứng hiện thực trong mã nguồn |
| :--- | :---: | :--- |
| **Trao đổi khóa bất đối xứng** | **100% Đạt** | Giao thức bắt tay dùng RSA-OAEP 2048-bit bọc Master Secret; ký số RSA-PSS (`src/handshake.py`). |
| **Mã hóa dữ liệu đối xứng** | **100% Đạt** | Áp dụng AES-256-CBC theo chuẩn Encrypt-then-MAC (HMAC-SHA256) (`src/session.py`, `src/crypto_utils.py`). |
| **Mã xác thực chống giả mạo** | **100% Đạt** | HMAC-SHA256 cho từng khung truyền; RSA-PSS-SHA256 cho tin nhắn và phân mảnh tệp E2E. |
| **Chương trình Demo Client-Server** | **100% Đạt** | Chương trình Server CLI (`src/server.py`) và Client CLI (`src/client.py`) hoạt động hoàn chỉnh qua mạng TCP. |
| **Phân tích an toàn chống MitM** | **100% Đạt** | Có kịch bản kiểm thử MitM chuyên biệt (`tests/test_mitm_demo.py`) và phân tích chi tiết tại Chương 2 trong `REPORT.md`. |
| **Lồng ghép Plaintext Handshake** | **100% Đạt** | Thông điệp bắt tay chứa chuỗi: `Hello, We are 2412716, 2412760` (`src/handshake.py`). |
| **Khóa khởi tạo KDF băm từ MSSV** | **100% Đạt** | Khóa phiên dẫn xuất có băm danh sách MSSV: `SHA256(MS \|\| enc_list(MSSV) \|\| Nonce)` (`src/crypto_utils.py`). |
| **Dịch vụ CA chuẩn X.509** | **100% Đạt** | Công cụ `tools/make_pki.py` sinh Root CA X.509v3 và cấp phát chứng thư số cho Server và Client. |
| **Tích hợp kiểm tra CRL** | **100% Đạt** | Module `src/crl.py` phát hành X.509 CRL theo RFC 5280, tích hợp thẩm định vào `pki.verify_cert_with_crl()`. |
| **Tích hợp kiểm tra OCSP** | **100% Đạt** | Module `src/ocsp_server.py` hiện thực HTTP OCSP Responder theo RFC 6960, kiểm tra qua `pki.verify_cert_with_ocsp()`. |
| **Lồng ghép CN của Root CA** | **100% Đạt** | $CN = \text{CA-Root-2412716-2412760}$ (`tools/make_pki.py`). |
| **Lồng ghép OU của Root CA** | **100% Đạt** | $OU = \text{Faculty of Computer Science and Engineer – 2412716-2412760}$ (`tools/make_pki.py`). |
| **Cấu trúc nộp bài quy định** | **100% Đạt** | Có tệp `README.md`, thư mục `src/`, thư mục `refs/`, và báo cáo kỹ thuật `REPORT.md` (đầy đủ các chương 1, 2, 3, 4, TLTK, Phụ lục). |
