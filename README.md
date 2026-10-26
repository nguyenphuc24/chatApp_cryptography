# Secure Chat & File Transfer (E2E Encrypted & PKI Authenticated)

Ứng dụng chat client–server và truyền file mã hoá đầu cuối (End-to-End) bằng Python, đạt tiêu chuẩn bảo mật cho đồ án Mật mã & An ninh mạng.

Hệ thống được thiết kế hoàn chỉnh từ đầu nhằm giải quyết triệt để các lỗ hổng:
- **Chống nghe lén (Eavesdropping):** Toàn bộ tin nhắn chat và nội dung file được mã hoá E2E; server chỉ chuyển tiếp (relay) bản mã, hoàn toàn không giải mã được nội dung. MSSV và thông tin định danh trong quá trình bắt tay cũng được mã hoá, không lộ trên đường truyền.
- **Chống MitM (Man-in-the-Middle) & mạo danh:** Xác thực hai chiều bằng chứng chỉ X.509 ký bởi Root CA nội bộ; chữ ký số RSA-PSS trên transcript bắt tay ràng buộc chứng chỉ, nonce và master secret.
- **Chống Replay:** Kiểm soát số thứ tự gói tin (`seq`) tăng dần theo từng chiều, cửa sổ timestamp chặt chẽ `[now - 30s, now + 10s]`, và nonce ngẫu nhiên của server trong bắt tay.
- **Chống DoS & Race Condition:** Giới hạn kích thước khung truyền `MAX_FRAME = 64 KiB`, giới hạn file `MAX_FILE = 10 MiB`, lock đồng bộ socket đa luồng, heartbeat `PING`/`PONG` tự động đóng phiên idle.
- **Toàn vẹn dữ liệu:** Mã hoá kênh truyền theo mô hình Encrypt-then-MAC (AES-256-CBC + HMAC-SHA256).

---

## 1. Cấu trúc thư mục

```
chatApp_cryptography/
├── src/
│   ├── pki.py           # Quản lý, nạp và kiểm tra chứng chỉ X.509
│   ├── crypto_utils.py  # Nguyên hàm mã hoá (AES, EtM, RSA-OAEP, RSA-PSS, KDF, encoding)
│   ├── framing.py       # Khung truyền TCP [ length (4B big-endian) ][ payload ]
│   ├── session.py       # Record layer: EtM, seq, timestamp, thread lock, heartbeat
│   ├── handshake.py     # Giao thức handshake xác thực chứng chỉ hai chiều
│   ├── e2e.py           # Mã hoá đầu cuối (E2E chat & E2E chunked file transfer)
│   ├── server.py        # Server đa luồng: accept, handshake, relay E2E, lưu file an toàn
│   └── client.py        # Client CLI: handshake, chat E2E, upload/download file E2E
├── tools/
│   └── make_pki.py      # Công cụ tạo Root CA, chứng chỉ server và chứng chỉ nhóm
├── tests/               # Toàn bộ 63 test cases tự động (unit test & integration test)
├── requirements.txt     # cryptography, pycryptodome
├── HANDBOOK.md          # Cẩm nang kỹ thuật chi tiết (thiết kế, thuật toán, thư viện, debug)
├── KE_HOACH.md          # Kế hoạch và tài liệu đặc tả kỹ thuật
└── README.md
```

---

## 2. Cài đặt môi trường

Yêu cầu: **Python ≥ 3.10**

```bash
# Tạo môi trường ảo
python -m venv .venv

# Kích hoạt môi trường (Windows PowerShell)
.\.venv\Scripts\Activate.ps1
# Hoặc trên Linux / macOS:
# source .venv/bin/activate

# Cài đặt thư viện phụ thuộc
pip install -r requirements.txt
```

---

## 3. Khởi tạo hạ tầng PKI (Chứng chỉ X.509)

Hệ thống sử dụng Root CA tự ký làm gốc tin cậy duy nhất (`pki/ca.crt`).

```bash
# 1. Tạo Root CA và chứng chỉ Server (CN=chat-server):
python tools/make_pki.py

# 2. Tạo chứng chỉ cho Team 1 (CN=team1, UID=MSSV):
python tools/make_pki.py --team team1 --mssv 2412716 2412760

python tools/make_pki.py --team team2 --mssv 2312716 2312760
python tools/make_pki.py --team team3 --mssv 2512716 2512760
```

Các file được tạo ra trong thư mục `pki/`:
- `pki/ca.crt` (Root CA công khai được tin cậy)
- `pki/server.crt`, `pki/server.key` (chứng chỉ và khoá riêng của Server)
- `pki/<team>/client.crt`, `pki/<team>/client.key` (chứng chỉ và khoá riêng của Client)

---

## 4. Chạy chương trình

### Khởi động Server:
```bash
python src/server.py
```
Server mặc định lắng nghe tại `0.0.0.0:5000`, nạp chứng chỉ `pki/server.crt` và khoá `pki/server.key`.

### Khởi động Client Team 1:
Mở terminal mới và chạy:
```bash
python src/client.py --cert pki/team1/client.crt --key pki/team1/client.key --mssv 2412716 2412760
```

### Khởi động Client Team 2:
Mở terminal tiếp theo và chạy:
```bash
python src/client.py --cert pki/team2/client.crt --key pki/team2/client.key --mssv 2312716 2312760

python src/client.py --cert pki/team3/client.crt --key pki/team3/client.key --mssv 2512716 2512760

```

Trạng thái E2E (số thứ tự đã gửi) được lưu tự động vào `.client_state/<CN>_state.json` sau mỗi lần gửi. Khi khởi động lại, client nạp lại seq cũ và so với timestamp hiện tại, chọn giá trị lớn hơn — đảm bảo seq luôn tăng và không bao giờ tái sử dụng. `last_msg_seq` (replay map phía nhận) chỉ lưu trong bộ nhớ vì server không lưu lịch sử tin nhắn.

---

## 5. Các lệnh trong Client

| Lệnh | Chức năng |
|---|---|
| `<nội dung tin nhắn>` | Gửi tin nhắn chat mã hoá E2E tới mọi client online |
| `!roster` | Xem danh sách các thành viên và chứng chỉ công khai đã xác thực |
| `!sendfile <đường_dẫn>` | Upload file mã hoá E2E chia chunk (4 KiB/chunk) lên server |
| `!listfiles` | Xem danh sách file có trên server |
| `!getfile <tên_file>` | Tải file về thư mục `downloads/`, tự động giải mã và kiểm tra SHA-256 |
| `exit` | Đóng kết nối an toàn |

---

## 6. Chạy bộ kiểm thử tự động (Test Suite)

Toàn bộ 63 test cases bao phủ đầy đủ các yêu cầu an ninh từ B0 đến B7:

```bash
python -m unittest discover -s tests -v
```

**Kết quả mong đợi:** `Ran 63 tests in ~3–5s ─ OK`

---

## 7. Tăng cường bảo mật (Security Hardening)

Các mục dưới đây được triển khai vượt yêu cầu đề bài, dựa trên kiểm định thực tế:

| # | Vấn đề | Vị trí | Biện pháp |
|---|---|---|---|
| 1 | **Path traversal khi nhận file** | `client.py` `_finalize_recv_file` | `validate_filename()` kiểm tra whitelist `[A-Za-z0-9._-]`, sau đó `os.path.realpath` xác nhận đường dẫn cuối cùng nằm trong `downloads/` |
| 2 | **Chunk order binding vào MAC** | `e2e.py` `e2e_prepare_file` | Mỗi chunk EtM trên `struct.pack("!I", i) + chunk_bytes`; hoán đổi thứ tự chunk → HMAC sai → bị từ chối |
| 3 | **E2E seq bền qua restart** | `client.py` `_load_state`/`_save_state` | Lưu `sent_msg_seq`, `sent_file_seq` vào `.client_state/<CN>_state.json` (ghi nguyên tử qua `.tmp`); nạp lại khi khởi động; dùng `max(saved, now_ms)` làm seq mới |
| 4 | **X.509 KeyUsage không kiểm tra** | `pki.py` `verify_cert` | Kiểm tra extension `KeyUsage` nếu tồn tại: cần `digitalSignature` hoặc `keyEncipherment` |
| 5 | **State không lưu sau gửi** | `client.py` `send_msg`/`send_file` | `_save_state()` được gọi ngay sau mỗi lần gửi thành công, tránh mất seq khi crash |

---

## 8. Hạn chế đã ghi nhận (ngoài phạm vi)

- **Forward secrecy:** Khoá RSA dài hạn mã hoá master secret; nếu lộ khoá server thì có thể giải các phiên đã ghi. Hướng cải thiện: ECDHE X25519.
- **Reflection:** Khoá phiên dùng chung hai chiều. Hướng cải thiện: HKDF tách `c2s`/`s2c`.
- **Thu hồi chứng chỉ:** CRL/OCSP chưa hỗ trợ.
- **Metadata lộ với server:** Server thấy tên file, kích thước, người gửi và thời điểm gửi.
- **Rate limit, giới hạn số kết nối:** Chưa triển khai.
- **Mã hoá khoá riêng khi lưu:** Khoá riêng lưu dạng PEM không mã hoá.

---

### Danh mục kiểm thử:
1. `test_crypto.py`: EtM roundtrip, phát hiện sửa 1 bit ciphertext/HMAC, từ chối khoá sai, frame ngắn, RSA-OAEP, RSA-PSS.
2. `test_kdf.py`: Encoding không nhập nhằng `enc_list(["23","12"]) ≠ enc_list(["2312"])`, độ nhạy với thứ tự MSSV, nonce, MS.
3. `test_pki.py`: Kiểm tra CA tin cậy, từ chối CA lạ, từ chối sai CN, từ chối chứng chỉ CA làm leaf, kiểm tra chứng chỉ hết hạn / chưa có hiệu lực.
4. `test_framing.py`: Chống DoS quá frame `MAX_FRAME` (64 KiB), ghép phân mảnh TCP, phát hiện EOF giữa frame.
5. `test_handshake.py`: Bắt tay hợp lệ, chống MitM với chứng chỉ tự ký, chống khai man MSSV (so với UID cert), chữ ký sai khoá, chứng chỉ do CA lạ cấp, **đảm bảo MSSV không xuất hiện dạng rõ trên dây**, chống replay gói INIT cũ.
6. `test_replay.py`: Chống lặp số thứ tự `seq`, chống lùi seq, chống bỏ bước seq, chống replay timestamp quá hạn.
7. `test_concurrency.py`: Hai luồng gửi đồng thời 1000 gói tin trên cùng socket có thread lock bảo vệ, bên nhận giải mã hoàn hảo 1000/1000 gói tin không lỗi HMAC.
8. `test_timeout.py`: Tự động ngắt kết nối idle khi không có dữ liệu, duy trì kết nối khi có heartbeat PING/PONG.
9. `test_e2e_chat.py`: Server không giải mã được tin nhắn chat E2E, người không có wrap không đọc được, từ chối chữ ký giả mạo, chống replay E2E.
10. `test_e2e_file.py`: Truyền nhận file E2E chia chunk, từ chối chunk đảo thứ tự hoặc thiếu chunk, xác minh toàn vẹn SHA-256, từ chối file vượt `MAX_FILE = 10 MiB`.
11. `test_files_server.py`: Chặn path traversal (`../`), lọc tên file nguy hiểm, tự động đổi tên `file (1).ext` chống ghi đè, dọn dẹp file tạm `.tmp_*` khi lỗi.
12. `test_mitm_demo.py`: Mô phỏng kịch bản tấn công Man-in-the-Middle (thay thế chứng chỉ và can thiệp byte trên đường truyền), ghi nhận kết quả phòng thủ thành công.
13. `test_integration_tcp.py`: Kiểm thử tích hợp toàn diện trên kết nối TCP thật với Server, 2 Client, trao đổi chat E2E và file E2E.

---

## 9. Tài liệu kỹ thuật chi tiết

Xem **[HANDBOOK.md](HANDBOOK.md)** để có cẩm nang đầy đủ bao gồm:
- Thiết kế giao thức từng lớp (framing → PKI → handshake → record → E2E)
- Giải thích lý do chọn mỗi thuật toán (EtM, OAEP, PSS, KDF...)
- Hướng dẫn sử dụng thư viện `cryptography`, `pycryptodome`, `struct`, `socket`
- Danh sách các lỗi đã gặp và cách khắc phục chi tiết
- Bảng tóm tắt mọi quyết định thiết kế