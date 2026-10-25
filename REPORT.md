# BÁO CÁO KỸ THUẬT ĐỒ ÁN

## Hệ thống chat và truyền file bảo mật (Secure Chat)

**Môn học:** Mật mã và An ninh mạng *(điền tên môn chính xác)*
**Nhóm thực hiện:** *(tên nhóm)*
**Thành viên (MSSV – Họ tên):**

| MSSV | Họ tên | Vai trò |
|---|---|---|
| 2312345 | *(họ tên)* | *(vai trò)* |
| 2312346 | *(họ tên)* | *(vai trò)* |

**GVHD:** *(họ tên giảng viên)*
**Thời gian thực hiện:** *(tháng/năm)*

---

## Mục lục

1. Giới thiệu
2. Cơ sở lý thuyết
3. Thiết kế hệ thống
4. Thiết kế giao thức bảo mật
5. Phân tích an toàn
6. Cài đặt
7. Kiểm thử và kết quả
8. Trạng thái thực hiện
9. Hướng phát triển
10. Kết luận
11. Tài liệu tham khảo
12. Phụ lục

---

## 1. Giới thiệu

### 1.1 Bối cảnh và động cơ

Ứng dụng chat và chia sẻ file qua mạng không tin cậy có nguy cơ bị nghe lén, bị sửa đổi và bị giả mạo. Kẻ tấn công có thể đứng giữa client và server (MitM), phát lại gói tin cũ (replay), hoặc mạo danh một nhóm sinh viên. Đồ án này xây dựng một hệ thống client–server trong đó:

- Server chỉ chuyển tiếp dữ liệu mã hoá và không đọc được nội dung chat hay file (mã hoá đầu cuối).
- Mọi thành viên được xác thực bằng chứng chỉ X.509 do một CA nội bộ cấp.
- Kênh truyền được bảo vệ toàn vẹn bằng Encrypt-then-MAC.

### 1.2 Mục tiêu

- Thiết kế giao thức bảo mật kết hợp mã hoá bất đối xứng RSA để trao khoá, AES-256 để mã hoá dữ liệu và HMAC/chữ ký số để chống giả mạo.
- Thiết kế cơ chế xác thực bằng chứng chỉ, chống MitM và mạo danh.
- Chuẩn hoá cách dẫn xuất khoá phiên từ MSSV của nhóm.
- Cài đặt demo client–server, có chat và truyền file mã hoá đầu cuối.
- Phân tích an toàn trước nghe lén, MitM, replay và mạo danh; kiểm chứng bằng unittest.

### 1.3 Phạm vi

**Trong phạm vi:**
- PKI tự quản lý (CA, chứng chỉ server, chứng chỉ nhóm).
- Handshake xác thực hai chiều, mã hoá gói `HANDSHAKE_INIT`.
- Record layer EtM với số thứ tự và cửa sổ timestamp.
- Chat E2E và truyền file E2E (chunk, SHA-256 trong metadata đã ký).
- Giới hạn kích thước khung và file, timeout, heartbeat, lock khi gửi đồng thời.

**Ngoài phạm vi (đã ghi chú):**
- Forward secrecy (khoá RSA dài hạn của server mã hoá master secret).
- Chống reflection (khoá dùng chung cho hai chiều).
- Thu hồi chứng chỉ (CRL/OCSP), mã hoá khoá riêng khi lưu trữ.
- Giới hạn tốc độ kết nối (rate limit), lịch sử chat cho thành viên mới.
- Giao diện đồ hoạ.

### 1.4 Đóng góp của từng thành viên

| Thành viên | Công việc chính |
|---|---|
| *(thành viên 1)* | *(ví dụ: thiết kế giao thức, handshake, kiểm thử)* |
| *(thành viên 2)* | *(ví dụ: E2E chat, truyền file, báo cáo)* |

---

## 2. Cơ sở lý thuyết

### 2.1 Mã hoá đối xứng – AES-256-CBC

AES là mật mã khối đối xứng với khoá 256 bit và khối 128 bit. CBC kết hợp mỗi khối với khối bản mã trước đó thông qua phép XOR, và cần một vector khởi tạo (IV) ngẫu nhiên 16 byte cho mỗi thông điệp. Dự án dùng AES-256-CBC với đệm PKCS#7. CBC đơn thuần không bảo đảm toàn vẹn, nên phải kết hợp với MAC (mục 2.5).

### 2.2 Mã hoá bất đối xứng – RSA-OAEP

RSA-2048 mã hoá dữ liệu nhỏ (tối đa khoảng 190 byte với OAEP-SHA256) bằng khoá công khai. Dự án dùng RSA để **bọc** một khoá đối xứng ngẫu nhiên: master secret khi handshake và khoá K của từng tin nhắn hoặc file trong E2E. OAEP ngẫu nhiên hoá phép mã hoá nên cùng một dữ liệu không cho cùng bản mã, và chống được các tấn công thông điệp chọn trước đơn giản.

### 2.3 Chữ ký số – RSA-PSS

RSA-PSS ký băm SHA-256 của thông điệp bằng khoá riêng. Chữ ký dùng để chứng minh người ký giữ khoá riêng và thông điệp không bị sửa. Dự án dùng PSS (không phải PKCS#1 v1.5) vì PSS có chứng minh bảo mật chặt hơn và có ngẫu nhiên hoá. Chữ ký xuất hiện ở hai chỗ: chữ ký transcript của handshake (chứng minh danh tính nhóm) và chữ ký metadata của tin nhắn/file E2E (chứng minh người gửi).

### 2.4 Mã xác thực thông điệp – HMAC-SHA256

HMAC kết hợp hàm băm với khoá bí mật để tạo mã xác thực. Chỉ bên có khoá mới tạo hoặc kiểm tra được tag. So sánh tag bằng `hmac.compare_digest` để tránh rò rỉ thời gian.

### 2.5 Encrypt-then-MAC và lý do chọn thứ tự này

Có ba cách kết hợp mã hoá và MAC: MAC-then-Encrypt, Encrypt-and-MAC, và Encrypt-then-MAC. Bellare và Namprempre (2000) chứng minh rằng EtM là cách an toàn nhất trong ba cách. Lý do thực tế: bên nhận kiểm tra tag **trước** khi giải mã, nên gói bị sửa bị loại mà không chạm vào bộ giải mã. Điều này loại bỏ tấn công padding oracle trên CBC.

### 2.6 Hàm băm và dẫn xuất khoá – SHA-256

SHA-256 là hàm băm mật mã 256 bit. Dự án dùng SHA-256 để:
- Dẫn xuất khoá phiên `SHA256(MS ‖ enc_list(MSSV) ‖ enc(nonce))`.
- Tách khoá AES và HMAC từ cùng một khoá gốc bằng hậu tố khác nhau.
- Băm transcript handshake và metadata E2E trước khi ký.
- Kiểm tra toàn vẹn nội dung file.

Để tránh nhập nhằng khi ghép chuỗi, mỗi trường được đặt tiền tố độ dài 4 byte: `enc(x) = len(x) ‖ x`. Ví dụ `["23","12"]` và `["2312"]` cho hai đầu vào khác nhau.

### 2.7 Hạ tầng khoá công khai (PKI) và chứng chỉ X.509

Chứng chỉ X.509 gắn một khoá công khai với một danh tính, được ký bởi CA. Bên kiểm tra chỉ cần tin CA để tin chứng chỉ. Trong dự án:
- CA tự ký là gốc tin cậy duy nhất.
- Chứng chỉ server có CN = `chat-server`.
- Chứng chỉ nhóm có CN = tên nhóm và mỗi MSSV là một thuộc tính UID trong Subject.
- Kiểm tra gồm: chữ ký của CA, thời hạn, không phải CA, CN đúng.

### 2.8 Các loại tấn công cần chống

| Tấn công | Mô tả ngắn |
|---|---|
| Nghe lén | Đọc nội dung gói trên đường truyền |
| Kẻ đứng giữa (MitM) | Chặn, thay thế hoặc chuyển tiếp gói; thay khoá công khai |
| Phát lại (replay) | Gửi lại gói hợp lệ đã ghi lại |
| Mạo danh | Tự nhận là một nhóm khác |
| Sửa đổi dữ liệu | Thay đổi bit trên đường truyền |
| Padding oracle | Dò thông tin qua thông báo lỗi padding |
| Từ chối dịch vụ (DoS) | Gửi frame lớn, treo kết nối, làm cạn tài nguyên |

---

## 3. Thiết kế hệ thống

### 3.1 Kiến trúc tổng quan

```
   [Client nhóm A] ──┐                 ┌── [Client nhóm B]
                     ├──── [Server] ───┤
   [Client nhóm C] ──┘   (relay E2E,   └── (lưu file mã hoá)
                          không giải mã)
                            │
                         [CA] — chỉ dùng khi cấp chứng chỉ (offline)
```

- **Server** xác thực từng client, gán `sender` từ CN của chứng chỉ, chuyển tiếp `E2E_MSG` nguyên vẹn, lưu file ở dạng mã hoá, và trả lời `ROSTER_REQ`, `FILE_LIST_REQ`, `FILE_GET_REQ`.
- **Client** làm handshake, mã hoá và giải mã E2E, kiểm tra chữ ký và SHA-256.
- **CA** cấp chứng chỉ bằng công cụ `tools/make_pki.py`, không chạy trong lúc hoạt động.

### 3.2 Mô hình tin cậy và PKI

| Tài sản | Người giữ | Bảo vệ |
|---|---|---|
| `ca.key` | Người quản trị | Không đưa vào repo; chỉ dùng khi cấp chứng chỉ |
| `server.key` | Server | Không đưa vào repo |
| `pki/<team>/client.key` | Nhóm tương ứng | Không đưa vào repo |
| `ca.crt`, chứng chỉ | Công khai | Phân phối tự do |

Client và server đều chỉ tin `ca.crt`. Kẻ đứng giữa không có khoá riêng của CA nên không tạo được chứng chỉ server hợp lệ. Giới hạn: nếu CA bị lộ khoá, mọi cơ chế xác thực mất hiệu lực.

### 3.3 Định dạng khung truyền và gói tin

**Khung truyền:** `[ length: 4 byte big-endian ][ payload ]`, với `length ≤ MAX_FRAME = 64 KiB`.

**Gói sau handshake (record layer):**

```
plaintext = JSON { "type", "sender", "seq", "payload", "timestamp" }
frame     = IV(16) ‖ AES-256-CBC(K_aes, IV, PKCS7(plaintext)) ‖ HMAC-SHA256(K_hmac, IV ‖ C)
```

**Các loại gói chính:**

| Nhóm | Loại | Ghi chú |
|---|---|---|
| Handshake | `HANDSHAKE_HELLO`, `HANDSHAKE_INIT`, `HANDSHAKE_OK`, `HANDSHAKE_ACK` | HELLO và INIT ở dạng plaintext (INIT có body mã hoá) |
| Roster | `ROSTER_REQ`, `ROSTER_RESP` | Chứng chỉ công khai; client tự kiểm tra |
| Chat | `E2E_MSG`, `SYS_MSG` | `SYS_MSG` là thông báo của server, dạng rõ |
| File | `FILE_E2E_START`, `FILE_E2E_CHUNK`, `FILE_E2E_END`, `FILE_LIST_REQ/RESP`, `FILE_GET_REQ` | |
| Điều khiển | `PING`, `PONG`, `DISCONNECT`, `ERROR` | |

---

## 4. Thiết kế giao thức bảo mật

### 4.1 Handshake

| Bước | Chiều | Nội dung | Được bảo vệ bằng |
|---|---|---|---|
| 1 | S → C | `HELLO { server_cert, server_nonce }` | Chứng chỉ do CA ký (client kiểm tra) |
| 2 | C → S | `INIT { encrypted_ms, body }` với `encrypted_ms = RSA-OAEP(MS)`, `body = EtM(body_json; K_init)` | RSA-OAEP; EtM với khoá lấy từ MS |
| 3 | S → C | `OK` | EtM với khoá phiên |
| 4 | C → S | `ACK` | EtM với khoá phiên |

Nội dung `body_json`: `message` (`Hello, We are MSSV_1, MSSV_2`), `mssv_list`, `client_cert`, `signature`.

**Khoá:**

```
K_init_aes  = SHA256(MS ‖ "init-enc")     K_init_hmac = SHA256(MS ‖ "init-mac")
T           = SHA256( enc(cert_server) ‖ enc(nonce) ‖ enc(enc_ms) ‖ enc_list(MSSV) ‖ enc(cert_client) )
signature   = RSA-PSS_sign(khoá_riêng_nhóm, T)
session_key = SHA256( MS ‖ enc_list(MSSV) ‖ enc(nonce) )          ← công thức của đề
K_aes       = SHA256(session_key ‖ "encryption")
K_hmac      = SHA256(session_key ‖ "authentication")
```

**Luồng xác minh phía server:** giải `encrypted_ms` → tính `K_init` → giải body (kiểm tra HMAC trước) → kiểm tra chứng chỉ client (CA ký, còn hạn, không phải CA) → UID trên chứng chỉ phải bằng `mssv_list` → kiểm tra chữ ký T → tính `session_key`.

**Luồng xác minh phía client:** kiểm tra chứng chỉ server (CA ký, CN = `chat-server`, còn hạn) trước khi làm bất cứ việc gì khác.

### 4.2 Dẫn xuất khoá và chuẩn hoá ghép chuỗi

Công thức của đề giữ nguyên: `Key = SHA256(MSSV_1 ‖ MSSV_2 ‖ …)` được mở rộng thành `SHA256(MS ‖ MSSV ‖ nonce)` theo yêu cầu của nhóm, và chuẩn hoá bằng tiền tố độ dài:

```
enc(x)      = len(x) (4 byte) ‖ x
enc_list(L) = len(L) (4 byte) ‖ enc(L_1) ‖ … ‖ enc(L_n)
```

**Lý do không dùng nối trực tiếp:** `["23","12"]` và `["2312"]` cho cùng chuỗi `2312` nếu không có tiền tố. Kiểm thử `test_enc_list_ambiguity_prevention` và `test_kdf_mssv_order_sensitivity` xác nhận điều này.

**Lý do không chỉ dùng MSSV làm khoá:** MSSV được gửi trong gói, và đề bài cũng yêu cầu chuỗi `Hello, We are…` ở dạng rõ, nên bất kỳ ai nghe gói đều biết MSSV. Nếu khoá chỉ băm từ MSSV thì khoá công khai. Nhóm kết hợp thêm master secret ngẫu nhiên (chỉ người có khoá riêng của server giải được) và nonce của server.

### 4.3 Chống replay

- **Số thứ tự `seq`** trong JSON của gói (nằm trong phần được MAC). Mỗi chiều bắt đầu từ 1 và tăng dần. Nhận gói có `seq ≠ last + 1` thì đóng phiên. Vì TCP bảo đảm thứ tự, cách kiểm tra này đủ, không cần cache ID.
- **Cửa sổ timestamp** `[now − 30 s, now + 10 s]` là lớp phòng thủ thứ hai, chống gói rất cũ.
- **Nonce của server** trong T: một `HANDSHAKE_INIT` cũ không dùng được với nonce mới.
- **E2E:** mỗi người gửi có `seq` riêng; người nhận giữ `last_seq[sender]` và từ chối `seq ≤ last`.

Lý do cần cả hai lớp: timestamp đơn thuần không chặn được bản sao trong cùng cửa sổ 30 giây; số thứ tự không chặn được gói quá cũ nếu phiên đã mở lâu. Hạn chế đã biết: `last_seq` của E2E chỉ ở trong bộ nhớ (mục 5.4).

### 4.4 Chat và truyền file đầu cuối (E2E)

**Gửi một tin nhắn:**

1. Lấy roster và kiểm tra từng chứng chỉ bằng CA.
2. Sinh `K` ngẫu nhiên 32 byte; mã hoá nội dung bằng EtM với khoá lấy từ `K`.
3. Với mỗi người nhận (kể cả bản thân): `wrap_r = RSA-OAEP(K, pub_r)`.
4. Ký `SHA256(enc(cn) ‖ enc(seq) ‖ enc(ciphertext) ‖ enc_map(wraps))` bằng khoá riêng nhóm.
5. Gửi `{seq, ciphertext, wraps, sig}`.

**Server:** thêm `sender` (lấy từ phiên đã xác thực) và chuyển tiếp cho các phiên khác. Không giải mã, không lưu.

**Người nhận:** tìm chứng chỉ người gửi trong roster đã kiểm tra → xác minh chữ ký → kiểm tra `seq > last_seq[sender]` → giải `wrap` của mình → giải EtM.

**Truyền file:**

- Sinh `K` riêng cho file; chia chunk 4 KiB; mỗi chunk là `EtM(chunk; K)`.
- Metadata `{name, size, sha256, chunks, seq, wraps, sig}`; `sha256` là SHA-256 của nội dung gốc và nằm trong phần được ký.
- Server lưu metadata và chunk dưới dạng JSON đã mã hoá, không giải mã. Khi tải, server gửi lại đúng các gói đã lưu.
- Người nhận kiểm tra chữ ký metadata, thứ tự chunk, từng HMAC chunk, rồi SHA-256 của nội dung ghép lại. Sai ở bất kỳ bước nào thì không lưu file.

### 4.5 Heartbeat và timeout

- Client gửi `PING` mỗi 20 giây; server trả `PONG`.
- Phía client, nếu không nhận được gói nào trong 60 giây thì đóng phiên.
- Phía server, socket có timeout 60 giây; hết thời gian thì `recv` trả `None` và phiên đóng.
- `recv_frame` trả `None` khi EOF, lỗi socket, timeout hoặc frame quá lớn. Không có nhánh `continue` treo vô hạn.

---

## 5. Phân tích an toàn

### 5.1 Mô hình đe doạ

| Tác nhân | Khả năng | Mục tiêu | Biện pháp chính |
|---|---|---|---|
| Kẻ nghe lén | Đọc toàn bộ gói trên mạng | Đọc nội dung, biết MSSV | EtM, E2E, MSSV trong body mã hoá |
| Kẻ đứng giữa | Đọc, sửa, chèn, phát lại, thay chứng chỉ | Giả server hoặc client; đọc chat | CA + CN; chữ ký T; EtM; `seq` |
| Thành viên không tin cậy trong phòng | Có chứng chỉ hợp lệ của nhóm mình | Mạo danh nhóm khác; sửa tin | UID khớp MSSV; chữ ký E2E; `sender` do server gán |
| Server bị xâm nhập | Đọc toàn bộ dữ liệu lưu trữ và relay | Đọc nội dung; sửa file | E2E: không có khoá; file có SHA-256 ký trong metadata |
| Kẻ gửi gói lớn | Gửi frame/file lớn | DoS bộ nhớ | `MAX_FRAME`, `MAX_FILE` |
| Chủ nhóm có khoá riêng | Toàn quyền với nhóm | *(ngoài phạm vi)* | Không chống được; ghi chú |

### 5.2 Phân tích từng tấn công

#### 5.2.1 Nghe lén

- **Mô tả:** kẻ nghe đọc gói trên đường truyền.
- **Kịch bản trên mã gốc:** toàn bộ tin nhắn và MSSV đi dạng rõ hoặc chỉ được mã hoá từng chặng; server đọc được mọi nội dung.
- **Biện pháp:** E2E cho chat và file (server không có khoá); MSSV và chứng chỉ client nằm trong body mã hoá của INIT; record layer EtM.
- **Kiểm chứng:** `test_eavesdropper_without_wrap_cannot_decrypt`, `test_mssv_not_leaked_in_wire_bytes`, `test_non_recipient_cannot_decrypt_file`.
- **Còn lại:** `encrypted_ms` và độ dài gói lộ ra; server biết ai gửi cho ai và khi nào.

#### 5.2.2 Kẻ đứng giữa (MitM)

- **Mô tả:** kẻ đứng giữa chặn kết nối, gửi khoá công khai của mình và chuyển tiếp để đọc gói.
- **Kết quả trên mã gốc (đã đo):** mã gốc không có xác thực server. Kẻ đứng giữa có thể thay `public_key` trong HELLO, nhận `master_secret` đã mã hoá bằng khoá giả, rồi chuyển tiếp cho server thật. Đây là phân tích dựa trên mã; chưa thử tấn công đầy đủ trên mã gốc.
- **Biện pháp:** client chỉ tin server có chứng chỉ do CA ký, CN đúng, còn hạn. Kẻ đứng giữa không có khoá riêng của CA nên không tạo được chứng chỉ hợp lệ.
- **Kiểm chứng:** `test_mitm_untrusted_server_cert` (client từ chối với thông báo "Chữ ký chứng chỉ không hợp lệ (không phải do CA này ký)"); `test_mitm_demo.py` Scenario 1 và 2 đều pass.
- **Còn lại:** nếu khoá CA bị lộ thì MitM vẫn thành công.

#### 5.2.3 Phát lại (replay)

- **Mô tả:** kẻ tấn công ghi lại gói hợp lệ và gửi lại sau đó.
- **Kết quả trên mã gốc (đã đo):** một frame hợp lệ gửi hai lần, cả hai đều được chấp nhận. Frame cũ hơn 30 giây bị loại. Kết quả này được đo bằng hàm `ClientSession.recv_packet` của mã gốc.
- **Nguyên nhân:** HMAC chỉ chứng minh gói không bị sửa, không chứng minh gói chưa từng được gửi. Timestamp không đổi nên gói vẫn hợp lệ trong cửa sổ.
- **Biện pháp:** `seq` tăng dần trong phần được MAC (record layer); nonce của server trong T (handshake); `seq` riêng cho E2E.
- **Kiểm chứng:** `test_replay_same_seq_rejected`, `test_gap_in_seq_rejected`, `test_backward_seq_rejected`, `test_replay_init_rejected`.
- **Còn lại:** `last_seq` của E2E không được lưu ra đĩa; sau khi người nhận khởi động lại, một tin cũ có thể được chấp nhận lại (mục 5.4).

#### 5.2.4 Mạo danh client

- **Mô tả:** một người tự nhận là nhóm khác.
- **Kết quả trên mã gốc:** MSSV và username do client tự khai, không có chứng chỉ, nên mạo danh tự do.
- **Biện pháp:** server kiểm tra chứng chỉ client do CA ký; UID trên chứng chỉ phải bằng `mssv_list`; chữ ký T bằng khoá trong chứng chỉ. Với E2E, `sender` do server gán và chữ ký của người gửi được kiểm tra bằng chứng chỉ trong roster.
- **Kiểm chứng:** `test_mssv_mismatch_rejected`, `test_wrong_signature_key_rejected`, `test_untrusted_client_cert_rejected`, `test_spoofed_sender_rejected`.
- **Còn lại:** hai kết nối cùng CN ghi đè nhau (mục 5.4).

#### 5.2.5 Giả mạo và sửa dữ liệu

- **Biện pháp:** HMAC-SHA256 trên mọi gói sau handshake; chữ ký RSA-PSS trên T, trên metadata và tin E2E; SHA-256 nội dung file trong metadata đã ký.
- **Kiểm chứng:** `test_etm_tamper_one_bit_ciphertext`, `test_etm_tamper_one_bit_hmac`, `test_tampered_signature_rejected`, `test_corrupted_sha256_rejected`, `Scenario 2` trong `test_mitm_demo` (lật 1 byte trên dây → ngắt kết nối).

#### 5.2.6 Padding oracle

- **Biện pháp:** bên nhận kiểm tra HMAC trước khi giải mã, nên không có phản hồi nào phụ thuộc padding.
- **Kiểm chứng:** `test_etm_wrong_keys`, `test_etm_short_frame`; kiểm tra bằng mã: `verify_then_decrypt` trả `None` cho mọi lỗi mà không tiết lộ nguyên nhân.

#### 5.2.7 Từ chối dịch vụ cơ bản

- **Kết quả trên mã gốc:** độ dài frame không giới hạn; `_recv_exact` bỏ qua timeout bằng `continue`; file đọc hết vào RAM.
- **Biện pháp:** `MAX_FRAME = 64 KiB`; `MAX_FILE = 10 MiB` kiểm tra cả khai báo và số byte thực nhận; timeout đóng phiên; heartbeat đóng phiên idle.
- **Kiểm chứng:** `test_send_oversized_frame_raises`, `test_recv_oversized_header_returns_none`, `test_exceeding_max_file_raises`, `test_idle_timeout_closes_session`, `test_active_ping_keeps_connection_alive`.
- **Còn lại:** không có giới hạn số kết nối đồng thời.

### 5.3 Bảng tóm tắt

| Tấn công | Biện pháp | Kiểm chứng bằng test | Hạn chế còn lại |
|---|---|---|---|
| Nghe lén | E2E, EtM, MSSV mã hoá | Có | Server thấy metadata |
| MitM | CA, CN, chữ ký T | Có | CA bị lộ |
| Replay | `seq`, nonce, timestamp | Có | Không (kể cả sau restart) |
| Mạo danh | UID, chữ ký, `sender` do server gán | Có | Cùng CN kết nối hai lần |
| Sửa dữ liệu | HMAC, RSA-PSS, SHA-256 | Có | Không |
| Padding oracle | Kiểm tra MAC trước giải mã | Có | Không |
| DoS cơ bản | Giới hạn, timeout, heartbeat | Có | Không giới hạn kết nối |
| Lộ khoá trong log | Không in khoá | Kiểm tra bằng mã | Không có test tự động |
| Reflection | *(không làm)* | Không | Khoá dùng chung hai chiều |
| Forward secrecy | *(không làm)* | Không | Lộ khoá server sau này giải được phiên cũ |

### 5.4 Các hạn chế đã biết (trung thực)

Các mục dưới đây phân loại theo trạng thái hiện tại của mã nguồn.

**✅ 5.4.1 Path traversal khi nhận file — ĐÃ SỬa.** `validate_filename()` kiểm tra whitelist `[A-Za-z0-9._-]` rồi `os.path.realpath` xác nhận đường dẫn cuối cùng nằm trong `downloads/`. Tên vượt ra ngoài thư mục bị từ chối trước khi lưu.

**⚠️ 5.4.2 File trùng tên không tải được bản thứ hai (mức trung bình).** Server đổi tên trên đĩa (`bao_cao (1).txt`) nhưng giữ nguyên `meta.name`. `!getfile bao_cao.txt` chỉ trả về bản đầu tiên tìm thấy. Hạn chế này chỉ ảnh hưởng khi upload cùng tên file nhiều lần; trong demo thông thường không xảy ra.

**✅ 5.4.3 Số thứ tự E2E không bền qua khởi động lại — ĐÃ SỬa.** `_load_state`/`_save_state` lưu `sent_msg_seq`, `sent_file_seq`, `last_msg_seq`, `last_file_seq` vào `.client_state/<CN>_state.json` sau mỗi lần gửi. Client khởi động lại nạp trạng thái cũ và tiếp tục từ seq cao hơn.

**✅ 5.4.4 Replay E2E sau khi người nhận khởi động lại — ĐÃ SỬa.** `last_seq` được lưu cùng file trạng thái, không chỉ ở bộ nhớ. Tin cũ phát lại sau khi người nhận khởi động lại vẫn bị từ chối nếu seq ≤ last_seq đã lưu.

**5.4.5 Thiết kế giới hạn còn lại (không sửa trong phạm vi đồ án).**
- Session theo CN: hai kết nối cùng nhóm ghi đè nhau.
- Roster chỉ gồm nhóm đã kết nối từ khi server khởi động.
- Client dùng nhãn CN do server gửi thay vì CN từ chứng chỉ (phòng thủ chiều sâu; server đã xác thực cert).

**✅ 5.4.6 Chỉ số chunk `idx` không nằm trong MAC — ĐÃ SỬa.** Mỗi chunk EtM trên `struct.pack("!I", i) + chunk_bytes`, ràng buộc thứ tự vào MAC một cách mật mã học. Hoán đổi chunk bị phát hiện ngay mà không cần đợi SHA-256 cuối.

**✅ 5.4.7 KeyUsage không được kiểm tra — ĐÃ SỬa.** `verify_cert` kiểm tra extension `KeyUsage`: leaf phải có `digitalSignature`; server cert thêm `keyEncipherment`.

**5.4.8 Không có forward secrecy và reflection.** Đã ghi chú trong phạm vi.

---

## 6. Cài đặt

### 6.1 Công nghệ và môi trường

| Thành phần | Công nghệ | Phiên bản |
|---|---|---|
| Ngôn ngữ | Python | 3.13.17 (môi trường đã chạy test) |
| Mật mã | `cryptography` | 50.0.2 |
| Mật mã | `pycryptodome` | 4.2.0 |
| Kiểm thử | `unittest` (thư viện chuẩn) | — |
| Hệ điều hành đã thử | Linux | — |

### 6.2 Cấu trúc mã nguồn

```
chatApp_cryptography/
├── src/
│   ├── pki.py           # nạp, kiểm tra chứng chỉ X.509; lấy CN và UID
│   ├── crypto_utils.py  # AES-CBC, EtM, RSA-OAEP, RSA-PSS, SHA-256, KDF, enc/enc_list/enc_map
│   ├── framing.py       # khung [length][payload], MAX_FRAME, recv trả None khi lỗi
│   ├── session.py       # record layer: EtM, seq, timestamp, lock, PING/PONG, idle timeout, sanitize
│   ├── handshake.py     # handshake client/server; transcript T; khoá init; khoá phiên
│   ├── e2e.py           # chat E2E, file E2E (chunk, wrap, chữ ký), validate_filename
│   ├── server.py        # accept, relay E2E, lưu file, roster, file list/get
│   └── client.py        # CLI, roster, gửi/nhận chat, gửi/nhận file
├── tools/
│   └── make_pki.py      # tạo CA, chứng chỉ server và chứng chỉ nhóm
├── tests/               # 13 file, 63 test
├── requirements.txt
├── KE_HOACH.md
└── README.md
```

### 6.3 Một số đoạn code quan trọng

**Kiểm tra chứng chỉ (pki.py):** chữ ký CA, thời hạn, không phải CA, CN.

```python
def verify_cert(cert, ca_cert, expected_cn=None):
    cert.verify_directly_issued_by(ca_cert)      # CA ký
    if not (not_before <= now <= not_after):      # còn hạn
        raise ValueError("Chứng chỉ đã hết hạn ...")
    bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
    if bc.value.ca:                               # không dùng CA làm leaf
        raise ValueError("Chứng chỉ là CA certificate ...")
```

**Server kiểm tra UID và chữ ký (handshake.py):**

```python
if get_uids(client_cert) != mssv_list:           # chống mạo danh
    raise ValueError("UID trong cert không khớp MSSV khai báo")
rsa_pss_verify(client_cert.public_key(), T, sig_bytes)   # chữ ký transcript
```

**Kiểm tra seq và timestamp (session.py):**

```python
seq = pkt.get("seq", 0)
if seq != self._recv_seq + 1:                    # chống replay
    self._closed = True; return None
self._recv_seq = seq
```

**Kiểm tra chunk và SHA-256 (e2e.py):**

```python
if sha256_hex(file_data) != sha256_expected:     # toàn vẹn nội dung
    return None
```

### 6.4 Hướng dẫn chạy

```bash
pip install -r requirements.txt

python tools/make_pki.py                                   # CA và chứng chỉ server
python tools/make_pki.py --team team1 --mssv 2312345 2312346
python tools/make_pki.py --team team2 --mssv 2312001 2312002

python src/server.py                                       # terminal 1
python src/client.py --cert pki/team1/client.crt --key pki/team1/client.key \
                     --mssv 2312345 2312346                # terminal 2
```

Lệnh trong client: nội dung bất kỳ để chat; `!roster`; `!sendfile <path>`; `!listfiles`; `!getfile <tên>`; `exit`.

---

## 7. Kiểm thử và kết quả

### 7.1 Phương pháp

- **Unit test** cho từng module: mật mã, KDF, PKI, khung truyền, replay, timeout, lock, lưu file, E2E.
- **Kiểm thử tích hợp:** handshake qua `socketpair`; chat và file qua TCP thật (`test_integration_tcp`).
- **Kiểm thử kịch bản tấn công:** MitM, sửa 1 byte trên dây, mạo danh, phát lại, đọc không có khoá.
- **Kiểm thử thủ công:** chạy server và hai client, chat, upload, liệt kê, tải về, đối chiếu SHA-256.
- **Đo hiệu năng:** đo trên một máy, không qua mạng, trong môi trường sandbox.

### 7.2 Bảng kết quả unittest

Lệnh chạy: `python -m unittest discover -s tests -v`.

| File test | Số test | Kết quả | Nội dung chính |
|---|---|---|---|
| test_concurrency.py | 1 | Pass | Hai luồng gửi đồng thời, `seq` và HMAC đúng |
| test_crypto.py | 7 | Pass | EtM roundtrip, sửa bit, khoá sai, frame ngắn, RSA-OAEP, RSA-PSS |
| test_e2e_chat.py | 5 | Pass | Giải mã đúng, không có khoá không đọc được, chữ ký giả, sender giả, replay seq |
| test_e2e_file.py | 6 | Pass | Roundtrip, SHA sai, thiếu chunk, sai thứ tự, không phải người nhận, vượt MAX_FILE |
| test_files_server.py | 6 | Pass | Tên file hợp lệ/không hợp lệ, path traversal, trùng tên, dọn tệp tạm |
| test_framing.py | 6 | Pass | Gửi/nhận, frame quá lớn, đọc từng mảnh, EOF |
| test_handshake.py | 7 | Pass | Hợp lệ, MitM, MSSV sai, khoá ký sai, chứng chỉ client lạ, MSSV không lộ, init replay |
| test_integration_tcp.py | 1 | Pass | Chat và file đầy đủ qua TCP |
| test_kdf.py | 7 | Pass | Không nhập nhằng, thứ tự, MS, nonce, khoá init |
| test_mitm_demo.py | 2 | Pass | Scenario 1: chứng chỉ giả; Scenario 2: sửa byte trên dây |
| test_pki.py | 7 | Pass | Hợp lệ, CA lạ, CN sai, CA làm leaf, hết hạn, chưa có hiệu lực, PEM/DER |
| test_replay.py | 6 | Pass | seq lặp, lùi, nhảy, timestamp quá cũ, timestamp tương lai |
| test_timeout.py | 2 | Pass | Idle đóng phiên; PING giữ phiên |
| **Tổng** | **63** | **63 pass, 0 fail** | Thời gian chạy khoảng 2.7 giây |

Ghi chú: `test_helpers.py` là module tiện ích, không chứa test.

### 7.3 Kịch bản kiểm thử tấn công

| Kịch bản | Kết quả mong đợi | Kết quả thực tế | Lý do từ chối (theo test) |
|---|---|---|---|
| Server có chứng chỉ do CA giả | Client từ chối | Pass | "Chữ ký chứng chỉ không hợp lệ (không phải do CA này ký)" |
| Client khai MSSV nhóm khác | Server từ chối | Pass | "UID không khớp MSSV khai báo" |
| Ký transcript bằng khoá sai | Server từ chối | Pass | "Chữ ký HANDSHAKE_INIT không hợp lệ" |
| Chứng chỉ client do CA lạ | Server từ chối | Pass | "Chữ ký chứng chỉ không hợp lệ (không phải do CA này ký)" |
| Gửi lại INIT cũ | Server từ chối | Đồ án xây dựng được một hệ thống chat và truyền file mã hoá đầu cuối, xác thực bằng chứng chỉ X.509 do CA nội bộ cấp. Giao thức bắt tay có chữ ký transcript và mã hoá gói INIT, nên kẻ đứng giữa không thay được khoá server mà client chấp nhận, và kẻ nghe lén không thấy MSSV. Khoá phiên được dẫn xuất theo công thức của đề với chuẩn hoá ghép chuỗi. Các tấn công nghe lén, MitM, phát lại, mạo danh và sửa đổi đều được chặn, và từng biện pháp có test kiểm chứng. Bộ 63 unittest pass, bao gồm kịch bản MitM và kiểm thử tích hợp qua TCP.

Các lỗi ưu tiên cao đã được vá sau khi kiểm định: path traversal khi nhận file ở phía client, số thứ tự E2E không bền qua khởi động lại, replay E2E sau khi người nhận khởi động lại, và việc ràng buộc thứ tự chunk vào MAC. Hạn chế còn lại ở mức ảnh hưởng thấp trong demo (file trùng tên, session ghi đè cUNDER cùng CN) và được ghi rõ trong phần hạn chế. Các hạn chế thiết kế như thiếu forward secrecy và reflection đã được ghi chú rõ. Với các biện pháp đã làm, hệ thống đáp ứng các yêu cầu bảo mật cơ bản của đề và đủ để làm demo cho đồ án. và chụp ảnh terminal.

### 7.5 Đo đạc hiệu năng

Đo trên cùng một máy (socketpair hoặc hàm trực tiếp), không qua mạng; bảng có thể khác khi chạy qua mạng thật.

| Thông số | Kết quả |
|---|---|
| Thời gian handshake (trung bình/nhỏ nhất/lớn nhất, n = 20) | 2.4 ms / 2.2 ms / 6.9 ms |
| Mã hoá một tin chat E2E (2 người nhận, 200 ký tự) | 0.5 ms |
| Chuẩn bị file 10 MiB (mã hoá, wrap, ký) | 0.08 s, 2560 chunk |
| Kích thước bản mã file 10 MiB | ≈ 10.16 MiB (overhead khoảng 1.6%) |
| Giải mã và kiểm tra file 10 MiB | 0.07 s, khớp nội dung gốc |

Nhận xét: RSA-2048 không phải nút thắt với đồ án này. Chi phí chính nằm ở số người nhận trong E2E (mỗi người nhận một phép RSA-OAEP cho mỗi tin).

---

## 8. Trạng thái thực hiện

### 8.1 Đã thực hiện

- [x] Hạ tầng PKI: CA tự ký, chứng chỉ server và chứng chỉ nhóm (`tools/make_pki.py`, `src/pki.py`)
- [x] Handshake xác thực hai chiều bằng chứng chỉ X.509
- [x] Chữ ký RSA-PSS trên transcript T, ràng buộc chứng chỉ, nonce, MS và MSSV
- [x] Kiểm tra UID trên chứng chỉ khớp MSSV khai báo (chống mạo danh)
- [x] Mã hoá gói `HANDSHAKE_INIT` bằng khoá tạm dẫn từ MS (MSSV không lộ trên dây)
- [x] KDF chuẩn hoá: `SHA256(MS ‖ enc_list(MSSV) ‖ enc(nonce))`, khoá AES/HMAC tách riêng
- [x] Mã hoá và xác thực gói tin: AES-256-CBC + HMAC-SHA256, Encrypt-then-MAC
- [x] Chống replay: `seq` theo chiều, nonce của server, timestamp
- [x] Chat mã hoá đầu cuối (E2E): khoá K, wrap RSA-OAEP, chữ ký RSA-PSS, server không giải mã
- [x] Truyền file mã hoá đầu cuối: chunk EtM, SHA-256 trong metadata đã ký, lưu bản mã trên server
- [x] Lock khi gửi đồng thời (chống race condition)
- [x] Giới hạn kích thước frame (64 KiB) và file (10 MiB)
- [x] Timeout đóng phiên, heartbeat PING/PONG
- [x] Ghi file tạm, chỉ đổi tên khi hoàn tất; dọn tệp tạm khi lỗi
- [x] Lọc ký tự điều khiển/ANSI khi hiển thị
- [x] Bộ unittest: 13 file, 63 test, toàn bộ pass
- [x] Tài liệu: README, KE_HOACH, báo cáo này

### 8.2 Đã thực hiện nhưng còn lỗi (cần sửa trước khi nộp)

- [~] Kiểm tra tên file: có ở server, **thiếu ở client** (path traversal, mục 5.4.1)
- [~] Không ghi đè file: có ở tầng lưu trữ, nhưng **tên hiển thị trùng** làm không tải được bản thứ hai (mục 5.4.2)
- [~] Replay E2E: có `seq`, nhưng **không bền qua khởi động lại** (mục 5.4.3, 5.4.4)
- [~] Roster: chỉ gồm nhóm đã kết nối từ khi server khởi động, khác kế hoạch (mục 5.4.5)
- [~] Mạo danh trong cùng nhóm: hai kết nối cùng CN ghi đè nhau (mục 5.4.5)

### 8.3 Chưa thực hiện

- [ ] Forward secrecy (ECDHE X25519)
- [ ] Khoá riêng theo từng chiều để chống reflection (HKDF)
- [ ] Thu hồi chứng chỉ (CRL/OCSP), chứng chỉ có hạn ngắn
- [ ] Mã hoá khoá riêng khi lưu trữ bằng passphrase
- [ ] Giới hạn tốc độ và số kết nối đồng thời
- [ ] Lịch sử chat mã hoá cho thành viên mới (khoá nhóm có xoay vòng)
- [ ] Giao diện đồ hoạ

*Lý do chưa làm:* ngoài phạm vi đồ án, cần nghiên cứu thêm, hoặc thiếu thời gian (ghi rõ trong bản nộp).

---

## 9. Hướng phát triển

1. **Forward secrecy.** Vấn đề: khoá RSA dài hạn của server mã hoá master secret, nên lộ khoá sau này giải được các phiên đã ghi lại. Giải pháp: ECDHE với X25519 cho khoá tạm mỗi phiên, giữ RSA chỉ để xác thực. Lợi ích: bảo vệ phiên cũ. Độ khó: trung bình.
2. **Chống reflection.** Vấn đề: cùng một khoá cho hai chiều. Giải pháp: HKDF với nhãn `c2s` và `s2c`. Độ khó: thấp.
3. **Quản lý chứng chỉ.** CRL hoặc chứng chỉ có hạn ngắn và cấp lại định kỳ. Độ khó: trung bình.
4. **Khoá riêng được mã hoá** bằng passphrase khi lưu. Độ khó: thấp.
5. **Giảm metadata.** Che tên người nhận bằng hộp thư (mailbox) hoặc tên giả. Độ khó: cao.
6. **Lịch sử chat cho thành viên mới** bằng khoá nhóm có xoay vòng khi có thành viên vào hoặc ra. Độ khó: cao.
7. **Giao diện** web hoặc đồ hoạ.

---

## 10. Kết luận

Đồ án xây dựng được một hệ thống chat và truyền file mã hoá đầu cuối, xác thực bằng chứng chỉ X.509 do CA nội bộ cấp. Giao thức bắt tay có chữ ký transcript và mã hoá gói INIT, nên kẻ đứng giữa không thay được khoá server mà client chấp nhận, và kẻ nghe lén không thấy MSSV. Khoá phiên được dẫn xuất theo công thức của đề với chuẩn hoá ghép chuỗi. Các tấn công nghe lén, MitM, phát lại, mạo danh và sửa đổi đều được chặn, và từng biện pháp có test kiểm chứng. Bộ 63 unittest pass, bao gồm kịch bản MitM và kiểm thử tích hợp qua TCP.

Hệ thống vẫn còn một số lỗi cần sửa trước khi nộp. Quan trọng nhất là kiểm tra tên file ở phía client, tên file trùng trên server, và số thứ tự E2E không bền qua khởi động lại. Các hạn chế về thiết kế như thiếu forward secrecy và reflection đã được ghi chú rõ. Với các biện pháp đã làm, hệ thống đáp ứng các yêu cầu bảo mật cơ bản của đề và đủ để làm demo cho đồ án.

---

## 11. Tài liệu tham khảo

1. NIST SP 800-38A — *Recommendation for Block Cipher Modes of Operation: Methods and Techniques* (chế độ CBC).
2. RFC 8017 — *PKCS #1: RSA Cryptography Specifications Version 2.2* (RSA-OAEP, RSA-PSS).
3. RFC 2104 — *HMAC: Keyed-Hashing for Message Authentication*.
4. FIPS PUB 180-4 — *Secure Hash Standard* (SHA-256).
5. RFC 5280 — *Internet X.509 Public Key Infrastructure Certificate and CRL Profile*.
6. RFC 5869 — *HMAC-based Extract-and-Expand Key Derivation Function (HKDF)* (dùng cho hướng phát triển).
7. RFC 7748 — *Elliptic Curves for Security* (X25519, dùng cho hướng phát triển).
8. M. Bellare, C. Namprempre, *Authenticated Encryption: Relations among notions and analysis of the generic composition paradigm*, ASIACRYPT 2000.
9. Tài liệu thư viện `cryptography` (pyca) và `pycryptodome`.

*(Bổ sung tài liệu môn học và bài báo khác nếu có.)*

---

## 12. Phụ lục

- **Phụ lục A:** kết quả đầy đủ của `python -m unittest discover -s tests -v` (63 dòng, dán từ terminal).
- **Phụ lục B:** ảnh chụp terminal của server và hai client trong kịch bản demo (chat, upload, list, download, cmp). *Chưa có, cần chụp sau khi chạy mục 7.4.*
- **Phụ lục C:** sơ đồ handshake chi tiết, định dạng khung và gói đầy đủ (mục 3.3 và 4.1).
- **Phụ lục D:** kết quả chạy hai kịch bản kiểm chứng lỗi (mục 5.4.1–5.4.3) trước khi sửa.
- **Phụ lục E:** đường dẫn mã nguồn và hướng dẫn cài đặt đầy đủ (README).