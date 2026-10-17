import socket
import os
import sys
import threading
import secrets
import time

from datetime import datetime

from crypto_utils import (
    deserialize_public_key, rsa_encrypt,
    derive_session_key, derive_keys,
    encrypt_then_MAC, MAC_then_decrypt,
    hex_to_bytes, sha256_hex,
)
from protocol import (
    Packet, MessageType,
    send_msg, recv_msg,
    make_handshake_init, make_handshake_ack,
    make_message, make_file_start, make_file_data, make_file_end,
    make_file_list_req, make_file_download_req,
    make_disconnect,
)



REPLAY_WINDOW_SECONDS = 30

def is_timestamp_valid(ts: float) -> bool:
    now = time.time()
    return (now - REPLAY_WINDOW_SECONDS) <= ts <= (now + 10)


class SecureChatClient:

    def __init__(self, host: str = '127.0.0.1', port: int = 5000,
                 mssv_list: list = None):
        self.host = host
        self.port = port
        self.mssv_list = mssv_list

        self.sock: socket.socket | None = None
        self.connected                  = False
        self.running                    = True

        self.server_pub_key             = None
        self.master_secret: bytes| None = None
        self.session_key: bytes | None  = None
        self.key_aes : bytes | None     = None
        self.key_hmac : bytes | None    = None
        self.server_nonce: str          = ""


        self.download_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "../downloads")
        os.makedirs(self.download_dir, exist_ok=True)

        self._recv_file_name: str = ""
        self._recv_file_chk : str = ""
        self._recv_file_size: int = 0
        self._recv_file_buf: bytearray = bytearray()


    def log(self, msg: str = ""):
        ts = datetime.now().strftime("%H:%M:%S")
        print(f"[{ts}] [Client] {msg}")

    def _send_packet(self, pkt: Packet) -> None:
        raw = pkt.to_bytes()
        if self.key_aes is not None and self.key_hmac is not None:
            payload = encrypt_then_MAC(raw, self.key_aes, self.key_hmac)
        else:
            payload = raw
        send_msg(self.sock, payload)

    def _recv_packet(self) -> Packet | None:
        raw_payload = recv_msg(self.sock)
        if raw_payload is None:
            self.connected = False
            return None

        if self.key_aes is not None and self.key_hmac is not None:
            decrypted = MAC_then_decrypt(raw_payload, self.key_aes, self.key_hmac)
            if decrypted is None:
                self.log("[CẢNH BÁO] Gói tin từ Server BỊ GIẢ MẠO hoặc lỗi HMAC! Drop.")
                return None

            pkt = Packet.from_byte(decrypted)

            if not is_timestamp_valid(pkt.timestamp):
                self.log("[CẢNH BÁO] Gói tin từ Server bị REPLAY ATTACK - timestamp lỗi thời!")
                return None

            return pkt
        else:
            return Packet.from_byte(raw_payload)


    def connect(self) -> bool:
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((self.host, self.port))
            self.connected = True
            self.log(f"Đã kết nối tới {self.host}:{self.port}")
            return True
        except Exception as e:
            self.log(f"Không thể kết nối : {e}")
            return False

    def handshake(self) -> bool:
        try: 
            r1 = self._recv_packet()
            if r1 is None or r1.type != MessageType.HANDSHAKE_RESPONSE.value:
                return False

            srv_pub_pem = r1.payload.get("public_key", "")
            self.server_nonce = r1.payload.get("server_nonce", "")
            self.server_pub_key = deserialize_public_key(srv_pub_pem.encode())
            
            self.log(f"Đã nhận Server Public Key và Server Nonce: {self.server_nonce[:8]}…")

            self.master_secret = secrets.token_bytes(32)
            self.log(f"Đã sinh Pre-Master Secret (hex đầu): {self.master_secret.hex()[:16]}…")
            encrypted_ms = rsa_encrypt(self.master_secret, self.server_pub_key)


            self.session_key = derive_session_key(self.master_secret, self.mssv_list, self.server_nonce)
            self.log(f"Session Key dẫn xuất (KDF từ MS + MSSV + Server Nonce): {self.session_key.hex()[:16]}…")


            pkt = make_handshake_init(
                mssv_list=self.mssv_list,
                encrypted_ms_hex=encrypted_ms.hex(),
            )

            self._send_packet(pkt)
            self.log(f"Đã gửi HANDSHAKE_INIT: 'Hello, We are {', '.join(self.mssv_list)}' kèm encrypted_ms")

            self.key_aes, self.key_hmac = derive_keys(self.session_key)
            #Bước này đã có kiểm tra HMAC
            r2 = self._recv_packet()
            if r2 is None or r2.payload.get("status") != "HANDSHAKE_OK":
                return False

            # Gửi ACK
            self._send_packet(make_handshake_ack())
            self.log("  Handshake HOÀN TẤT - Kênh truyền đã được mã hoá Encrypt-then-MAC (EtM).")
            return True
        except Exception as e:
            self.log(f"Lỗi Handshake: {e}")
            return False

    def send_chat(self, msg: str) -> None:
        self._send_packet(make_message(content=msg, sender="client"))


    def send_file(self, path: str) -> None:
        if not os.path.exists(path):
            self.log(f"File không tồn tại: {path}")
            return

        filename = os.path.basename(path)
        with open(path, "rb") as f:
            data = f.read()
        filesize = len(data)
        checksum = sha256_hex(data)

        self.log(f"Gửi file '{filename}' ({filesize} bytes) | SHA-256: {checksum[:16]}…")

        # Gửi START
        self._send_packet(make_file_start(filename, filesize, checksum))

        # Gửi từng chunk 4 KB
        chunk_size  = 4096
        chunk_count = (filesize + chunk_size - 1) // chunk_size
        for i, offset in enumerate(range(0, filesize, chunk_size)):
            chunk = data[offset: offset + chunk_size]
            self._send_packet(make_file_data(i, chunk))
            # Hiển thị tiến trình
            pct = int((i + 1) / chunk_count * 100)
            print(f"\r  Tiến trình: {i+1}/{chunk_count} chunks ({pct}%)", end="", flush=True)
        print()

        # Gửi END
        self._send_packet(make_file_end())
        self.log(f"  Đã gửi xong file '{filename}'")

    def _receive_loop(self):
        """Thread nền nhận thông điệp từ Server (ACK, broadcast chat, thông báo hệ thống)."""
        while self.running and self.connected:
            try:
                pkt = self._recv_packet()
                if pkt is None:
                    break
                if pkt.type == MessageType.MESSAGE_ACK.value:
                    # Server xác nhận đã nhận tin của mình
                    print(f"\n [Server ACK] Tin nhắn đã được gửi.\n> ", end="", flush=True)
                elif pkt.type == MessageType.MESSAGE.value:
                    # Tin nhắn broadcast từ client khác hoặc thông báo hệ thống
                    content = pkt.payload.get("content", "")
                    print(f"\n{content}\n> ", end="", flush=True)
                elif pkt.type == MessageType.FILE_TRANSFER_START.value:
                    self._recv_file_name = os.path.basename(pkt.payload.get("filename", "downloaded_file"))
                    self._recv_file_size = pkt.payload.get("filesize", 0)
                    self._recv_file_chk  = pkt.payload.get("checksum", "")
                    self._recv_file_buf  = bytearray()
                    print(f"\n[File] Đang nhận file '{self._recv_file_name}' ({self._recv_file_size} bytes)...\n> ", end="", flush=True)
                elif pkt.type == MessageType.FILE_TRANSFER_DATA.value:
                    chunk_hex = pkt.payload.get("data", "")
                    self._recv_file_buf.extend(hex_to_bytes(chunk_hex))
                elif pkt.type == MessageType.FILE_TRANSFER_END.value:
                    actual_chk = sha256_hex(bytes(self._recv_file_buf))
                    save_path  = os.path.join(self.download_dir, self._recv_file_name)
                    if actual_chk.lower() == self._recv_file_chk.lower():
                        with open(save_path, "wb") as f:
                            f.write(self._recv_file_buf)
                        print(f"\n  [File] Đã tải về thành công file '{self._recv_file_name}'!\n  Lưu tại: {save_path}\n  SHA-256 khớp: {actual_chk[:16]}…\n> ", end="", flush=True)
                    else:
                        print(f"\n  [File] Lỗi: Checksum SHA-256 không khớp khi tải file '{self._recv_file_name}'!\n> ", end="", flush=True)
                elif pkt.type == MessageType.FILE_LIST_RESP.value:
                    files = pkt.payload.get("files", [])
                    print("\n" + "=" * 50)
                    print(f" DANH SÁCH FILE TRÊN SERVER ({len(files)} files)")
                    print("=" * 50)
                    if not files:
                        print("  (Hiện chưa có file nào trên server)")
                    else:
                        for idx, item in enumerate(files, 1):
                            fname = item.get("filename", "")
                            fsize = item.get("size", 0)
                            print(f"  {idx}. {fname:<25} ({fsize:,} bytes)")
                        print("  Gõ '!download <tên_file>' để tải về máy.")
                    print("=" * 50 + "\n> ", end="", flush=True)
                elif pkt.type == MessageType.ERROR.value:
                    code = pkt.payload.get("error_code", 0)
                    msg  = pkt.payload.get("error_message", "")
                    print(f"\n[!] Lỗi từ Server [{code}]: {msg}\n> ", end="", flush=True)
            except Exception:
                break
        self.connected = False


    def run(self):
        if not self.connect():
            return
        if not self.handshake():
            self.log("Handshake thất bại, dừng.")
            return

        t = threading.Thread(target=self._receive_loop, daemon=True)
        t.start()

        print()
        print("=" * 55)
        print(" SECURE CHAT CLIENT - SẴN SÀNG")
        print(" Lệnh:")
        print("   - Nhập nội dung bất kỳ để chat bảo mật")
        print("   - '!sendfile <path>'     : Gửi file lên server")
        print("   - '!listfiles'           : Xem danh sách file trên server")
        print("   - '!download <tên_file>' : Tải file từ server về máy")
        print("   - 'exit'                 : Thoát chương trình")
        print("=" * 55)

        try:
            while self.running and self.connected:
                try:
                    line = input("> ").strip()
                except EOFError:
                    break

                if not line:
                    continue

                if line.lower() == "exit":
                    self._send_packet(make_disconnect())
                    break
                elif line.startswith("!sendfile "):
                    path = line[len("!sendfile "):].strip()
                    self.send_file(path)
                elif line.lower() == "!listfiles":
                    self._send_packet(make_file_list_req())
                elif line.startswith("!download "):
                    target_file = line[len("!download "):].strip()
                    if target_file:
                        self.log(f"Yêu cầu tải file '{target_file}'...")
                        self._send_packet(make_file_download_req(target_file))
                    else:
                        print("Cú pháp: !download <tên_file>")
                else:
                    self.send_chat(line)

        except KeyboardInterrupt:
            pass
        finally:
            self.shutdown()

    def shutdown(self):
        self.log("Đang đóng Client…")
        self.running   = False
        self.connected = False
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass


if __name__ == "__main__":
    mssv = ["2312345", "2312346"]        # ← Thay bằng MSSV thực tế của nhóm
    if len(sys.argv) > 2 and sys.argv[1] == "--mssv":
        mssv = sys.argv[2:]

    client = SecureChatClient(host="127.0.0.1", port=5000, mssv_list=mssv)
    client.run()
