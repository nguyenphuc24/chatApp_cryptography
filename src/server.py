import socket
import threading
import time
import os
import hashlib
from datetime import datetime

from crypto_utils import (
    gen_rsa_keypair, serialize_public_key, deserialize_public_key,
    rsa_decrypt, aes_encrypt, aes_decrypt,
    hmac_sign, hmac_verify, derive_session_key,
    derive_keys, encrypt_then_MAC, MAC_then_decrypt,
    hex_to_bytes, sha256_hex, bytes_to_hex,
)

from protocol import (
    Packet, MessageType,
    send_msg, recv_msg,
    make_handshake_response, make_handshake_ok, make_message_ack,
    make_message, make_error,
)

# Bảo vệ Replay attack

REPLAY_WINDOW_SECONDS = 30

def is_timestamp_valid(ts: float) -> bool:
    now = time.time()
    return (now - REPLAY_WINDOW_SECONDS) <= ts <= (now + 10)

# Quản lý phiên Client
class ClientSession:

    
    def __init__(self, client_id: int, sock: socket.socket, addr: tuple):
        self.client_id      = client_id
        self.socket         = sock
        self.addr           = addr
        self.client_pub_key = None              # RSA public key của client
        self.session_key: bytes | None = None
        self.key_aes: bytes | None = None    # AES-256 key (Tách khoá)
        self.key_hmac: bytes | None = None    # HMAC key (Tách khoá)
        self.server_nonce: str       = ""       # Nonce ngẫu nhiên do Server sinh
        self.client_nonce: str       = ""       # Nonce ngẫu nhiên do Client gửi
        self.mssv_list: list[str]    = []
        self.username: str           = f"Client#{client_id}"
        self.connected       = True
        # Buffer nhận file
        self._file_buf : bytearray = bytearray()
        self._file_name: str       = ""
        self._file_chk : str       = ""


    def send_packet(self, pkt: Packet) -> None:
        raw = pkt.to_bytes()

        if self.session_key is not None:
            payload = encrypt_then_MAC(raw, self.key_aes, self.key_hmac)

        else : 
            payload = raw

        send_msg(self.socket, payload)

    def recv_packet(self) -> Packet | None:
        raw_payload = recv_msg(self.socket)
        if raw_payload is None:
            self.connected = False
            return None

        if self.key_aes is not None and self.key_hmac is not None:
            decrypted = MAC_then_decrypt(raw_payload, self.key_aes, self.key_hmac)
            if decrypted is None:
                print(f"[!] WARNING : Gói tin từ client #{self.client_id} bị giả mạo hoặc lỗi HMAC")
                return None

            pkt = Packet.from_byte(decrypted)

            if not is_timestamp_valid(pkt.timestamp):
                print(f"[!] WARNING : Gói tin từ client {self.client_id} quá hạn (Replay Attack)")
                return None
            return pkt

        else: 
            return Packet.from_byte(raw_payload)


    def close(self):
        self.connected = False
        try:
            self.socket.close()
        except Exception:
            pass



class SecureChatServer:
    def __init__(self, host: str = "0.0.0.0", port: int = 5000):
        self.host    = host
        self.port    = port
        self.running = True
        self.clients: dict[int, ClientSession] = {}
        self._lock   = threading.Lock()
        self._next_id = 0

        # Sinh cặp khoá RSA-2048 cho Server
        self.log("Đang sinh cặp khoá RSA-2048 cho Server…")
        self._priv_key, self._pub_key = gen_rsa_keypair(2048)
        self._pub_pem = serialize_public_key(self._pub_key).decode()
        self.log("Sinh khoá RSA xong.")

    def log(self, msg: str):
        ts = datetime.now().strftime("%H:%M:%S")
        print(f"[{ts}] [Server] {msg}")

    def start(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((self.host, self.port))
        srv.listen(5)
        self.log(f"Đang lắng nghe trên {self.host}:{self.port}")

        try:
            while self.running:
                try:
                    conn, addr = srv.accept()
                except OSError:
                    break

                with self._lock:
                    self._next_id += 1
                    cid = self._next_id

                self.log(f"Client #{cid} kết nối từ {addr[0]}:{addr[1]}")
                t = threading.Thread(
                    target=self._handle_client,
                    args=(cid, conn, addr),
                    daemon=True
                )
                t.start()
        except KeyboardInterrupt:
            print("Tắt server ...")
        finally:
            self.running = False
            for s in list(self.clients.values()):
                s.close()
            srv.close()

    def _handle_client(self, cid: int, conn: socket.socket, addr: tuple):
        pass
