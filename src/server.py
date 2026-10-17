import socket
import threading
import time
import secrets
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
    make_file_data, make_file_start, make_file_end, make_file_list_resp
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
        self.session_key: bytes | None = None
        self.key_aes: bytes | None = None    # AES-256 key (Tách khoá)
        self.key_hmac: bytes | None = None    # HMAC key (Tách khoá)
        self.server_nonce: str       = ""       # Nonce ngẫu nhiên do Server sinh
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

        self.storage_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "../server_storage")
        os.makedirs(self.storage_dir, exist_ok=True)

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
        conn.settimeout(60)

        session = ClientSession(cid, conn, addr)

        with self._lock:
            self.clients[cid] = session

        try:
            if not self._handshake(session):
                self.log(f"Handshake thất bại với Client #{cid}. Đóng kết nối.")
                return
            
            self.log(f"Handshake thành công với Client #{cid}. (MSSV: {', '.join(session.mssv_list)})")
            #Thông báo broadcast
            self._broadcast_system(f"[{session.username}] đã tham gia phòng chat.", exclude_id=cid)

            while session.connected:
                pkt = session.recv_packet()
                if pkt is None:
                    break
                self._process(session, pkt) #logic xử lý gói tin

        except Exception as e:
            self.log(f"Lỗi Client #{cid}: {e}")
        finally:
            session.close()
            with self._lock:
                self.clients.pop(cid, None)
            self.log(f"Client #{cid} đã ngắt kết nối.")
            self._broadcast_system(f"[{session.username}] đã rời phòng chat.", exclude_id=cid)


    def _handshake(self, session: ClientSession) -> bool:


        try:
            session.server_nonce = secrets.token_hex(16)
            session.send_packet(make_handshake_response(self._pub_pem, session.server_nonce))

            pkt = session.recv_packet()
            if pkt is None or pkt.type != MessageType.HANDSHAKE_INIT.value : return False

            msg = pkt.payload.get("message", "")
            mssv_list = pkt.payload.get("mssv_list", [])
            ms_hex = pkt.payload.get("encrypted_ms" ,"")

            session.mssv_list = mssv_list
            session.username  = f"{'_'.join(str(m) for m in mssv_list)}" if mssv_list else session.username

            ms_bytes = hex_to_bytes(ms_hex)
            try: 
                master_secret = rsa_decrypt(ms_bytes, self._priv_key)
            except Exception as e:
                self.log(f"Lỗi giải mã master secret: {e}")
                return False

            self.log(f"  → Thông điệp MSSV: '{msg}'")
            self.log(f"  → Server Nonce: {session.server_nonce[:8]}...")
            self.log(f"  → Master Secret (hex đầu): {master_secret.hex()[:16]}…")


            #KDF
            session.session_key = derive_session_key(master_secret, mssv_list, session.server_nonce)
            self.log(f"  ✓ Session Key dẫn xuất thành công (hex đầu): {session.session_key.hex()[:16]}…")
            session.key_enc, session.key_mac = derive_keys(session.session_key)
            #Send response
            session.send_packet(make_handshake_ok())
            #Recv ACK
            ack = session.recv_packet()
            if ack is None or ack.type != MessageType.HANDSHAKE_ACK.value:
                return False

            return True
        except Exception as e:
            self.log(f"Handshake lỗi : {e}")
            return False


    def _broadcast(self, pkt: Packet, exclude_id: int = -1) -> None:
        with self._lock:
            target = [s for cid, s in self.clients.items()
                      if cid != exclude_id and s.connected and s.session_key is not None]


        for s in target:
            try:
                s.send_packet(pkt)
            except Exception as e:
                self.log(f"Lỗi Broadcast : {e}")

    def _broadcast_system(self, text: str, exclude_id: int = -1) -> None:
        """Gửi thông báo hệ thống broadcast"""
        pkt = make_message(f"[Server]: {text}", "server")
        self._broadcast(pkt, exclude_id=exclude_id)


    def _process(self,session: ClientSession, pkt: Packet ):
        t = pkt.type

        if t == MessageType.MESSAGE.value:
            content = pkt.payload.get("content", "")
            self.log(f"[Chat {session.username}] {content}")
            relay_pkt = make_message(f"[{session.username}] {content}", "server")
            self._broadcast(relay_pkt, exclude_id=session.client_id)
            #ACK cho client gửi
            session.send_packet(make_message_ack())

        elif t == MessageType.FILE_TRANSFER_START.value:
            raw_filename = pkt.payload.get("filename", "file.bin")

            session._file_name = os.path.basename(raw_filename)
            session._file_chk  = pkt.payload.get("checksum", "")
            session._file_buf  = bytearray()
            self.log(f"Bắt đầu nhận file '{session._file_name}' từ {session.username}")
        
        elif t == MessageType.FILE_TRANSFER_DATA.value:
            chunk_hex = pkt.payload.get("data", "")
            session._file_buf.extend(hex_to_bytes(chunk_hex))
        
        elif t == MessageType.FILE_TRANSFER_END.value:
            actual_chk = sha256_hex(bytes(session._file_buf))
            
            
            save_path  = os.path.join(self.storage_dir, session._file_name)
            
            with open(save_path, "wb") as f:
                f.write(session._file_buf)
            
            if actual_chk.lower() == session._file_chk.lower():
                self.log(f"  File '{save_path}' nhận OK - SHA-256 khớp!")
                self._broadcast_system(
                    f"[{session.username}] đã chia sẻ file '{session._file_name}' ({len(session._file_buf)} bytes). Gõ '!download {session._file_name}' để tải về."
                )
            else:
                self.log(f"  File '{save_path}' BỊ LỖI - SHA-256 KHÔNG KHỚP!")
                self.log(f"  Nhận: {actual_chk[:16]}…  Kỳ vọng: {session._file_chk[:16]}…")


        #List các file có trên server
        elif t == MessageType.FILE_LIST_REQ.value:
            file_list = []
            try:
                for fname in os.listdir(self.storage_dir):
                    fpath = os.path.join(self.storage_dir, fname)
                    if os.path.isfile(fpath):
                        file_list.append({
                            "filename": fname,
                            "size": os.path.getsize(fpath),
                        })
            except Exception as e:
                self.log(f"Lỗi đọc danh sách file: {e}")
            session.send_packet(make_file_list_resp(file_list))

        #Download 1 file với lệnh !download
        elif t == MessageType.FILE_DOWNLOAD_REQ.value:
            req_filename = os.path.basename(pkt.payload.get("filename", ""))
            file_path    = os.path.join(self.storage_dir, req_filename)

            if not os.path.exists(file_path) or not os.path.isfile(file_path):
                self.log(f"Client #{session.client_id} yêu cầu tải file không tồn tại: '{req_filename}'")
                session.send_packet(make_error(404, f"File '{req_filename}' không tồn tại trên Server!"))
                return

            try:
                with open(file_path, "rb") as f:
                    file_data = f.read()
                filesize = len(file_data)
                checksum = sha256_hex(file_data)

                self.log(f"Đang gửi file '{req_filename}' ({filesize} bytes) cho {session.username}...")
                session.send_packet(make_file_start(req_filename, filesize, checksum))

                chunk_size = 4096
                for i, offset in enumerate(range(0, filesize, chunk_size)):
                    chunk = file_data[offset: offset + chunk_size]
                    session.send_packet(make_file_data(i, chunk))

                session.send_packet(make_file_end())
                self.log(f"  Đã gửi xong file '{req_filename}' tới {session.username}")
            except Exception as e:
                self.log(f"Lỗi khi gửi file tải về cho Client #{session.client_id}: {e}")
                session.send_packet(make_error(500, f"Lỗi đọc/truyền file trên Server: {e}"))

        


        elif t == MessageType.DISCONNECT.value:
            reason = pkt.payload.get("reason", "")
            self.log(f"Client #{session.client_id} yêu cầu ngắt kết nối: {reason}")
            session.connected = False

        else:
            self.log(f"Nhận gói không xác định: {t}")
if __name__ == "__main__":
    server = SecureChatServer(host="0.0.0.0", port=5000)
    server.start()