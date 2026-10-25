"""
session.py – Record layer sau handshake: mã hoá, seq, lock, PING/PONG, heartbeat.

Mỗi Session quản lý:
  - Mã hoá EtM: khoá phiên K_aes, K_hmac.
  - Số thứ tự (seq): mỗi chiều tăng dần từ 1; sai thứ tự → đóng phiên.
  - Timestamp: cửa sổ [now−30s, now+10s].
  - Lock: bảo vệ socket khi nhiều luồng gửi (chống race condition).
  - Heartbeat: PING mỗi 20s; idle 60s → đóng kết nối.
  - sanitize(): lọc ANSI và ký tự điều khiển khi in ra terminal.

Sử dụng:
    session = Session(sock, key_aes, key_hmac, peer_cn="team1")
    session.send("E2E_MSG", {"ciphertext": "..."}, sender="team1")
    pkt = session.recv()   # dict hoặc None
    session.start_heartbeat()
    session.close()
"""

import json
import re
import socket
import threading
import time

import framing
from crypto_utils import encrypt_then_MAC, verify_then_decrypt

# ─── Hằng số thời gian ────────────────────────────────────────────────────────

REPLAY_WINDOW_SEC: float = 30.0   # cửa sổ chấp nhận timestamp cũ
FUTURE_SLACK_SEC:  float = 10.0   # cho phép timestamp sớm hơn now
PING_INTERVAL:     float = 20.0   # giây giữa mỗi lần gửi PING
IDLE_TIMEOUT:      float = 60.0   # giây không có gói → đóng kết nối

# ─── Message types ────────────────────────────────────────────────────────────

# Handshake (gửi plaintext, không qua Session.send)
MT_HELLO          = "HANDSHAKE_HELLO"
MT_INIT           = "HANDSHAKE_INIT"
MT_OK             = "HANDSHAKE_OK"
MT_ACK            = "HANDSHAKE_ACK"

# Roster
MT_ROSTER_REQ     = "ROSTER_REQ"
MT_ROSTER_RESP    = "ROSTER_RESP"

# Chat E2E
MT_E2E_MSG        = "E2E_MSG"

# Thông báo hệ thống (server → client, plaintext trong payload)
MT_SYS_MSG        = "SYS_MSG"

# File E2E
MT_FILE_E2E_START = "FILE_E2E_START"
MT_FILE_E2E_CHUNK = "FILE_E2E_CHUNK"
MT_FILE_E2E_END   = "FILE_E2E_END"
MT_FILE_LIST_REQ  = "FILE_LIST_REQ"
MT_FILE_LIST_RESP = "FILE_LIST_RESP"
MT_FILE_GET_REQ   = "FILE_GET_REQ"

# Điều khiển
MT_PING           = "PING"
MT_PONG           = "PONG"
MT_DISCONNECT     = "DISCONNECT"
MT_ERROR          = "ERROR"

# ─── Lọc ký tự điều khiển ────────────────────────────────────────────────────

_ANSI_RE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
_CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def sanitize(text: str) -> str:
    """Lọc escape ANSI và ký tự điều khiển trước khi hiển thị ra terminal."""
    text = _ANSI_RE.sub("", text)
    text = _CTRL_RE.sub("", text)
    return text


# ─── Session ──────────────────────────────────────────────────────────────────

class Session:
    """Kênh mã hoá đã xác thực (EtM) với kiểm tra seq và heartbeat."""

    def __init__(
        self,
        sock: socket.socket,
        key_aes: bytes,
        key_hmac: bytes,
        peer_cn: str = "",
        peer_cert_pem: str = "",
    ):
        self.sock          = sock
        self.key_aes       = key_aes
        self.key_hmac      = key_hmac
        self.peer_cn       = peer_cn          # CN của phía bên kia (từ cert)
        self.peer_cert_pem = peer_cert_pem    # PEM của chứng chỉ phía bên kia

        self._send_lock = threading.Lock()
        self._send_seq  = 0              # tăng trong _send_lock trước khi gửi
        self._recv_seq  = 0              # seq được nhận gần nhất
        self._last_recv = time.monotonic()
        self._closed    = False
        self._hb_thread: threading.Thread | None = None

    # ── Gửi ──────────────────────────────────────────────────────────────────

    def send(self, msg_type: str, payload: dict, sender: str = "") -> None:
        """
        Gửi gói tin đã mã hoá EtM. Thread-safe (lock bảo vệ seq và sendall).
        sender: thường là CN của bên gửi (server sẽ ghi đè khi relay).
        """
        with self._send_lock:
            if self._closed:
                return
            self._send_seq += 1
            pkt = {
                "type":      msg_type,
                "sender":    sender,
                "seq":       self._send_seq,
                "payload":   payload,
                "timestamp": time.time(),
            }
            raw   = json.dumps(pkt, ensure_ascii=False).encode()
            frame = encrypt_then_MAC(raw, self.key_aes, self.key_hmac)
            framing.send_frame(self.sock, frame)

    # ── Nhận ─────────────────────────────────────────────────────────────────

    def recv(self) -> dict | None:
        """
        Nhận và xác thực một gói tin. Trả về dict hoặc None khi lỗi.
        Kiểm tra:
          1. HMAC hợp lệ (verify_then_decrypt).
          2. seq đúng bằng recv_seq + 1.
          3. timestamp trong cửa sổ [now−30s, now+10s].
        None → caller nên đóng phiên.
        """
        frame = framing.recv_frame(self.sock)
        if frame is None:
            self._closed = True
            return None

        raw = verify_then_decrypt(frame, self.key_aes, self.key_hmac)
        if raw is None:
            self._closed = True
            return None

        try:
            pkt = json.loads(raw.decode())
        except (json.JSONDecodeError, UnicodeDecodeError):
            self._closed = True
            return None

        # Kiểm tra seq
        seq = pkt.get("seq", 0)
        if seq != self._recv_seq + 1:
            self._closed = True
            return None
        self._recv_seq = seq

        # Kiểm tra timestamp
        ts  = pkt.get("timestamp", 0.0)
        now = time.time()
        if not (now - REPLAY_WINDOW_SEC <= ts <= now + FUTURE_SLACK_SEC):
            self._closed = True
            return None

        self._last_recv = time.monotonic()
        return pkt

    # ── Heartbeat ─────────────────────────────────────────────────────────────

    def start_heartbeat(self) -> None:
        """Khởi động luồng gửi PING định kỳ và kiểm tra idle timeout."""
        self._hb_thread = threading.Thread(
            target=self._heartbeat_loop, daemon=True, name="heartbeat"
        )
        self._hb_thread.start()

    def _heartbeat_loop(self) -> None:
        while not self._closed:
            time.sleep(PING_INTERVAL)
            if self._closed:
                break
            # Kiểm tra idle
            if time.monotonic() - self._last_recv > IDLE_TIMEOUT:
                self._closed = True
                try:
                    self.sock.close()
                except Exception:
                    pass
                break
            # Gửi PING
            try:
                self.send(MT_PING, {})
            except Exception:
                self._closed = True
                break

    # ── Đóng ─────────────────────────────────────────────────────────────────

    def close(self) -> None:
        """Đóng session và socket."""
        self._closed = True
        try:
            self.sock.close()
        except Exception:
            pass

    @property
    def closed(self) -> bool:
        return self._closed
