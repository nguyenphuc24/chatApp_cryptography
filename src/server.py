"""
server.py – Server đa luồng: accept kết nối, handshake, relay E2E, lưu file.

Chức năng:
  - Xác thực từng client bằng PKI (handshake.server_handshake).
  - Server gán sender = CN của cert (client không tự khai được).
  - Relay E2E_MSG nguyên vẹn (không giải mã).
  - Lưu file E2E vào server_storage/ (meta + chunks JSON).
  - Xử lý ROSTER_REQ, FILE_LIST_REQ, FILE_GET_REQ.
  - PING/PONG heartbeat; idle 60s → đóng kết nối.
  - Ghi file an toàn: ghi tệp tạm, os.replace khi hoàn tất; xoá tạm nếu lỗi.
  - Tên file hợp lệ: [A-Za-z0-9._-], ≤100 ký tự. Trùng tên → đổi tên.
  - Giới hạn kích thước file: MAX_FILE = 10 MiB.

Chạy:
  python src/server.py
  python src/server.py --ca pki/ca.crt --cert pki/server.crt --key pki/server.key
"""

import argparse
import json
import os
import sys
import threading
import time
import uuid
from datetime import datetime

# Thêm src/ vào path để import các module cùng thư mục
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import framing
import handshake as hs
import pki as pki_module
from e2e import validate_filename, MAX_FILE
from session import (
    Session, sanitize,
    MT_PING, MT_PONG, MT_DISCONNECT, MT_ERROR,
    MT_ROSTER_REQ, MT_ROSTER_RESP,
    MT_E2E_MSG,
    MT_SYS_MSG,
    MT_FILE_E2E_START, MT_FILE_E2E_CHUNK, MT_FILE_E2E_END,
    MT_FILE_LIST_REQ, MT_FILE_LIST_RESP, MT_FILE_GET_REQ,
)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_CA      = os.path.join(BASE_DIR, "pki", "ca.crt")
DEFAULT_CERT    = os.path.join(BASE_DIR, "pki", "server.crt")
DEFAULT_KEY     = os.path.join(BASE_DIR, "pki", "server.key")
DEFAULT_STORAGE = os.path.join(BASE_DIR, "server_storage")


# ─── Đổi tên file không trùng ─────────────────────────────────────────────────

def _unique_name(storage_dir: str, name: str) -> str:
    """Nếu <name>.json đã tồn tại, thử <name> (1).json, (2)... cho đến khi tìm được."""
    base, ext = os.path.splitext(name)
    candidate  = name
    i = 1
    while os.path.exists(os.path.join(storage_dir, candidate + ".json")):
        candidate = f"{base} ({i}){ext}"
        i += 1
    return candidate


# ─── Server ────────────────────────────────────────────────────────────────────

class SecureChatServer:

    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 5000,
        ca_cert=None,
        server_cert=None,
        server_key=None,
        storage_dir: str = DEFAULT_STORAGE,
    ):
        self.host        = host
        self.port        = port
        self.ca_cert     = ca_cert
        self.server_cert = server_cert
        self.server_key  = server_key
        self.storage_dir = storage_dir
        os.makedirs(self.storage_dir, exist_ok=True)

        self._lock   = threading.Lock()
        # sessions: {cn: Session}  — chỉ client đã handshake thành công
        self._sessions: dict[str, Session] = {}
        # known_certs: {cn: x509.Certificate} — tất cả cert đã thấy
        self._known_certs: dict[str, object] = {}

    def log(self, msg: str) -> None:
        ts = datetime.now().strftime("%H:%M:%S")
        safe_msg = sanitize(msg)
        try:
            print(f"[{ts}] [Server] {safe_msg}")
        except UnicodeEncodeError:
            print(f"[{ts}] [Server] {safe_msg.encode('ascii', errors='backslashreplace').decode('ascii')}")

    # ── Vòng lặp chính ────────────────────────────────────────────────────────

    def start(self) -> None:
        srv = __import__("socket").socket()
        srv.setsockopt(__import__("socket").SOL_SOCKET, __import__("socket").SO_REUSEADDR, 1)
        srv.bind((self.host, self.port))
        srv.listen(10)
        self._srv = srv
        self.log(f"Lắng nghe tại {self.host}:{self.port}")

        try:
            while True:
                try:
                    conn, addr = srv.accept()
                except OSError:
                    break
                conn.settimeout(60)
                t = threading.Thread(
                    target=self._handle_client,
                    args=(conn, addr),
                    daemon=True,
                )
                t.start()
        except KeyboardInterrupt:
            self.log("Tắt server.")
        finally:
            try:
                srv.close()
            except Exception:
                pass

    def stop(self) -> None:
        """Đóng server socket để thoát vòng lặp accept."""
        if hasattr(self, "_srv") and self._srv:
            try:
                self._srv.close()
            except Exception:
                pass

    # ── Xử lý từng client ─────────────────────────────────────────────────────

    def _handle_client(self, conn, addr) -> None:
        peer = f"{addr[0]}:{addr[1]}"
        session: Session | None = None
        try:
            session = hs.server_handshake(
                conn, self.ca_cert, self.server_cert, self.server_key
            )
        except Exception as exc:
            self.log(f"Handshake thất bại từ {peer}: {exc}")
            try:
                conn.close()
            except Exception:
                pass
            return

        cn = session.peer_cn
        self.log(f"Handshake OK: {cn} ({peer})")

        with self._lock:
            self._sessions[cn] = session
            if session.peer_cert_pem:
                self._known_certs[cn] = session.peer_cert_pem

        self._broadcast_sys(f"{cn} đã tham gia.", exclude_cn=cn)

        try:
            self._dispatch_loop(session)
        except Exception as exc:
            self.log(f"Lỗi client {cn}: {exc}")
        finally:
            with self._lock:
                self._sessions.pop(cn, None)
            try:
                session.close()
            except Exception:
                pass
            self.log(f"{cn} đã ngắt kết nối.")
            self._broadcast_sys(f"{cn} đã rời.", exclude_cn=cn)

    def _dispatch_loop(self, session: Session) -> None:
        """Vòng lặp nhận và điều phối gói tin từ một client."""
        upload: dict | None = None   # {'meta': ..., 'chunks': [...], 'tmp': str}

        while not session.closed:
            pkt = session.recv()
            if pkt is None:
                break

            t       = pkt.get("type", "")
            payload = pkt.get("payload", {})
            cn      = session.peer_cn   # Đây là sender thực sự (từ cert)

            if t == MT_PING:
                session.send(MT_PONG, {}, sender="server")

            elif t == MT_PONG:
                pass   # heartbeat phản hồi, _last_recv đã cập nhật trong recv()

            elif t == MT_DISCONNECT:
                break

            elif t == MT_ROSTER_REQ:
                self._handle_roster_req(session)

            elif t == MT_E2E_MSG:
                self._relay_e2e_msg(session, payload, cn)

            elif t == MT_FILE_E2E_START:
                upload = self._handle_file_start(session, payload, cn)

            elif t == MT_FILE_E2E_CHUNK:
                if upload is not None:
                    upload["chunks"].append({
                        "idx":  payload.get("idx", -1),
                        "data": payload.get("data", ""),
                    })
                    # Kiểm tra kích thước tích luỹ (mỗi chunk hex = ~2× bytes thực)
                    total_bytes = sum(len(c["data"]) // 2 for c in upload["chunks"])
                    if total_bytes > MAX_FILE:
                        self.log(f"File từ {cn} vượt MAX_FILE — huỷ upload.")
                        self._cancel_upload(upload)
                        upload = None
                        session.send(MT_ERROR, {"code": 413, "message": "File vượt giới hạn MAX_FILE"}, sender="server")

            elif t == MT_FILE_E2E_END:
                if upload is not None:
                    self._handle_file_end(session, upload, cn)
                    upload = None
                else:
                    session.send(MT_ERROR, {"code": 400, "message": "Không có upload đang thực hiện"}, sender="server")

            elif t == MT_FILE_LIST_REQ:
                self._handle_file_list(session)

            elif t == MT_FILE_GET_REQ:
                self._handle_file_get(session, payload, cn)

            else:
                self.log(f"Gói không xác định từ {cn}: {t}")

    # ── Roster ─────────────────────────────────────────────────────────────────

    def _handle_roster_req(self, session: Session) -> None:
        """Gửi danh sách các cert đã biết (kể cả offline; cert_pem rỗng nếu chưa lưu)."""
        with self._lock:
            online_set = set(self._sessions.keys())
            roster = []
            for cn, cert_pem in self._known_certs.items():
                roster.append({
                    "cn":       cn,
                    "cert_pem": cert_pem if isinstance(cert_pem, str) else "",
                    "online":   cn in online_set,
                })
        session.send(MT_ROSTER_RESP, {"roster": roster}, sender="server")

    # ── Relay E2E message ──────────────────────────────────────────────────────

    def _relay_e2e_msg(self, session: Session, payload: dict, sender_cn: str) -> None:
        """Chuyển tiếp E2E_MSG đến mọi client khác. Không giải mã."""
        with self._lock:
            targets = [s for cn, s in self._sessions.items() if cn != sender_cn]
        for tgt in targets:
            try:
                tgt.send(MT_E2E_MSG, payload, sender=sender_cn)
            except Exception as exc:
                self.log(f"Lỗi relay E2E_MSG → {tgt.peer_cn}: {exc}")

    # ── File E2E ──────────────────────────────────────────────────────────────

    def _handle_file_start(self, session: Session, payload: dict, cn: str) -> dict | None:
        """Bắt đầu nhận file E2E. Trả về upload-state dict hoặc None nếu lỗi."""
        meta = payload.get("meta") if (isinstance(payload, dict) and "meta" in payload) else payload
        try:
            name = validate_filename(meta.get("name", ""))
        except ValueError as exc:
            session.send(MT_ERROR, {"code": 400, "message": str(exc)}, sender="server")
            return None

        declared_size = meta.get("size", 0)
        if declared_size > MAX_FILE:
            session.send(MT_ERROR, {"code": 413, "message": "Kích thước khai báo vượt MAX_FILE"}, sender="server")
            return None

        tmp_id   = uuid.uuid4().hex
        tmp_path = os.path.join(self.storage_dir, f".tmp_{tmp_id}.json")
        self.log(f"Bắt đầu nhận file '{name}' từ {cn} (tmp={tmp_id[:8]})")
        return {"meta": meta, "chunks": [], "tmp": tmp_path, "name": name, "sender": cn}

    def _handle_file_end(self, session: Session, upload: dict, cn: str) -> None:
        """Hoàn tất upload: kiểm tra chunk count, ghi file tạm, đổi tên sang cuối."""
        meta     = upload["meta"]
        chunks   = upload["chunks"]
        tmp_path = upload["tmp"]
        name     = upload["name"]

        expected_chunks = meta.get("chunks", 0)
        if len(chunks) != expected_chunks:
            self.log(f"File '{name}' từ {cn}: số chunk không khớp ({len(chunks)} ≠ {expected_chunks})")
            self._cancel_upload(upload)
            session.send(MT_ERROR, {
                "code": 400,
                "message": f"Số chunk không khớp: nhận {len(chunks)}, khai báo {expected_chunks}",
            }, sender="server")
            return

        # Ghi tệp tạm trước
        stored = {"meta": meta, "chunks": chunks, "sender": cn}
        try:
            with open(tmp_path, "w", encoding="utf-8") as f:
                json.dump(stored, f, ensure_ascii=False)
        except Exception as exc:
            self.log(f"Lỗi ghi tệp tạm: {exc}")
            self._cancel_upload(upload)
            session.send(MT_ERROR, {"code": 500, "message": "Lỗi ghi file tạm"}, sender="server")
            return

        # Đổi tên sang tên cuối (tránh ghi đè)
        final_name = _unique_name(self.storage_dir, name)
        final_path = os.path.join(self.storage_dir, final_name + ".json")
        try:
            os.replace(tmp_path, final_path)
        except Exception as exc:
            self.log(f"Lỗi os.replace: {exc}")
            self._cancel_upload(upload)
            session.send(MT_ERROR, {"code": 500, "message": "Lỗi lưu file"}, sender="server")
            return

        self.log(f"File '{final_name}' từ {cn} lưu xong.")
        self._broadcast_sys(f"{cn} đã chia sẻ file '{final_name}'. Dùng !getfile để tải.")

    def _cancel_upload(self, upload: dict) -> None:
        """Xoá tệp tạm khi upload thất bại."""
        tmp = upload.get("tmp", "")
        if tmp and os.path.exists(tmp):
            try:
                os.remove(tmp)
            except Exception:
                pass

    # ── File list ─────────────────────────────────────────────────────────────

    def _handle_file_list(self, session: Session) -> None:
        files = []
        try:
            for fname in os.listdir(self.storage_dir):
                if fname.endswith(".json") and not fname.startswith(".tmp_"):
                    fpath = os.path.join(self.storage_dir, fname)
                    try:
                        with open(fpath, "r", encoding="utf-8") as f:
                            data = json.load(f)
                        meta   = data.get("meta", {})
                        sender = data.get("sender", "?")
                        files.append({
                            "name":   meta.get("name", fname),
                            "size":   meta.get("size", 0),
                            "sender": sender,
                        })
                    except Exception:
                        pass
        except Exception as exc:
            self.log(f"Lỗi đọc danh sách file: {exc}")
        session.send(MT_FILE_LIST_RESP, {"files": files}, sender="server")

    # ── File download ──────────────────────────────────────────────────────────

    def _handle_file_get(self, session: Session, payload: dict, cn: str) -> None:
        req_name = payload.get("name", "")
        # Tìm file khớp tên gốc (meta.name)
        found_path = None
        try:
            for fname in os.listdir(self.storage_dir):
                if fname.endswith(".json") and not fname.startswith(".tmp_"):
                    fpath = os.path.join(self.storage_dir, fname)
                    try:
                        with open(fpath, "r", encoding="utf-8") as f:
                            data = json.load(f)
                        if data.get("meta", {}).get("name") == req_name:
                            found_path = fpath
                            break
                    except Exception:
                        pass
        except Exception:
            pass

        if found_path is None:
            session.send(MT_ERROR, {"code": 404, "message": f"File '{req_name}' không tồn tại"}, sender="server")
            return

        try:
            with open(found_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as exc:
            session.send(MT_ERROR, {"code": 500, "message": f"Lỗi đọc file: {exc}"}, sender="server")
            return

        meta   = data.get("meta", {})
        chunks = data.get("chunks", [])
        sender = data.get("sender", "")

        # Gửi START
        session.send(MT_FILE_E2E_START, {"meta": meta}, sender=sender)
        # Gửi từng chunk
        for chunk in chunks:
            session.send(MT_FILE_E2E_CHUNK, chunk, sender=sender)
        # Gửi END
        session.send(MT_FILE_E2E_END, {"chunks": len(chunks)}, sender=sender)
        self.log(f"Đã gửi file '{req_name}' cho {cn}.")

    # ── Broadcast hệ thống ─────────────────────────────────────────────────────

    def _broadcast_sys(self, text: str, exclude_cn: str = "") -> None:
        with self._lock:
            targets = [s for cn, s in self._sessions.items() if cn != exclude_cn]
        for tgt in targets:
            try:
                tgt.send(MT_SYS_MSG, {"text": text}, sender="server")
            except Exception:
                pass


# ─── Entry point ──────────────────────────────────────────────────────────────

def _parse_args():
    p = argparse.ArgumentParser(description="Secure Chat Server")
    p.add_argument("--host",    default="0.0.0.0")
    p.add_argument("--port",    type=int, default=5000)
    p.add_argument("--ca",      default=DEFAULT_CA)
    p.add_argument("--cert",    default=DEFAULT_CERT)
    p.add_argument("--key",     default=DEFAULT_KEY)
    p.add_argument("--storage", default=DEFAULT_STORAGE)
    return p.parse_args()


if __name__ == "__main__":
    args = _parse_args()
    print("=== Secure Chat Server ===")
    print(f"  CA:      {args.ca}")
    print(f"  Cert:    {args.cert}")
    print(f"  Storage: {args.storage}")

    ca_cert     = pki_module.load_cert_from_file(args.ca)
    server_cert = pki_module.load_cert_from_file(args.cert)
    server_key  = pki_module.load_private_key_from_file(args.key)

    srv = SecureChatServer(
        host=args.host,
        port=args.port,
        ca_cert=ca_cert,
        server_cert=server_cert,
        server_key=server_key,
        storage_dir=args.storage,
    )
    srv.start()