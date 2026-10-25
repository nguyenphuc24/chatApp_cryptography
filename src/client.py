"""
client.py – Client CLI: handshake, chat E2E, truyền file E2E.

Lệnh:
    <nội dung>              Gửi tin nhắn E2E
    !roster                 Xem danh sách thành viên online
    !sendfile <path>        Upload file E2E
    !listfiles              Xem danh sách file trên server
    !getfile <tên>          Tải file từ server (giải mã E2E)
    exit                    Thoát

Chạy:
    python src/client.py
    python src/client.py --ca pki/ca.crt --cert pki/team1/client.crt --key pki/team1/client.key --mssv 2312345 2312346
"""

import argparse
import json
import os
import sys
import threading
import time
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import handshake as hs
import pki as pki_module
from e2e import (
    e2e_encrypt_msg, e2e_decrypt_msg,
    e2e_prepare_file, e2e_assemble_file,
    validate_filename,
)
from session import (
    Session, sanitize,
    MT_PING, MT_PONG, MT_DISCONNECT, MT_ERROR,
    MT_ROSTER_REQ, MT_ROSTER_RESP,
    MT_E2E_MSG,
    MT_SYS_MSG,
    MT_FILE_E2E_START, MT_FILE_E2E_CHUNK, MT_FILE_E2E_END,
    MT_FILE_LIST_REQ, MT_FILE_LIST_RESP, MT_FILE_GET_REQ,
)

BASE_DIR      = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_CA    = os.path.join(BASE_DIR, "pki", "ca.crt")
DEFAULT_CERT  = os.path.join(BASE_DIR, "pki", "team1", "client.crt")
DEFAULT_KEY   = os.path.join(BASE_DIR, "pki", "team1", "client.key")
DEFAULT_MSSV  = ["2312345", "2312346"]
DOWNLOAD_DIR  = os.path.join(BASE_DIR, "downloads")
STATE_DIR     = os.path.join(BASE_DIR, ".client_state")


class SecureChatClient:

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 5000,
        ca_cert=None,
        client_cert=None,
        client_key=None,
        mssv_list: list[str] = None,
    ):
        self.host        = host
        self.port        = port
        self.ca_cert     = ca_cert
        self.client_cert = client_cert
        self.client_key  = client_key
        self.mssv_list   = mssv_list or []
        self.my_cn       = pki_module.get_cn(client_cert) if client_cert else ""

        self.session: Session | None = None

        # Roster (sau khi lấy về từ server)
        self._roster: dict = {}       # {cn: x509.Certificate}
        self._roster_raw: list = []   # raw list từ server (để hiển thị)

        # Seq E2E và chống replay
        self._e2e_lock     = threading.Lock()
        self._last_msg_seq:  dict[str, int] = {}
        self._last_file_seq: dict[str, int] = {}

        os.makedirs(DOWNLOAD_DIR, exist_ok=True)
        os.makedirs(STATE_DIR, exist_ok=True)
        self._state_file = os.path.join(STATE_DIR, f"{self.my_cn}_state.json") if self.my_cn else None
        self._load_state()

        # Buffer nhận file
        self._recv_file_meta:   dict | None = None
        self._recv_file_chunks: list        = []

    def _load_state(self) -> None:
        """Nạp trạng thái seq và last_seq từ đĩa để chống replay và duy trì seq qua khởi động lại."""
        now_ms = int(time.time() * 1000)
        self._e2e_seq = now_ms
        self._e2e_file_seq = now_ms
        if self._state_file and os.path.exists(self._state_file):
            try:
                with open(self._state_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                saved_msg_seq = data.get("sent_msg_seq", 0)
                saved_file_seq = data.get("sent_file_seq", 0)
                self._e2e_seq = max(saved_msg_seq, now_ms)
                self._e2e_file_seq = max(saved_file_seq, now_ms)
                self._last_msg_seq = data.get("last_msg_seq", {})
                self._last_file_seq = data.get("last_file_seq", {})
            except Exception:
                pass

    def _save_state(self) -> None:
        """Lưu trạng thái seq và last_seq ra đĩa an toàn."""
        if not self._state_file:
            return
        state = {
            "sent_msg_seq": self._e2e_seq,
            "sent_file_seq": self._e2e_file_seq,
            "last_msg_seq": self._last_msg_seq,
            "last_file_seq": self._last_file_seq,
        }
        try:
            tmp = self._state_file + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(state, f, ensure_ascii=False)
            os.replace(tmp, self._state_file)
        except Exception:
            pass

    def log(self, msg: str) -> None:
        ts = datetime.now().strftime("%H:%M:%S")
        safe_msg = sanitize(msg)
        try:
            print(f"\n[{ts}] {safe_msg}\n> ", end="", flush=True)
        except UnicodeEncodeError:
            print(f"\n[{ts}] {safe_msg.encode('ascii', errors='backslashreplace').decode('ascii')}\n> ", end="", flush=True)

    # ── Kết nối và handshake ──────────────────────────────────────────────────

    def connect(self) -> bool:
        import socket
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(60)
            sock.connect((self.host, self.port))
        except Exception as exc:
            print(f"[Lỗi] Không thể kết nối: {exc}")
            return False

        try:
            self.session = hs.client_handshake(
                sock, self.ca_cert, self.client_cert, self.client_key, self.mssv_list
            )
        except Exception as exc:
            print(f"[Lỗi] Handshake thất bại: {exc}")
            try:
                sock.close()
            except Exception:
                pass
            return False

        print(f"\n[✓] Handshake thành công. Kênh EtM đã thiết lập. CN={self.my_cn}")
        return True

    # ── Nhận tin nền ──────────────────────────────────────────────────────────

    def _recv_loop(self) -> None:
        while self.session and not self.session.closed:
            pkt = self.session.recv()
            if pkt is None:
                print("\n[!] Mất kết nối với server.\n> ", end="", flush=True)
                break
            self._handle_packet(pkt)

    def _handle_packet(self, pkt: dict) -> None:
        t       = pkt.get("type", "")
        payload = pkt.get("payload", {})
        sender  = pkt.get("sender", "")   # CN đặt bởi server (tin cậy)

        if t == MT_PING:
            try:
                self.session.send(MT_PONG, {}, sender=self.my_cn)
            except Exception:
                pass

        elif t == MT_PONG:
            pass

        elif t == MT_SYS_MSG:
            text = sanitize(payload.get("text", ""))
            print(f"\n[Server] {text}\n> ", end="", flush=True)

        elif t == MT_ROSTER_RESP:
            self._process_roster(payload.get("roster", []))

        elif t == MT_E2E_MSG:
            self._handle_e2e_msg(payload, sender)

        elif t == MT_FILE_E2E_START:
            self._recv_file_meta   = payload.get("meta", {})
            self._recv_file_meta["_sender"] = sender
            self._recv_file_chunks = []
            fname = sanitize(self._recv_file_meta.get("name", "?"))
            fsize = self._recv_file_meta.get("size", 0)
            print(f"\n[File] Nhận file '{fname}' ({fsize:,} bytes) từ {sanitize(sender)}...\n> ",
                  end="", flush=True)

        elif t == MT_FILE_E2E_CHUNK:
            if self._recv_file_meta is not None:
                self._recv_file_chunks.append({
                    "idx":  payload.get("idx", -1),
                    "data": payload.get("data", ""),
                })

        elif t == MT_FILE_E2E_END:
            if self._recv_file_meta is not None:
                self._finalize_recv_file(sender)
                self._recv_file_meta   = None
                self._recv_file_chunks = []

        elif t == MT_FILE_LIST_RESP:
            files = payload.get("files", [])
            lines = ["\n=== Danh sách file trên server ==="]
            if not files:
                lines.append("  (Chưa có file nào)")
            for item in files:
                name   = sanitize(item.get("name", ""))
                size   = item.get("size", 0)
                sender2 = sanitize(item.get("sender", "?"))
                lines.append(f"  • {name:<30} {size:>10,} bytes  (từ {sender2})")
            lines.append("==================================")
            print("\n".join(lines) + "\n> ", end="", flush=True)

        elif t == MT_ERROR:
            code = payload.get("code", 0)
            msg  = sanitize(payload.get("message", ""))
            print(f"\n[!] Lỗi server [{code}]: {msg}\n> ", end="", flush=True)

    # ── Roster ─────────────────────────────────────────────────────────────────

    def _process_roster(self, roster_list: list) -> None:
        self._roster_raw = roster_list
        self._roster = {}
        for item in roster_list:
            cn       = item.get("cn", "")
            cert_pem = item.get("cert_pem", "")
            if cn and cert_pem:
                try:
                    cert = pki_module.load_cert(cert_pem.encode())
                    pki_module.verify_cert(cert, self.ca_cert)
                    self._roster[cn] = cert
                except Exception:
                    pass   # Cert không hợp lệ → bỏ qua
        lines = ["\n=== Roster ==="]
        for item in roster_list:
            cn     = sanitize(item.get("cn", ""))
            online = "● online" if item.get("online") else "○ offline"
            lines.append(f"  {online}  {cn}")
        lines.append("==============")
        print("\n".join(lines) + "\n> ", end="", flush=True)

    # ── Giải mã E2E chat ───────────────────────────────────────────────────────

    def _handle_e2e_msg(self, payload: dict, sender_cn: str) -> None:
        text = e2e_decrypt_msg(
            payload, sender_cn, self.my_cn, self.client_key,
            self._roster, self._last_msg_seq,
        )
        if text is None:
            self.log(f"[CẢNH BÁO] Tin nhắn E2E từ {sanitize(sender_cn)} bị từ chối (sig/seq/wrap lỗi).")
            return
        print(f"\n[{sanitize(sender_cn)}] {sanitize(text)}\n> ", end="", flush=True)

    # ── Giải mã E2E file ───────────────────────────────────────────────────────

    def _finalize_recv_file(self, sender_from_end: str) -> None:
        meta       = self._recv_file_meta
        chunks     = self._recv_file_chunks
        sender_cn  = meta.get("_sender", sender_from_end)

        # Kiểm tra tên file: validate_filename ném ValueError nếu tên chứa path traversal
        raw_name = meta.get("name", "downloaded_file")
        try:
            filename = validate_filename(sanitize(raw_name))
        except ValueError as exc:
            print(f"\n[!] Từ chối file: tên không hợp lệ ({exc}).\n> ", end="", flush=True)
            return

        file_data = e2e_assemble_file(
            meta, chunks, self.my_cn, self.client_key,
            self._roster, sender_cn, self._last_file_seq,
        )
        if file_data is None:
            print(f"\n[!] File '{filename}' bị từ chối (chữ ký / SHA-256 / chunk không hợp lệ).\n> ",
                  end="", flush=True)
            return

        # Xây dựng đường dẫn lưu và đảm bảo nằm trong DOWNLOAD_DIR
        save_path = os.path.realpath(os.path.join(DOWNLOAD_DIR, filename))
        dl_real   = os.path.realpath(DOWNLOAD_DIR)
        if not save_path.startswith(dl_real + os.sep) and save_path != dl_real:
            print(f"\n[!] Từ chối file: đường dẫn vượt ra ngoài thư mục tải về.\n> ",
                  end="", flush=True)
            return

        # Tránh ghi đè file đã có ở phía client
        if os.path.exists(save_path):
            base, ext = os.path.splitext(filename)
            i = 1
            candidate = save_path
            while os.path.exists(candidate):
                candidate = os.path.join(dl_real, f"{base} ({i}){ext}")
                i += 1
            save_path = candidate

        with open(save_path, "wb") as f:
            f.write(file_data)
        self._save_state()
        print(f"\n[✓] File '{filename}' đã tải về: {save_path}\n> ", end="", flush=True)

    # ── Gửi ───────────────────────────────────────────────────────────────────

    def send_msg(self, message: str) -> None:
        if not self._roster:
            self.log("Roster trống. Dùng !roster để lấy danh sách người nhận.")
            return
        with self._e2e_lock:
            self._e2e_seq += 1
            seq = self._e2e_seq
        # Lấy mọi người trong roster (kể cả bản thân để tự đọc lại)
        recipients = dict(self._roster)
        if self.my_cn not in recipients and self.client_cert:
            recipients[self.my_cn] = self.client_cert
        payload = e2e_encrypt_msg(message, self.my_cn, seq, self.client_key, recipients)
        self.session.send(MT_E2E_MSG, payload, sender=self.my_cn)
        self._save_state()   # Bảo toàn seq sau mỗi lần gửi

    def send_file(self, path: str) -> None:
        if not os.path.exists(path):
            self.log(f"File không tồn tại: {path}")
            return
        if not self._roster:
            self.log("Roster trống. Dùng !roster trước.")
            return
        recipients = dict(self._roster)
        if self.my_cn not in recipients and self.client_cert:
            recipients[self.my_cn] = self.client_cert
        with self._e2e_lock:
            self._e2e_file_seq += 1
            seq = self._e2e_file_seq
        try:
            meta, chunks = e2e_prepare_file(path, self.my_cn, seq, self.client_key, recipients)
        except ValueError as exc:
            self.log(f"Lỗi chuẩn bị file: {exc}")
            return

        self.session.send(MT_FILE_E2E_START, {"meta": meta}, sender=self.my_cn)
        total = len(chunks)
        for i, chunk in enumerate(chunks):
            self.session.send(MT_FILE_E2E_CHUNK, chunk, sender=self.my_cn)
            pct = int((i + 1) / total * 100)
            print(f"\r  Upload: {i+1}/{total} chunks ({pct}%)", end="", flush=True)
        print()
        self.session.send(MT_FILE_E2E_END, {"chunks": total}, sender=self.my_cn)
        self._save_state()   # Bảo toàn file_seq sau mỗi lần gửi
        self.log(f"Đã gửi file '{meta['name']}' ({meta['size']:,} bytes).")

    # ── Vòng lặp chính ────────────────────────────────────────────────────────

    def run(self) -> None:
        if not self.connect():
            return

        # Lấy roster ngay sau khi kết nối
        self.session.send(MT_ROSTER_REQ, {}, sender=self.my_cn)

        # Khởi động heartbeat
        self.session.start_heartbeat()

        # Luồng nhận nền
        t = threading.Thread(target=self._recv_loop, daemon=True, name="recv")
        t.start()

        print()
        print("=" * 56)
        print(" SECURE CHAT CLIENT")
        print(f" CN: {self.my_cn}  |  MSSV: {', '.join(self.mssv_list)}")
        print(" Lệnh: !roster  !sendfile <path>  !listfiles  !getfile <name>  exit")
        print("=" * 56)

        try:
            while self.session and not self.session.closed:
                try:
                    line = input("> ").strip()
                except EOFError:
                    break

                if not line:
                    continue

                if line.lower() == "exit":
                    try:
                        self.session.send(MT_DISCONNECT, {"reason": "user exit"}, sender=self.my_cn)
                    except Exception:
                        pass
                    break

                elif line.lower() == "!roster":
                    self.session.send(MT_ROSTER_REQ, {}, sender=self.my_cn)

                elif line.lower() == "!listfiles":
                    self.session.send(MT_FILE_LIST_REQ, {}, sender=self.my_cn)

                elif line.startswith("!sendfile "):
                    path = line[len("!sendfile "):].strip()
                    self.send_file(path)

                elif line.startswith("!getfile "):
                    name = line[len("!getfile "):].strip()
                    if name:
                        self.session.send(MT_FILE_GET_REQ, {"name": name}, sender=self.my_cn)
                    else:
                        print("Cú pháp: !getfile <tên_file>")

                else:
                    self.send_msg(line)

        except KeyboardInterrupt:
            pass
        finally:
            if self.session:
                self.session.close()
            print("\n[Client] Đã thoát.")


# ─── Entry point ──────────────────────────────────────────────────────────────

def _parse_args():
    p = argparse.ArgumentParser(description="Secure Chat Client")
    p.add_argument("--host",  default="127.0.0.1")
    p.add_argument("--port",  type=int, default=5000)
    p.add_argument("--ca",    default=DEFAULT_CA)
    p.add_argument("--cert",  default=DEFAULT_CERT)
    p.add_argument("--key",   default=DEFAULT_KEY)
    p.add_argument("--mssv",  nargs="+", default=DEFAULT_MSSV)
    return p.parse_args()


if __name__ == "__main__":
    args = _parse_args()
    ca_cert     = pki_module.load_cert_from_file(args.ca)
    client_cert = pki_module.load_cert_from_file(args.cert)
    client_key  = pki_module.load_private_key_from_file(args.key)

    cli = SecureChatClient(
        host=args.host,
        port=args.port,
        ca_cert=ca_cert,
        client_cert=client_cert,
        client_key=client_key,
        mssv_list=args.mssv,
    )
    cli.run()
