"""
ocsp_server.py – OCSP Responder đơn giản dựa trên stdlib HTTP.

Giao thức: HTTP POST /ocsp với body là DER-encoded OCSPRequest.
           HTTP GET  /ocsp/<base64url> (RFC 5019)

Chạy:
    python src/ocsp_server.py
    python src/ocsp_server.py --host 127.0.0.1 --port 8080 --ca pki/ca.crt --key pki/ca.key --db pki/revoked.json

Tích hợp kiểm thử:
    from ocsp_server import OCSPResponder, make_ocsp_response
"""

import argparse
import base64
import datetime
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import ocsp

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pki as pki_module
from crl import load_revoked_db

BASE_DIR     = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_CA   = os.path.join(BASE_DIR, "pki", "ca.crt")
DEFAULT_KEY  = os.path.join(BASE_DIR, "pki", "ca.key")
DEFAULT_DB   = os.path.join(BASE_DIR, "pki", "revoked.json")


# ─── Tạo OCSP Response ────────────────────────────────────────────────────────

def make_ocsp_response(
    ocsp_request: ocsp.OCSPRequest,
    ca_cert: x509.Certificate,
    ca_key,
    revoked_db: list[dict],
) -> bytes:
    """
    Tạo OCSP Response đã ký (DER bytes).

    Trạng thái:
        - GOOD      : Chứng chỉ còn hiệu lực.
        - REVOKED   : Chứng chỉ đã bị thu hồi (có lý do và thời gian).
        - UNKNOWN   : Số serial không được CA này biết đến.

    Args:
        ocsp_request: OCSPRequest đã parse.
        ca_cert:      Chứng chỉ CA (issuer).
        ca_key:       Khóa riêng CA để ký response.
        revoked_db:   Danh sách thu hồi [{serial, revoked_at, reason}, ...].

    Returns:
        DER bytes của OCSPResponse.
    """
    serial_int = ocsp_request.serial_number
    serial_hex = hex(serial_int)

    # Tìm trong DB thu hồi
    revoked_record = None
    for record in revoked_db:
        rec_serial = record.get("serial", "").lower().lstrip("0x") or "0"
        if int(rec_serial, 16) == serial_int:
            revoked_record = record
            break

    now = datetime.datetime.now(datetime.timezone.utc)
    this_update = now
    next_update = now + datetime.timedelta(hours=1)

    builder = ocsp.OCSPResponseBuilder()

    if revoked_record is not None:
        # Cert đã bị thu hồi
        revoked_at_str = revoked_record.get("revoked_at", now.isoformat())
        try:
            revoked_at = datetime.datetime.fromisoformat(revoked_at_str)
            if revoked_at.tzinfo is None:
                revoked_at = revoked_at.replace(tzinfo=datetime.timezone.utc)
        except Exception:
            revoked_at = now

        reason_str = revoked_record.get("reason", "unspecified")
        from crl import REASON_MAP
        reason_flag = REASON_MAP.get(reason_str, x509.ReasonFlags.unspecified)

        builder = builder.add_response(
            cert=_dummy_cert_with_serial(serial_int, ca_cert),
            issuer=ca_cert,
            algorithm=hashes.SHA256(),
            cert_status=ocsp.OCSPCertStatus.REVOKED,
            this_update=this_update,
            next_update=next_update,
            revocation_time=revoked_at,
            revocation_reason=reason_flag,
        ).responder_id(ocsp.OCSPResponderEncoding.HASH, ca_cert)
    else:
        # Cert hợp lệ (GOOD) — CA biết về cert này nhưng không thu hồi
        builder = builder.add_response(
            cert=_dummy_cert_with_serial(serial_int, ca_cert),
            issuer=ca_cert,
            algorithm=hashes.SHA256(),
            cert_status=ocsp.OCSPCertStatus.GOOD,
            this_update=this_update,
            next_update=next_update,
            revocation_time=None,
            revocation_reason=None,
        ).responder_id(ocsp.OCSPResponderEncoding.HASH, ca_cert)

    response = builder.sign(ca_key, hashes.SHA256())
    return response.public_bytes(serialization.Encoding.DER)


_CACHED_DUMMY_KEY = None


def _get_dummy_key() -> rsa.RSAPrivateKey:
    global _CACHED_DUMMY_KEY
    if _CACHED_DUMMY_KEY is None:
        _CACHED_DUMMY_KEY = rsa.generate_private_key(65537, 1024, default_backend())
    return _CACHED_DUMMY_KEY


def _dummy_cert_with_serial(serial_int: int, ca_cert: x509.Certificate) -> x509.Certificate:
    """
    Tạo một dummy Certificate chỉ để truyền serial vào OCSPResponseBuilder.
    (cryptography library yêu cầu cert object; chỉ cần serial và issuer khớp)
    """
    dummy_key = _get_dummy_key()
    now = datetime.datetime.now(datetime.timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(ca_cert.subject)
        .issuer_name(ca_cert.subject)
        .public_key(dummy_key.public_key())
        .serial_number(serial_int)
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(dummy_key, hashes.SHA256(), default_backend())
    )


# ─── OCSP HTTP Handler ────────────────────────────────────────────────────────

class OCSPHandler(BaseHTTPRequestHandler):
    """HTTP handler xử lý OCSP Request theo RFC 6960."""

    # Các thuộc tính này được set bởi OCSPResponder
    ca_cert   = None
    ca_key    = None
    db_path   = None

    def log_message(self, format, *args):
        """Tắt log mặc định để không spam console khi test."""
        pass

    def _load_db(self) -> list[dict]:
        return load_revoked_db(self.db_path or DEFAULT_DB)

    def do_POST(self):
        """Xử lý POST /ocsp với body là DER OCSPRequest."""
        if not self.path.rstrip("/").endswith("/ocsp"):
            self.send_error(404)
            return
        try:
            length = int(self.headers.get("Content-Length", 0))
            body   = self.rfile.read(length)
            ocsp_req = ocsp.load_der_ocsp_request(body)
            resp_der = make_ocsp_response(ocsp_req, self.ca_cert, self.ca_key, self._load_db())
            self.send_response(200)
            self.send_header("Content-Type", "application/ocsp-response")
            self.send_header("Content-Length", str(len(resp_der)))
            self.end_headers()
            self.wfile.write(resp_der)
        except Exception as exc:
            self.send_error(400, str(exc))

    def do_GET(self):
        """Xử lý GET /ocsp/<base64url> theo RFC 5019."""
        path = self.path
        ocsp_prefix = "/ocsp/"
        idx = path.find(ocsp_prefix)
        if idx == -1:
            self.send_error(404)
            return
        try:
            b64 = path[idx + len(ocsp_prefix):]
            # URL-safe base64 → standard base64
            b64 = b64.replace("-", "+").replace("_", "/")
            padding = 4 - len(b64) % 4
            if padding != 4:
                b64 += "=" * padding
            body = base64.b64decode(b64)
            ocsp_req = ocsp.load_der_ocsp_request(body)
            resp_der = make_ocsp_response(ocsp_req, self.ca_cert, self.ca_key, self._load_db())
            self.send_response(200)
            self.send_header("Content-Type", "application/ocsp-response")
            self.send_header("Content-Length", str(len(resp_der)))
            self.end_headers()
            self.wfile.write(resp_der)
        except Exception as exc:
            self.send_error(400, str(exc))


# ─── OCSPResponder (singleton để dùng trong test) ────────────────────────────

class OCSPResponder:
    """
    OCSP Responder chạy trên một thread nền.

    Sử dụng trong test:
        responder = OCSPResponder(ca_cert, ca_key, db_path, port=0)
        responder.start()
        url = responder.url   # ví dụ: "http://127.0.0.1:54321"
        responder.stop()
    """

    def __init__(self, ca_cert, ca_key, db_path: str = DEFAULT_DB, port: int = 8080):
        self.ca_cert  = ca_cert
        self.ca_key   = ca_key
        self.db_path  = db_path
        self._port    = port
        self._server  = None
        self._thread  = None

    @property
    def url(self) -> str:
        if self._server is None:
            return ""
        host, port = self._server.server_address
        return f"http://{host}:{port}"

    def start(self) -> None:
        # Tạo handler class cụ thể với tham chiếu đến ca_cert, ca_key, db
        ca_cert  = self.ca_cert
        ca_key   = self.ca_key
        db_path  = self.db_path

        class _Handler(OCSPHandler):
            pass

        _Handler.ca_cert  = ca_cert
        _Handler.ca_key   = ca_key
        _Handler.db_path  = db_path

        self._server = HTTPServer(("127.0.0.1", self._port), _Handler)
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            daemon=True,
            name="ocsp-responder",
        )
        self._thread.start()

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()
            self._server = None


# ─── Tiện ích client OCSP ─────────────────────────────────────────────────────

def check_ocsp(cert: x509.Certificate, issuer_cert: x509.Certificate, ocsp_url: str) -> str:
    """
    Gọi OCSP server để kiểm tra trạng thái cert.

    Returns:
        "good"    : Cert hợp lệ.
        "revoked" : Cert đã bị thu hồi.
        "unknown" : Không xác định được.

    Raises:
        Exception nếu không kết nối được OCSP server.
    """
    import urllib.request

    builder = ocsp.OCSPRequestBuilder().add_certificate(cert, issuer_cert, hashes.SHA256())
    ocsp_req = builder.build()
    req_der  = ocsp_req.public_bytes(serialization.Encoding.DER)

    req = urllib.request.Request(
        url=ocsp_url.rstrip("/") + "/ocsp",
        data=req_der,
        headers={"Content-Type": "application/ocsp-response"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=5) as resp:
        resp_der = resp.read()

    ocsp_resp = ocsp.load_der_ocsp_response(resp_der)
    status = ocsp_resp.response_status
    if status != ocsp.OCSPResponseStatus.SUCCESSFUL:
        return "unknown"

    cert_status = ocsp_resp.certificate_status
    if cert_status == ocsp.OCSPCertStatus.GOOD:
        return "good"
    elif cert_status == ocsp.OCSPCertStatus.REVOKED:
        return "revoked"
    else:
        return "unknown"


# ─── CLI entry point ──────────────────────────────────────────────────────────

def _parse_args():
    p = argparse.ArgumentParser(description="OCSP Responder nội bộ cho Secure Chat PKI")
    p.add_argument("--host",  default="127.0.0.1")
    p.add_argument("--port",  type=int, default=8080)
    p.add_argument("--ca",   default=DEFAULT_CA)
    p.add_argument("--key",  default=DEFAULT_KEY)
    p.add_argument("--db",   default=DEFAULT_DB)
    return p.parse_args()


if __name__ == "__main__":
    args = _parse_args()
    print(f"=== OCSP Responder ===")
    print(f"  CA  : {args.ca}")
    print(f"  DB  : {args.db}")
    print(f"  URL : http://{args.host}:{args.port}/ocsp")
    print(f"  Dừng: Ctrl+C")

    ca_cert = pki_module.load_cert_from_file(args.ca)
    ca_key  = pki_module.load_private_key_from_file(args.key)

    responder = OCSPResponder(ca_cert, ca_key, args.db, port=args.port)
    responder._server = HTTPServer((args.host, args.port), type(
        "_H", (OCSPHandler,),
        {"ca_cert": ca_cert, "ca_key": ca_key, "db_path": args.db}
    ))
    try:
        print(f"[OCSP] Lắng nghe tại http://{args.host}:{args.port}/ocsp ...")
        responder._server.serve_forever()
    except KeyboardInterrupt:
        print("\n[OCSP] Đã dừng.")

