"""
handshake.py – Giao thức handshake phía client và server.

Luồng:
    S → C  HELLO  { server_cert: PEM, server_nonce: hex16 }           [plaintext]
    C → S  INIT   { encrypted_ms: hex, body: hex(EtM(body_json)) }    [plaintext]
    S → C  OK     { status: HANDSHAKE_OK }                            [EtM, khoá phiên]
    C → S  ACK    { status: OK }                                       [EtM, khoá phiên]

Tính chất bảo mật:
    - Chống MitM: client kiểm tra server_cert (CA ký, CN=chat-server).
    - Chống mạo danh: server kiểm tra client_cert (CA ký) + chữ ký RSA-PSS trên transcript T.
    - MSSV không lộ: nằm trong body đã mã hoá bằng khoá tạm K_init.
    - Replay handshake: nonce ngẫu nhiên của server nằm trong T.
    - Xác thực khoá: HANDSHAKE_OK và ACK mã hoá bằng khoá phiên → key confirmation.

API:
    client_handshake(sock, ca_cert, client_cert, client_key, mssv_list) -> Session
    server_handshake(sock, ca_cert, server_cert, server_key) -> Session
    Cả hai ném ValueError hoặc cryptography.exceptions.InvalidSignature nếu thất bại.
"""

import hashlib
import json
import secrets
import time

from cryptography import x509
from cryptography.exceptions import InvalidSignature

import framing
import pki as pki_module
from crypto_utils import (
    enc, enc_list,
    rsa_encrypt, rsa_decrypt,
    rsa_pss_sign, rsa_pss_verify,
    encrypt_then_MAC, verify_then_decrypt,
    kdf_session_key, kdf_keys, kdf_init_keys,
)
from session import Session, MT_HELLO, MT_INIT, MT_OK, MT_ACK

SERVER_CN = "chat-server"


# ─── Helpers plaintext ────────────────────────────────────────────────────────

def _send_plain(sock, msg_type: str, payload: dict) -> None:
    """Gửi gói tin plaintext (dùng cho HELLO và INIT — trước khi có khoá phiên)."""
    pkt = {"type": msg_type, "payload": payload, "timestamp": time.time()}
    framing.send_frame(sock, json.dumps(pkt, ensure_ascii=False).encode())


def _recv_plain(sock) -> dict | None:
    """Nhận gói tin plaintext."""
    frame = framing.recv_frame(sock)
    if frame is None:
        return None
    try:
        return json.loads(frame.decode())
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None


# ─── Transcript T ────────────────────────────────────────────────────────────

def _build_transcript(
    server_cert_der: bytes,
    nonce_bytes: bytes,
    enc_ms: bytes,
    mssv_list: list[str],
    client_cert_der: bytes,
) -> bytes:
    """
    T = SHA256( enc(server_cert_der) || enc(nonce_bytes) || enc(enc_ms)
                || enc_list(mssv_list) || enc(client_cert_der) )
    Cả hai bên tính T giống nhau → chữ ký ràng buộc tất cả tham số handshake.
    """
    return hashlib.sha256(
        enc(server_cert_der) +
        enc(nonce_bytes) +
        enc(enc_ms) +
        enc_list(mssv_list) +
        enc(client_cert_der)
    ).digest()


# ─── Client side ──────────────────────────────────────────────────────────────

def client_handshake(
    sock,
    ca_cert: x509.Certificate,
    client_cert: x509.Certificate,
    client_key,
    mssv_list: list[str],
) -> Session:
    """
    Thực hiện handshake phía client.
    Trả về Session sẵn sàng hoặc ném exception nếu thất bại.
    """

    # ── B1: Nhận HELLO từ server ──────────────────────────────────────────────
    hello = _recv_plain(sock)
    if hello is None or hello.get("type") != MT_HELLO:
        raise ValueError("Không nhận được HELLO từ server")

    payload          = hello.get("payload", {})
    server_cert_pem  = payload.get("server_cert", "")
    server_nonce_hex = payload.get("server_nonce", "")
    nonce_bytes      = bytes.fromhex(server_nonce_hex)

    # ── B2: Kiểm tra chứng chỉ server ────────────────────────────────────────
    server_cert = pki_module.load_cert(server_cert_pem.encode())
    pki_module.verify_cert(server_cert, ca_cert, expected_cn=SERVER_CN)
    server_pub  = server_cert.public_key()

    # ── B3: Sinh MS và mã hoá bằng khoá công khai server ────────────────────
    master_secret = secrets.token_bytes(32)
    enc_ms        = rsa_encrypt(master_secret, server_pub)

    # ── B4: Khoá tạm cho body ─────────────────────────────────────────────────
    k_init_aes, k_init_hmac = kdf_init_keys(master_secret)

    # ── B5: Tính transcript T và ký ──────────────────────────────────────────
    server_cert_der = pki_module.cert_to_der(server_cert)
    client_cert_der = pki_module.cert_to_der(client_cert)
    T   = _build_transcript(server_cert_der, nonce_bytes, enc_ms, mssv_list, client_cert_der)
    sig = rsa_pss_sign(client_key, T)

    # ── B6: Mã hoá body ───────────────────────────────────────────────────────
    mssv_str = ", ".join(mssv_list)
    body = {
        "message":     f"Hello, We are {mssv_str}",
        "mssv_list":   mssv_list,
        "client_cert": pki_module.cert_to_pem(client_cert),
        "signature":   sig.hex(),
    }
    body_frame = encrypt_then_MAC(
        json.dumps(body, ensure_ascii=False).encode(),
        k_init_aes, k_init_hmac,
    )

    # ── B7: Gửi INIT ──────────────────────────────────────────────────────────
    _send_plain(sock, MT_INIT, {
        "encrypted_ms": enc_ms.hex(),
        "body":         body_frame.hex(),
    })

    # ── B8: Dẫn xuất khoá phiên ───────────────────────────────────────────────
    session_key      = kdf_session_key(master_secret, mssv_list, nonce_bytes)
    key_aes, key_hmac = kdf_keys(session_key)

    # ── B9: Nhận OK (đã mã hoá bằng khoá phiên) ─────────────────────────────
    ok_frame = framing.recv_frame(sock)
    if ok_frame is None:
        raise ValueError("Không nhận được HANDSHAKE_OK")
    ok_raw = verify_then_decrypt(ok_frame, key_aes, key_hmac)
    if ok_raw is None:
        raise ValueError("HMAC của HANDSHAKE_OK sai (sai khoá phiên hoặc giả mạo)")
    ok_pkt = json.loads(ok_raw.decode())
    if ok_pkt.get("payload", {}).get("status") != "HANDSHAKE_OK":
        raise ValueError(f"HANDSHAKE_OK không hợp lệ: {ok_pkt}")

    # ── B10: Gửi ACK (đã mã hoá bằng khoá phiên) ────────────────────────────
    ack_raw   = json.dumps({
        "type": MT_ACK, "payload": {"status": "OK"},
        "seq": 0, "sender": "", "timestamp": time.time(),
    }, ensure_ascii=False).encode()
    ack_frame = encrypt_then_MAC(ack_raw, key_aes, key_hmac)
    framing.send_frame(sock, ack_frame)

    peer_cn = pki_module.get_cn(server_cert)
    return Session(sock, key_aes, key_hmac, peer_cn=peer_cn, peer_cert_pem=server_cert_pem)


# ─── Server side ──────────────────────────────────────────────────────────────

def server_handshake(
    sock,
    ca_cert: x509.Certificate,
    server_cert: x509.Certificate,
    server_key,
) -> Session:
    """
    Thực hiện handshake phía server.
    Trả về Session (peer_cn = CN của nhóm) hoặc ném exception nếu thất bại.
    """

    # ── B1: Gửi HELLO ─────────────────────────────────────────────────────────
    nonce_hex   = secrets.token_hex(16)
    nonce_bytes = bytes.fromhex(nonce_hex)
    _send_plain(sock, MT_HELLO, {
        "server_cert":  pki_module.cert_to_pem(server_cert),
        "server_nonce": nonce_hex,
    })

    # ── B2: Nhận INIT ─────────────────────────────────────────────────────────
    init = _recv_plain(sock)
    if init is None or init.get("type") != MT_INIT:
        raise ValueError("Không nhận được HANDSHAKE_INIT")

    pl = init.get("payload", {})
    enc_ms_bytes   = bytes.fromhex(pl.get("encrypted_ms", ""))
    encrypted_body = bytes.fromhex(pl.get("body", ""))

    # ── B3: Giải mã MS ────────────────────────────────────────────────────────
    try:
        master_secret = rsa_decrypt(enc_ms_bytes, server_key)
    except Exception as exc:
        raise ValueError(f"Giải mã master_secret thất bại: {exc}") from exc
    k_init_aes, k_init_hmac = kdf_init_keys(master_secret)

    # ── B4: Giải mã và xác thực body ─────────────────────────────────────────
    body_raw = verify_then_decrypt(encrypted_body, k_init_aes, k_init_hmac)
    if body_raw is None:
        raise ValueError("HMAC body HANDSHAKE_INIT sai — gói bị giả mạo hoặc khoá sai")
    body = json.loads(body_raw.decode())

    mssv_list       = body.get("mssv_list", [])
    client_cert_pem = body.get("client_cert", "")
    sig_bytes       = bytes.fromhex(body.get("signature", ""))

    # ── B5: Kiểm tra chứng chỉ client ────────────────────────────────────────
    client_cert = pki_module.load_cert(client_cert_pem.encode())
    pki_module.verify_cert(client_cert, ca_cert)  # CA ký, còn hạn, không phải CA

    # UID trong cert phải khớp mssv_list (đúng thứ tự)
    cert_uids = pki_module.get_uids(client_cert)
    if cert_uids != mssv_list:
        raise ValueError(
            f"UID trong cert {cert_uids} không khớp MSSV khai báo {mssv_list}"
        )

    # ── B6: Xác minh chữ ký trên transcript T ────────────────────────────────
    server_cert_der = pki_module.cert_to_der(server_cert)
    client_cert_der = pki_module.cert_to_der(client_cert)
    T = _build_transcript(
        server_cert_der, nonce_bytes, enc_ms_bytes, mssv_list, client_cert_der
    )
    try:
        rsa_pss_verify(client_cert.public_key(), T, sig_bytes)
    except InvalidSignature as exc:
        raise ValueError("Chữ ký HANDSHAKE_INIT không hợp lệ") from exc

    # ── B7: Dẫn xuất khoá phiên ───────────────────────────────────────────────
    session_key       = kdf_session_key(master_secret, mssv_list, nonce_bytes)
    key_aes, key_hmac = kdf_keys(session_key)

    # ── B8: Gửi OK (đã mã hoá bằng khoá phiên) ──────────────────────────────
    ok_raw   = json.dumps({
        "type": MT_OK, "payload": {"status": "HANDSHAKE_OK"},
        "seq": 0, "sender": "server", "timestamp": time.time(),
    }, ensure_ascii=False).encode()
    ok_frame = encrypt_then_MAC(ok_raw, key_aes, key_hmac)
    framing.send_frame(sock, ok_frame)

    # ── B9: Nhận ACK ──────────────────────────────────────────────────────────
    ack_frame = framing.recv_frame(sock)
    if ack_frame is None:
        raise ValueError("Không nhận được ACK")
    ack_raw = verify_then_decrypt(ack_frame, key_aes, key_hmac)
    if ack_raw is None:
        raise ValueError("HMAC của ACK sai")
    ack_pkt = json.loads(ack_raw.decode())
    if ack_pkt.get("type") != MT_ACK:
        raise ValueError(f"ACK không hợp lệ: {ack_pkt.get('type')}")

    peer_cn = pki_module.get_cn(client_cert)
    return Session(sock, key_aes, key_hmac, peer_cn=peer_cn, peer_cert_pem=client_cert_pem)
