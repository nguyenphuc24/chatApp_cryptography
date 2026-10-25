"""
e2e.py – Mã hoá đầu cuối (E2E) cho chat và truyền file.

=== Chat E2E ===
    e2e_encrypt_msg(message, my_cn, seq, my_priv_key, recipients) -> payload dict
    e2e_decrypt_msg(payload, sender_cn, my_cn, my_priv_key, roster, last_seq) -> str | None

=== File E2E ===
    e2e_prepare_file(path, my_cn, seq, my_priv_key, recipients) -> (meta, chunks)
    e2e_assemble_file(meta, chunks, my_cn, my_priv_key, roster, sender_cn, last_file_seq) -> bytes | None

=== Kiểm tra tên file ===
    validate_filename(name) -> str  (hoặc ném ValueError)

Hằng số:
    MAX_FILE  = 10 MiB
    CHUNK_SIZE = 4 KiB

Thiết kế:
    - K ngẫu nhiên 32 bytes → k_aes=SHA256(K||"enc"), k_hmac=SHA256(K||"mac")
    - ciphertext = EtM(message, k_aes, k_hmac)
    - wraps[cn]  = RSA-OAEP(K, pub_r).hex()
    - sig = RSA-PSS(priv, SHA256(enc(cn)||enc(seq)||enc(ciphertext)||enc_map(wraps)))
    - Server chuyển tiếp E2E_MSG nguyên vẹn — không giải mã được vì không có K.
"""

import hashlib
import os
import re
import struct

from cryptography.exceptions import InvalidSignature

import pki as pki_module
from crypto_utils import (
    encrypt_then_MAC, verify_then_decrypt,
    rsa_encrypt, rsa_decrypt,
    rsa_pss_sign, rsa_pss_verify,
    enc, enc_list, enc_map,
    sha256_hex,
)

# ─── Hằng số ──────────────────────────────────────────────────────────────────

MAX_FILE:   int = 10 * 1024 * 1024   # 10 MiB
CHUNK_SIZE: int = 4 * 1024           # 4 KiB

_VALID_FNAME_RE = re.compile(r"^[A-Za-z0-9._\-]{1,100}$")


# ─── Kiểm tra tên file ────────────────────────────────────────────────────────

def validate_filename(name: str) -> str:
    """
    Kiểm tra tên file hợp lệ: [A-Za-z0-9._-], ≤100 ký tự, không bắt đầu bằng '.'.
    Trả về name nếu hợp lệ, ném ValueError nếu không.
    """
    if not name or not _VALID_FNAME_RE.match(name):
        raise ValueError(f"Tên file không hợp lệ: {name!r}")
    if name.startswith("."):
        raise ValueError(f"Tên file không được bắt đầu bằng '.': {name!r}")
    return name


# ─── Khoá E2E ─────────────────────────────────────────────────────────────────

def _e2e_subkeys(K: bytes) -> tuple[bytes, bytes]:
    """Từ ephemeral key K (32B), dẫn xuất k_aes và k_hmac cho EtM."""
    k_aes  = hashlib.sha256(K + b"enc").digest()
    k_hmac = hashlib.sha256(K + b"mac").digest()
    return k_aes, k_hmac


# ─── Chữ ký E2E (Chat) ────────────────────────────────────────────────────────

def _msg_transcript(
    sender_cn: str, seq: int, ciphertext: bytes, wraps: dict[str, str]
) -> bytes:
    """
    SHA256( enc(cn) || enc(seq_bytes) || enc(ciphertext) || enc_map(wraps) )
    """
    seq_bytes = seq.to_bytes(8, "big")
    return hashlib.sha256(
        enc(sender_cn.encode()) +
        enc(seq_bytes) +
        enc(ciphertext) +
        enc_map(wraps)
    ).digest()


# ─── Chat E2E ─────────────────────────────────────────────────────────────────

def e2e_encrypt_msg(
    message: str,
    my_cn: str,
    seq: int,
    my_priv_key,
    recipients: dict,   # {cn: x509.Certificate}
) -> dict:
    """
    Mã hoá tin nhắn E2E cho nhiều người nhận (kể cả bản thân).
    Trả về payload dict để gửi trong gói E2E_MSG.
    """
    K             = os.urandom(32)
    k_aes, k_hmac = _e2e_subkeys(K)
    ciphertext    = encrypt_then_MAC(message.encode(), k_aes, k_hmac)

    wraps: dict[str, str] = {}
    for cn, cert in recipients.items():
        wraps[cn] = rsa_encrypt(K, cert.public_key()).hex()

    T   = _msg_transcript(my_cn, seq, ciphertext, wraps)
    sig = rsa_pss_sign(my_priv_key, T)

    return {
        "seq":        seq,
        "ciphertext": ciphertext.hex(),
        "wraps":      wraps,
        "sig":        sig.hex(),
    }


def e2e_decrypt_msg(
    payload: dict,
    sender_cn: str,
    my_cn: str,
    my_priv_key,
    roster: dict,        # {cn: x509.Certificate}
    last_seq: dict,      # {sender_cn: last seen seq}, mutable
) -> str | None:
    """
    Xác thực và giải mã tin nhắn E2E. Trả về chuỗi hoặc None nếu thất bại.
    Cập nhật last_seq[sender_cn] sau khi xác thực thành công.
    """
    seq        = payload.get("seq", 0)
    ciphertext = bytes.fromhex(payload.get("ciphertext", ""))
    wraps      = payload.get("wraps", {})
    sig        = bytes.fromhex(payload.get("sig", ""))

    # 1. Tìm cert người gửi trong roster đã xác minh
    sender_cert = roster.get(sender_cn)
    if sender_cert is None:
        return None

    # 2. Xác minh chữ ký
    T = _msg_transcript(sender_cn, seq, ciphertext, wraps)
    try:
        rsa_pss_verify(sender_cert.public_key(), T, sig)
    except (InvalidSignature, Exception):
        return None

    # 3. Chống replay E2E (seq phải tăng dần)
    if seq <= last_seq.get(sender_cn, 0):
        return None
    last_seq[sender_cn] = seq

    # 4. Lấy wrap của bản thân
    my_wrap_hex = wraps.get(my_cn)
    if my_wrap_hex is None:
        return None   # Tin không dành cho mình
    try:
        K = rsa_decrypt(bytes.fromhex(my_wrap_hex), my_priv_key)
    except Exception:
        return None

    # 5. Giải mã EtM
    k_aes, k_hmac = _e2e_subkeys(K)
    plaintext = verify_then_decrypt(ciphertext, k_aes, k_hmac)
    if plaintext is None:
        return None

    return plaintext.decode()


# ─── File E2E ─────────────────────────────────────────────────────────────────

def _file_transcript(
    sender_cn: str, seq: int, name: str, sha256_bytes: bytes, wraps: dict[str, str]
) -> bytes:
    """
    SHA256( enc(cn) || enc(seq_bytes) || enc(name) || enc(sha256_bytes) || enc_map(wraps) )
    """
    seq_bytes = seq.to_bytes(8, "big")
    return hashlib.sha256(
        enc(sender_cn.encode()) +
        enc(seq_bytes) +
        enc(name.encode()) +
        enc(sha256_bytes) +
        enc_map(wraps)
    ).digest()


def e2e_prepare_file(
    path: str,
    my_cn: str,
    seq: int,
    my_priv_key,
    recipients: dict,    # {cn: x509.Certificate}
) -> tuple[dict, list[dict]]:
    """
    Chuẩn bị file để gửi E2E. Trả về (meta_dict, list_of_chunk_dicts).
    meta_dict chứa wraps và sig; chunks là list [{idx, data_hex}].
    Ném ValueError nếu file > MAX_FILE hoặc tên không hợp lệ.
    """
    with open(path, "rb") as f:
        file_data = f.read()

    if len(file_data) > MAX_FILE:
        raise ValueError(
            f"File vượt giới hạn MAX_FILE={MAX_FILE} bytes: {len(file_data)} bytes"
        )

    filename = validate_filename(os.path.basename(path))
    file_sha  = sha256_hex(file_data)
    total_chunks = (len(file_data) + CHUNK_SIZE - 1) // CHUNK_SIZE or 1

    # Sinh khoá ephemeral E2E
    K             = os.urandom(32)
    k_aes, k_hmac = _e2e_subkeys(K)

    # Mã hoá từng chunk (đưa idx 4B vào dữ liệu trước khi EtM để xác thực thứ tự trong MAC)
    chunks: list[dict] = []
    for i, offset in enumerate(range(0, len(file_data), CHUNK_SIZE)):
        chunk         = file_data[offset: offset + CHUNK_SIZE]
        chunk_payload = struct.pack("!I", i) + chunk
        enc_chunk     = encrypt_then_MAC(chunk_payload, k_aes, k_hmac)
        chunks.append({"idx": i, "data": enc_chunk.hex()})

    # Wraps cho mỗi người nhận
    wraps: dict[str, str] = {}
    for cn, cert in recipients.items():
        wraps[cn] = rsa_encrypt(K, cert.public_key()).hex()

    # Ký metadata
    sha256_bytes = bytes.fromhex(file_sha)
    T   = _file_transcript(my_cn, seq, filename, sha256_bytes, wraps)
    sig = rsa_pss_sign(my_priv_key, T)

    meta = {
        "name":   filename,
        "size":   len(file_data),
        "sha256": file_sha,
        "chunks": total_chunks,
        "seq":    seq,
        "wraps":  wraps,
        "sig":    sig.hex(),
        "sender": my_cn,
    }
    return meta, chunks


def e2e_assemble_file(
    meta: dict,
    chunks: list[dict],
    my_cn: str,
    my_priv_key,
    roster: dict,        # {cn: x509.Certificate}
    sender_cn: str,
    last_file_seq: dict, # {sender_cn: last seen seq}, mutable
) -> bytes | None:
    """
    Kiểm tra chữ ký và giải mã file E2E. Trả về bytes nội dung hoặc None.
    Cập nhật last_file_seq[sender_cn] nếu thành công.
    """
    seq          = meta.get("seq", 0)
    wraps        = meta.get("wraps", {})
    sig          = bytes.fromhex(meta.get("sig", ""))
    filename     = meta.get("name", "")
    sha256_expected = meta.get("sha256", "")

    # Kiểm tra tên file hợp lệ (chống path traversal ở tầng E2E)
    try:
        validate_filename(filename)
    except ValueError:
        return None

    # 1. Cert người gửi
    sender_cert = roster.get(sender_cn)
    if sender_cert is None:
        return None

    # 2. Xác minh chữ ký metadata
    sha256_bytes = bytes.fromhex(sha256_expected)
    T = _file_transcript(sender_cn, seq, filename, sha256_bytes, wraps)
    try:
        rsa_pss_verify(sender_cert.public_key(), T, sig)
    except (InvalidSignature, Exception):
        return None

    # 3. Chống replay E2E file
    if seq <= last_file_seq.get(sender_cn, 0):
        return None
    last_file_seq[sender_cn] = seq

    # 4. Giải mã wrap → K
    my_wrap_hex = wraps.get(my_cn)
    if my_wrap_hex is None:
        return None
    try:
        K = rsa_decrypt(bytes.fromhex(my_wrap_hex), my_priv_key)
    except Exception:
        return None
    k_aes, k_hmac = _e2e_subkeys(K)

    # 5. Kiểm tra số chunk và thứ tự
    expected_count = meta.get("chunks", 0)
    sorted_chunks  = sorted(chunks, key=lambda c: c["idx"])
    if len(sorted_chunks) != expected_count:
        return None

    # 6. Giải mã từng chunk
    parts: list[bytes] = []
    for expected_idx, chunk_dict in enumerate(sorted_chunks):
        if chunk_dict.get("idx") != expected_idx:
            return None  # Thứ tự chunk khai báo sai
        c_bytes = bytes.fromhex(chunk_dict.get("data", ""))
        plain   = verify_then_decrypt(c_bytes, k_aes, k_hmac)
        if plain is None or len(plain) < 4:
            return None  # HMAC chunk sai hoặc dữ liệu hỏng
        dec_idx = struct.unpack("!I", plain[:4])[0]
        if dec_idx != expected_idx:
            return None  # Chỉ số chunk xác thực trong MAC không khớp
        parts.append(plain[4:])

    file_data = b"".join(parts)

    # 7. Kiểm tra SHA-256 toàn vẹn
    if sha256_hex(file_data) != sha256_expected:
        return None  # Nội dung bị hỏng

    return file_data
