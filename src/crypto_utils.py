"""
crypto_utils.py – Mật mã: RSA-OAEP, RSA-PSS, AES-256-CBC, EtM, SHA-256, KDF.

=== Encoding không nhập nhằng ===
    enc(x: bytes) -> bytes              # 4-byte len || x
    enc_str(s: str) -> bytes
    enc_list(items: list[str]) -> bytes # 4-byte count || enc(item_0) || ...
    enc_map(d: dict[str, str]) -> bytes # sorted by key; value: hex string → bytes

=== KDF ===
    kdf_session_key(MS, mssv_list, nonce_bytes) -> bytes
        SHA256(MS || enc_list(mssv_list) || enc(nonce_bytes))
        Đảm bảo ["23","12"] ≠ ["2312"] (test_kdf.py).
    kdf_keys(session_key) -> (key_aes, key_hmac)
    kdf_init_keys(MS) -> (K_init_aes, K_init_hmac)

=== RSA ===
    rsa_encrypt(data, pub) -> bytes     (RSA-OAEP-SHA256)
    rsa_decrypt(ct, priv) -> bytes
    rsa_pss_sign(priv, msg) -> bytes    (RSA-PSS-SHA256)
    rsa_pss_verify(pub, msg, sig)       ném InvalidSignature nếu sai

=== AES-256-CBC ===
    aes_encrypt(data, key, iv=None) -> (ciphertext, iv)
    aes_decrypt(ciphertext, key, iv) -> plaintext

=== Encrypt-then-MAC ===
    encrypt_then_MAC(plaintext, key_aes, key_hmac) -> frame (IV||C||T)
    verify_then_decrypt(frame, key_aes, key_hmac) -> plaintext | None

=== SHA-256 & utils ===
    sha256_hash, sha256_hex
    bytes_to_hex, hex_to_bytes
"""

import hashlib
import hmac as _hmac
import os
import struct
from typing import Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding, rsa

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


# ─── Encoding không nhập nhằng ────────────────────────────────────────────────

def enc(x: bytes) -> bytes:
    """4-byte big-endian length || x. Đảm bảo ranh giới không nhập nhằng."""
    return struct.pack("!I", len(x)) + x


def enc_str(s: str) -> bytes:
    """enc(s.encode('utf-8'))."""
    return enc(s.encode())


def enc_list(items: list[str]) -> bytes:
    """
    4-byte count || enc(item_0) || enc(item_1) || ...
    Đảm bảo enc_list(["23","12"]) ≠ enc_list(["2312"]).
    """
    result = struct.pack("!I", len(items))
    for item in items:
        result += enc(item.encode())
    return result


def enc_map(d: dict[str, str]) -> bytes:
    """
    Mã hoá dict theo thứ tự key đã sắp xếp.
    Value phải là chuỗi hex (sẽ được chuyển sang bytes trước khi enc).
    Format: 4-byte count || (enc(key) || enc(val_bytes)) × n
    """
    keys = sorted(d.keys())
    result = struct.pack("!I", len(keys))
    for k in keys:
        v = d[k]
        v_bytes = bytes.fromhex(v) if isinstance(v, str) else v
        result += enc(k.encode()) + enc(v_bytes)
    return result


# ─── KDF ──────────────────────────────────────────────────────────────────────

def kdf_session_key(
    master_secret: bytes,
    mssv_list: list[str],
    nonce_bytes: bytes,
) -> bytes:
    """
    Dẫn xuất khoá phiên theo công thức của đề:
        SHA256(MS || enc_list(mssv_list) || enc(nonce_bytes))
    enc_list đảm bảo không nhập nhằng cú pháp.
    """
    return hashlib.sha256(
        master_secret + enc_list(mssv_list) + enc(nonce_bytes)
    ).digest()


def kdf_keys(session_key: bytes) -> Tuple[bytes, bytes]:
    """Tách khoá AES-256 và HMAC-SHA256 từ session key."""
    key_aes  = hashlib.sha256(session_key + b":encryption").digest()
    key_hmac = hashlib.sha256(session_key + b":authentication").digest()
    return key_aes, key_hmac


def kdf_init_keys(master_secret: bytes) -> Tuple[bytes, bytes]:
    """Khoá tạm để mã hoá body HANDSHAKE_INIT (không liên quan session key)."""
    k_init_aes  = hashlib.sha256(master_secret + b"init-enc").digest()
    k_init_hmac = hashlib.sha256(master_secret + b"init-mac").digest()
    return k_init_aes, k_init_hmac


# ─── RSA-OAEP (bọc khoá đối xứng) ────────────────────────────────────────────

def rsa_encrypt(data: bytes, public_key) -> bytes:
    """Mã hoá bằng RSA-OAEP-SHA256 (dùng để bọc master_secret hoặc K E2E)."""
    return public_key.encrypt(
        data,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def rsa_decrypt(ciphertext: bytes, private_key) -> bytes:
    """Giải mã RSA-OAEP-SHA256."""
    return private_key.decrypt(
        ciphertext,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


# ─── RSA-PSS (chữ ký số) ──────────────────────────────────────────────────────

def rsa_pss_sign(private_key, message: bytes) -> bytes:
    """
    Ký bằng RSA-PSS-SHA256. message là dữ liệu gốc (SHA256 tính bên trong sign).
    Dùng DIGEST_LENGTH làm salt length để xác định.
    """
    return private_key.sign(
        message,
        asym_padding.PSS(
            mgf=asym_padding.MGF1(hashes.SHA256()),
            salt_length=asym_padding.PSS.DIGEST_LENGTH,
        ),
        hashes.SHA256(),
    )


def rsa_pss_verify(public_key, message: bytes, signature: bytes) -> None:
    """
    Xác minh chữ ký RSA-PSS-SHA256.
    Ném cryptography.exceptions.InvalidSignature nếu không hợp lệ.
    """
    public_key.verify(
        signature,
        message,
        asym_padding.PSS(
            mgf=asym_padding.MGF1(hashes.SHA256()),
            salt_length=asym_padding.PSS.DIGEST_LENGTH,
        ),
        hashes.SHA256(),
    )


# ─── AES-256-CBC ──────────────────────────────────────────────────────────────

def aes_encrypt(data: bytes, key: bytes, iv: bytes | None = None) -> Tuple[bytes, bytes]:
    """
    AES-256-CBC encrypt với PKCS#7 padding.
    Trả về (ciphertext, iv). iv sinh ngẫu nhiên nếu không truyền.
    """
    if len(key) != 32:
        raise ValueError(f"AES key phải 32 bytes, nhận {len(key)}")
    if iv is None:
        iv = os.urandom(16)
    elif len(iv) != 16:
        raise ValueError("IV phải 16 bytes")
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(data, AES.block_size, style="pkcs7")), iv


def aes_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    """AES-256-CBC decrypt và bỏ PKCS#7 padding."""
    if len(key) != 32:
        raise ValueError(f"AES key phải 32 bytes, nhận {len(key)}")
    if len(iv) != 16:
        raise ValueError("IV phải 16 bytes")
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), AES.block_size, style="pkcs7")


# ─── HMAC-SHA256 ──────────────────────────────────────────────────────────────

def hmac_sign(data: bytes, key: bytes) -> bytes:
    return _hmac.new(key, data, hashlib.sha256).digest()


def hmac_verify(data: bytes, signature: bytes, key: bytes) -> bool:
    expected = hmac_sign(data, key)
    return _hmac.compare_digest(signature, expected)


# ─── Encrypt-then-MAC ─────────────────────────────────────────────────────────
# Wire format: [ IV (16B) ] [ Ciphertext (NB) ] [ HMAC-SHA256 Tag (32B) ]
# Bên nhận kiểm tra HMAC TRƯỚC, rồi mới giải mã → tránh padding oracle.

def encrypt_then_MAC(plaintext: bytes, key_aes: bytes, key_hmac: bytes) -> bytes:
    """Mã hoá và xác thực: trả về IV || C || HMAC(IV||C)."""
    ciphertext, iv = aes_encrypt(plaintext, key_aes)
    body = iv + ciphertext
    tag  = hmac_sign(body, key_hmac)
    return body + tag


def verify_then_decrypt(payload: bytes, key_aes: bytes, key_hmac: bytes) -> bytes | None:
    """
    Kiểm tra HMAC trước (compare_digest), rồi giải mã.
    Trả về plaintext hoặc None nếu HMAC sai / giải mã lỗi.
    Tối thiểu: IV(16) + block AES(16) + HMAC(32) = 64 bytes.
    """
    if len(payload) < 64:
        return None
    body = payload[:-32]
    tag  = payload[-32:]
    if not hmac_verify(body, tag, key_hmac):
        return None
    iv         = body[:16]
    ciphertext = body[16:]
    try:
        return aes_decrypt(ciphertext, key_aes, iv)
    except Exception:
        return None


# ─── SHA-256 ──────────────────────────────────────────────────────────────────

def sha256_hash(data: bytes) -> bytes:
    """Băm SHA-256 trả về 32 bytes nhị phân."""
    return hashlib.sha256(data).digest()


def sha256_hex(data: bytes) -> str:
    """Băm SHA-256 trả về 64 ký tự hex (dùng làm checksum file)."""
    return hashlib.sha256(data).hexdigest()


# ─── Tiện ích ─────────────────────────────────────────────────────────────────

def bytes_to_hex(data: bytes) -> str:
    return data.hex()


def hex_to_bytes(hex_str: str) -> bytes:
    return bytes.fromhex(hex_str)
