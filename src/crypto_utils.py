import os
import hashlib
import hmac
from typing import Tuple

from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

def gen_rsa_keypair(key_size: int = 2048) -> Tuple [object, object]:
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )
    return private_key, private_key.public_key()

def serialize_public_key(public_key: object) -> bytes:
    #turn public key to pem for network tranfer
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def deserialize_public_key(key_bytes: bytes) -> object:
    return serialization.load_pem_public_key(
        key_bytes,
        backend=default_backend()
    )


def rsa_encrypt(data: bytes, public_key: object) -> bytes:
    # Encrypt session key
    return public_key.encrypt(
        data,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def rsa_decrypt(cypertext: bytes, private_key : object) -> bytes:
    #decrypt session key 
    return private_key.decrypt(
        cypertext,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


#aes

def aes_encrypt(data: bytes, key: bytes, iv: bytes = None) -> Tuple[bytes, bytes]:
    if len(key) != 32:
        raise ValueError(f"AES key invalid")
    if iv is None:
        iv = os.urandom(16)
    elif len(iv) != 16:
        raise ValueError(f"IV phải có 16 bytes")

    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded = pad(data, AES.block_size, style='pkcs7')
    return cipher.encrypt(padded), iv

def aes_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    if len(key) != 32:
        raise ValueError(f"AES-256 cần key đúng 32 bytes, nhận được {len(key)} bytes")
    if len(iv) != 16:
        raise ValueError("IV phải đúng 16 bytes")

    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded  = cipher.decrypt(ciphertext)
    return unpad(padded, AES.block_size, style='pkcs7')


#KDF
def derive_session_key(master_secret: bytes, mssv_list: list, server_nonce: str) -> bytes:
    mssv_part = "".join(str(m).strip() for m in mssv_list).encode()
    nonce_part = str(server_nonce).encode()
    return hashlib.sha256(master_secret + mssv_part + nonce_part).digest()

def derive_keys(master_key: bytes) -> tuple[bytes, bytes]:
    key_aes = hashlib.sha256(master_key + b":encryption").digest()
    key_hmac = hashlib.sha256(master_key + b":authentication").digest()
    return key_aes, key_hmac


def hmac_sign(data: bytes, key: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()

def hmac_verify(data: bytes, signature: bytes, key: bytes) -> bool:
    expected = hmac_sign(data, key)
    return hmac.compare_digest(signature, expected)

#         Wire format: [ IV (16B) ] [ Ciphertext (NB) ] [ HMAC Tag (32B) ]
def encrypt_then_MAC(plaintext: bytes, key_aes: bytes, key_hmac: bytes) -> bytes:

    ciphertext, iv = aes_encrypt(plaintext, key_aes)
    payload_body = iv +  ciphertext
    sig = hmac_sign(payload_body, key_hmac)
    return payload_body + sig


def MAC_then_decrypt(payload: bytes, key_aes: bytes, key_hmac: bytes) -> bytes | None:
    if len(payload) < 64 : return None

    payload_body = payload[:-32]
    sig = payload[-32:]

    if not hmac_verify(payload_body, sig, key_hmac) : 
        return None

    iv = payload_body[:16]
    ciphertext = payload_body[16:]
    try:
        return aes_decrypt(ciphertext, key_aes, iv)
    except Exception:
        return None 


# SHA-256  –  Băm dữ liệu / kiểm tra toàn vẹn file


def sha256_hash(data: bytes) -> bytes:
    """Băm data trả về 32 bytes nhị phân."""
    return hashlib.sha256(data).digest()


def sha256_hex(data: bytes) -> str:
    """Băm data trả về 64 ký tự hex (dùng làm checksum file)."""
    return hashlib.sha256(data).hexdigest()



#  Utility


def bytes_to_hex(data: bytes) -> str:
    return data.hex()

def hex_to_bytes(hex_str: str) -> bytes:
    return bytes.fromhex(hex_str)



# Self_test
if __name__ == "__main__":
    print("=" * 60)
    print("  CRYPTO UTILS – BÀI TỰ KIỂM TRA")
    print("=" * 60)

    # --- Test 1: RSA ---
    print("\n[1] RSA-2048 + OAEP")
    priv, pub = gen_rsa_keypair(2048)
    pem = serialize_public_key(pub)
    pub2 = deserialize_public_key(pem)
    secret = b"MySessionKey!1234567890123456789"   # 32 bytes
    enc = rsa_encrypt(secret, pub2)
    dec = rsa_decrypt(enc, priv)
    assert dec == secret, "RSA THẤT BẠI"
    print("  ✓ RSA sinh khoá, serialize PEM, mã hoá và giải mã – OK")

    # --- Test 2: AES ---
    print("\n[2] AES-256-CBC + PKCS#7")
    key = os.urandom(32)
    msg = b"Tin nhan bao mat dai hon 16 bytes de kiem tra padding."
    ct, iv = aes_encrypt(msg, key)
    pt = aes_decrypt(ct, key, iv)
    assert pt == msg, "AES THẤT BẠI"
    print("  ✓ AES mã hoá và giải mã – OK")

    # --- Test 3: KDF ---
    print("\n[3] KDF từ MSSV")
    mssv = ["2312345", "2312346"]
    k1 = derive_session_key(mssv)
    k2 = derive_session_key(mssv)
    assert k1 == k2 and len(k1) == 32, "KDF THẤT BẠI"
    print(f"  ✓ Session Key (hex): {k1.hex()}")

    # --- Test 4: HMAC ---
    print("\n[4] HMAC-SHA256")
    sig = hmac_sign(msg, key)
    assert hmac_verify(msg, sig, key) == True,  "HMAC hợp lệ thất bại"
    assert hmac_verify(msg + b"x", sig, key) == False, "Phát hiện giả mạo thất bại"
    print("  ✓ HMAC ký và xác thực (kể cả phát hiện giả mạo) – OK")

    print("\n" + "=" * 60)
    print("  TẤT CẢ BÀI TEST ĐỀU ĐẠT – SẴN SÀNG TÍCH HỢP!")
    print("=" * 60)
