"""
test_crypto.py – Kiểm thử các nguyên hàm mật mã:
  - EtM roundtrip
  - Sửa 1 bit trong ciphertext/HMAC → từ chối (trả về None)
  - Sai khoá AES/HMAC → từ chối
  - Frame ngắn hơn header tối thiểu (< 48 bytes) → từ chối
  - RSA-OAEP roundtrip
  - RSA-PSS ký và xác minh (đúng, sai thông điệp ném InvalidSignature)
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa

from crypto_utils import (
    aes_decrypt,
    aes_encrypt,
    encrypt_then_MAC,
    rsa_decrypt,
    rsa_encrypt,
    rsa_pss_sign,
    rsa_pss_verify,
    sha256_hash,
    sha256_hex,
    verify_then_decrypt,
)


class TestCryptoPrimitives(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rsa_priv = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend(),
        )
        cls.rsa_pub = cls.rsa_priv.public_key()
        cls.key_aes = os.urandom(32)
        cls.key_hmac = os.urandom(32)

    def test_etm_roundtrip(self):
        msg = b"Hello, this is a secret test message for Encrypt-then-MAC!"
        frame = encrypt_then_MAC(msg, self.key_aes, self.key_hmac)
        decrypted = verify_then_decrypt(frame, self.key_aes, self.key_hmac)
        self.assertEqual(decrypted, msg)

    def test_etm_tamper_one_bit_ciphertext(self):
        msg = b"Sensitive information that must not be tampered."
        frame = bytearray(encrypt_then_MAC(msg, self.key_aes, self.key_hmac))
        # Tamper 1 bit in ciphertext (offset 20 is in ciphertext after 16-byte IV)
        frame[20] ^= 0x01
        res = verify_then_decrypt(bytes(frame), self.key_aes, self.key_hmac)
        self.assertIsNone(res, "Tampered ciphertext should be rejected by HMAC verification")

    def test_etm_tamper_one_bit_hmac(self):
        msg = b"Sensitive information that must not be tampered."
        frame = bytearray(encrypt_then_MAC(msg, self.key_aes, self.key_hmac))
        # Tamper last byte (in HMAC tag)
        frame[-1] ^= 0x01
        res = verify_then_decrypt(bytes(frame), self.key_aes, self.key_hmac)
        self.assertIsNone(res, "Tampered HMAC tag should be rejected")

    def test_etm_wrong_keys(self):
        msg = b"Data with wrong keys."
        frame = encrypt_then_MAC(msg, self.key_aes, self.key_hmac)
        wrong_aes = os.urandom(32)
        wrong_hmac = os.urandom(32)
        self.assertIsNone(verify_then_decrypt(frame, self.key_aes, wrong_hmac))
        self.assertIsNone(verify_then_decrypt(frame, wrong_aes, self.key_hmac))

    def test_etm_short_frame(self):
        # Frame must have at least 16 (IV) + 16 (1 AES block) + 32 (HMAC) = 64 bytes
        short_frame = os.urandom(47)
        self.assertIsNone(verify_then_decrypt(short_frame, self.key_aes, self.key_hmac))

    def test_rsa_oaep_roundtrip(self):
        secret = os.urandom(32)
        ct = rsa_encrypt(secret, self.rsa_pub)
        pt = rsa_decrypt(ct, self.rsa_priv)
        self.assertEqual(pt, secret)

    def test_rsa_pss_sign_and_verify(self):
        msg = b"Important transaction to sign."
        sig = rsa_pss_sign(self.rsa_priv, msg)
        # Verify valid signature (should not raise)
        rsa_pss_verify(self.rsa_pub, msg, sig)

        # Tampered message must raise InvalidSignature
        tampered_msg = b"Important transaction to sign!"
        with self.assertRaises(InvalidSignature):
            rsa_pss_verify(self.rsa_pub, tampered_msg, sig)

        # Tampered signature must raise InvalidSignature
        tampered_sig = bytearray(sig)
        tampered_sig[10] ^= 0x01
        with self.assertRaises(InvalidSignature):
            rsa_pss_verify(self.rsa_pub, msg, bytes(tampered_sig))


if __name__ == "__main__":
    unittest.main()
