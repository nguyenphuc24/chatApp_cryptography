"""
test_kdf.py – Kiểm thử KDF và encoding không nhập nhằng:
  - enc_list(["23", "12"]) != enc_list(["2312"])
  - Đổi thứ tự MSSV -> session_key thay đổi
  - Đổi nonce -> session_key thay đổi
  - Đổi MS -> session_key thay đổi
  - kdf_keys tách thành 2 khoá (AES, HMAC) 32 bytes riêng biệt
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from crypto_utils import enc, enc_list, enc_map, kdf_init_keys, kdf_keys, kdf_session_key


class TestKDF(unittest.TestCase):
    def test_enc_list_ambiguity_prevention(self):
        encoded1 = enc_list(["23", "12"])
        encoded2 = enc_list(["2312"])
        self.assertNotEqual(
            encoded1,
            encoded2,
            "enc_list must prevent canonicalization collision: ['23', '12'] vs ['2312']",
        )

    def test_kdf_mssv_order_sensitivity(self):
        ms = os.urandom(32)
        nonce = os.urandom(16)
        k1 = kdf_session_key(ms, ["2312345", "2312346"], nonce)
        k2 = kdf_session_key(ms, ["2312346", "2312345"], nonce)
        self.assertNotEqual(k1, k2, "KDF must produce different keys when MSSV order changes")

    def test_kdf_nonce_sensitivity(self):
        ms = os.urandom(32)
        nonce1 = os.urandom(16)
        nonce2 = os.urandom(16)
        k1 = kdf_session_key(ms, ["2312345"], nonce1)
        k2 = kdf_session_key(ms, ["2312345"], nonce2)
        self.assertNotEqual(k1, k2, "KDF must produce different keys with different nonces")

    def test_kdf_master_secret_sensitivity(self):
        ms1 = os.urandom(32)
        ms2 = os.urandom(32)
        nonce = os.urandom(16)
        k1 = kdf_session_key(ms1, ["2312345"], nonce)
        k2 = kdf_session_key(ms2, ["2312345"], nonce)
        self.assertNotEqual(k1, k2, "KDF must produce different keys with different MS")

    def test_kdf_key_expansion(self):
        sk = os.urandom(32)
        k_aes, k_hmac = kdf_keys(sk)
        self.assertEqual(len(k_aes), 32)
        self.assertEqual(len(k_hmac), 32)
        self.assertNotEqual(k_aes, k_hmac, "AES key and HMAC key derived from session key must differ")

    def test_kdf_init_keys(self):
        ms = os.urandom(32)
        k_init_aes, k_init_hmac = kdf_init_keys(ms)
        self.assertEqual(len(k_init_aes), 32)
        self.assertEqual(len(k_init_hmac), 32)
        self.assertNotEqual(k_init_aes, k_init_hmac)

    def test_enc_map_sorting(self):
        # enc_map should sort keys alphabetically
        d1 = {"bob": "aa", "alice": "bb"}
        d2 = {"alice": "bb", "bob": "aa"}
        self.assertEqual(enc_map(d1), enc_map(d2))


if __name__ == "__main__":
    unittest.main()
