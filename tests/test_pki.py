"""
test_pki.py – Kiểm thử xác thực chứng chỉ X.509:
  - CA hợp lệ: xác minh thành công
  - CA lạ (không ký chứng chỉ này): ném ValueError
  - Sai CN mong đợi: ném ValueError
  - CA cert dùng làm leaf cert: ném ValueError
  - Chứng chỉ hết hạn: ném ValueError
  - Chứng chỉ chưa có hiệu lực: ném ValueError
  - Trích xuất UID và chuyển đổi PEM/DER roundtrip
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

import pki
from test_helpers import create_test_ca, create_test_cert


class TestPKI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ca_cert, cls.ca_key = create_test_ca("Test Root CA")
        cls.other_ca_cert, cls.other_ca_key = create_test_ca("Untrusted Root CA")

    def test_valid_cert_verification(self):
        leaf_cert, _ = create_test_cert(
            self.ca_cert, self.ca_key, cn="chat-server", uids=["2312345"]
        )
        # Should not raise
        pki.verify_cert(leaf_cert, self.ca_cert, expected_cn="chat-server")
        self.assertEqual(pki.get_cn(leaf_cert), "chat-server")
        self.assertEqual(pki.get_uids(leaf_cert), ["2312345"])

    def test_untrusted_ca_rejected(self):
        leaf_cert, _ = create_test_cert(
            self.other_ca_cert, self.other_ca_key, cn="chat-server"
        )
        with self.assertRaises(ValueError) as ctx:
            pki.verify_cert(leaf_cert, self.ca_cert, expected_cn="chat-server")
        self.assertIn("Chữ ký chứng chỉ không hợp lệ", str(ctx.exception))

    def test_cn_mismatch_rejected(self):
        leaf_cert, _ = create_test_cert(
            self.ca_cert, self.ca_key, cn="fake-server"
        )
        with self.assertRaises(ValueError) as ctx:
            pki.verify_cert(leaf_cert, self.ca_cert, expected_cn="chat-server")
        self.assertIn("CN không khớp", str(ctx.exception))

    def test_ca_flagged_leaf_rejected(self):
        # A cert having CA=True must not be accepted as a leaf
        fake_leaf, _ = create_test_cert(
            self.ca_cert, self.ca_key, cn="team1", is_ca=True
        )
        with self.assertRaises(ValueError) as ctx:
            pki.verify_cert(fake_leaf, self.ca_cert, expected_cn="team1")
        self.assertIn("Chứng chỉ là CA certificate", str(ctx.exception))

    def test_expired_cert_rejected(self):
        # Valid 10 days ago, expired 1 day ago
        expired_cert, _ = create_test_cert(
            self.ca_cert,
            self.ca_key,
            cn="team1",
            validity_days=9,
            start_days_offset=-10,
        )
        with self.assertRaises(ValueError) as ctx:
            pki.verify_cert(expired_cert, self.ca_cert, expected_cn="team1")
        self.assertIn("đã hết hạn", str(ctx.exception))

    def test_future_cert_rejected(self):
        # Valid starts in 10 days
        future_cert, _ = create_test_cert(
            self.ca_cert,
            self.ca_key,
            cn="team1",
            validity_days=30,
            start_days_offset=10,
        )
        with self.assertRaises(ValueError) as ctx:
            pki.verify_cert(future_cert, self.ca_cert, expected_cn="team1")
        self.assertIn("chưa có hiệu lực", str(ctx.exception))

    def test_pem_der_roundtrip(self):
        cert, priv = create_test_cert(self.ca_cert, self.ca_key, cn="team2", uids=["1", "2"])
        pem_str = pki.cert_to_pem(cert)
        loaded = pki.load_cert(pem_str.encode())
        self.assertEqual(cert, loaded)

        der_bytes = pki.cert_to_der(cert)
        self.assertEqual(len(der_bytes) > 0, True)


if __name__ == "__main__":
    unittest.main()
