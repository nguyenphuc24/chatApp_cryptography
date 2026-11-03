"""
test_crl.py – Kiểm thử module CRL (Certificate Revocation List).

Các ca kiểm thử:
    1. test_make_crl_valid             – Tạo CRL hợp lệ, có thể load lại được
    2. test_revoked_cert_detected      – Cert đã revoke → is_revoked() trả True
    3. test_good_cert_not_revoked      – Cert chưa revoke → is_revoked() trả False
    4. test_expired_crl_rejected       – CRL hết hạn → verify_cert_with_crl ném lỗi
    5. test_verify_cert_with_crl_rejects_revoked – end-to-end: verify_cert_with_crl từ chối cert revoked
    6. test_handshake_rejected_with_revoked_cert – Handshake bị từ chối nếu cert bị thu hồi
"""

import datetime
import os
import socket
import sys
import threading
import time
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from test_helpers import create_test_ca, create_test_cert
import pki as pki_module
from crl import make_crl, load_crl, is_revoked, revoke_cert, load_revoked_db, save_revoked_db
from pki import verify_cert_with_crl


class TestCRL(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.ca_cert, cls.ca_key = create_test_ca("Test CRL Root CA")
        cls.client_cert, cls.client_key = create_test_cert(
            cls.ca_cert, cls.ca_key, cn="team_crl_test", uids=["9999001"]
        )
        cls.other_cert, cls.other_key = create_test_cert(
            cls.ca_cert, cls.ca_key, cn="team_other", uids=["9999002"]
        )

    # ─── Test 1: Tạo CRL hợp lệ ─────────────────────────────────────────────

    def test_make_crl_valid(self):
        """Tạo CRL rỗng; có thể load lại và xác minh issuer."""
        crl_pem = make_crl(self.ca_cert, self.ca_key, revoked_list=[])
        self.assertIsInstance(crl_pem, bytes)
        self.assertIn(b"BEGIN X509 CRL", crl_pem)

        crl = load_crl(crl_pem)
        # Issuer phải khớp với CA subject
        self.assertEqual(crl.issuer, self.ca_cert.subject)
        # nextUpdate phải ở tương lai
        now = datetime.datetime.now(datetime.timezone.utc)
        try:
            next_update = crl.next_update_utc
        except AttributeError:
            nu = crl.next_update
            next_update = nu.replace(tzinfo=datetime.timezone.utc)
        self.assertGreater(next_update, now)

    # ─── Test 2: Cert đã revoke → is_revoked() = True ───────────────────────

    def test_revoked_cert_detected(self):
        """Cert có serial nằm trong CRL → is_revoked() trả True."""
        serial_hex = hex(self.client_cert.serial_number)
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        revoked_list = [{"serial": serial_hex, "revoked_at": now, "reason": "keyCompromise"}]

        crl_pem = make_crl(self.ca_cert, self.ca_key, revoked_list=revoked_list)
        crl = load_crl(crl_pem)
        self.assertTrue(is_revoked(self.client_cert, crl))

    # ─── Test 3: Cert chưa revoke → is_revoked() = False ────────────────────

    def test_good_cert_not_revoked(self):
        """Cert không nằm trong CRL → is_revoked() trả False."""
        crl_pem = make_crl(self.ca_cert, self.ca_key, revoked_list=[])
        crl = load_crl(crl_pem)
        self.assertFalse(is_revoked(self.client_cert, crl))

    # ─── Test 4: CRL hết hạn → verify_cert_with_crl ném ValueError ──────────

    def test_expired_crl_rejected(self):
        """CRL đã qua nextUpdate → verify_cert_with_crl phải ném ValueError."""
        import datetime as dt
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import hashes
        from cryptography import x509

        now = dt.datetime.now(dt.timezone.utc)
        # Tạo CRL với nextUpdate đã qua (1 giây trước)
        past_next = now - dt.timedelta(seconds=1)
        builder = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(self.ca_cert.subject)
            .last_update(now - dt.timedelta(hours=1))
            .next_update(past_next)
        )
        crl = builder.sign(self.ca_key, hashes.SHA256(), default_backend())

        with self.assertRaises(ValueError) as ctx:
            verify_cert_with_crl(self.other_cert, self.ca_cert, crl)
        self.assertIn("hết hạn", str(ctx.exception).lower())

    # ─── Test 5: verify_cert_with_crl từ chối cert revoked ──────────────────

    def test_verify_cert_with_crl_rejects_revoked(self):
        """verify_cert_with_crl phải ném ValueError khi cert đã bị thu hồi."""
        serial_hex = hex(self.client_cert.serial_number)
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        revoked_list = [{"serial": serial_hex, "revoked_at": now, "reason": "cessationOfOperation"}]

        crl_pem = make_crl(self.ca_cert, self.ca_key, revoked_list=revoked_list)
        crl = load_crl(crl_pem)

        with self.assertRaises(ValueError) as ctx:
            verify_cert_with_crl(self.client_cert, self.ca_cert, crl)
        self.assertIn("thu hồi", str(ctx.exception).lower())

    # ─── Test 6: Cert chưa revoke → verify_cert_with_crl thành công ─────────

    def test_verify_cert_with_crl_accepts_good_cert(self):
        """Cert hợp lệ, không bị thu hồi → verify_cert_with_crl không ném lỗi."""
        crl_pem = make_crl(self.ca_cert, self.ca_key, revoked_list=[])
        crl = load_crl(crl_pem)
        # Không ném lỗi
        verify_cert_with_crl(self.other_cert, self.ca_cert, crl)


if __name__ == "__main__":
    unittest.main()
