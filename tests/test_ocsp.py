"""
test_ocsp.py – Kiểm thử OCSP Responder và tích hợp pki.verify_cert_with_ocsp.

Các ca kiểm thử:
    1. test_ocsp_good_response         – Cert hợp lệ → OCSP trả Good
    2. test_ocsp_revoked_response      – Cert revoked → OCSP trả Revoked
    3. test_ocsp_server_starts_and_responds – OCSP HTTP server thực sự hoạt động
    4. test_verify_cert_with_ocsp_good – verify_cert_with_ocsp không ném lỗi với cert tốt
    5. test_verify_cert_with_ocsp_revoked – verify_cert_with_ocsp ném lỗi với cert bị thu hồi
"""

import datetime
import os
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from test_helpers import create_test_ca, create_test_cert
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import ocsp
from ocsp_server import make_ocsp_response, OCSPResponder, check_ocsp
from pki import verify_cert_with_ocsp


def _make_ocsp_request(cert, issuer_cert):
    builder = ocsp.OCSPRequestBuilder().add_certificate(cert, issuer_cert, hashes.SHA256())
    return builder.build()


class TestOCSP(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.ca_cert, cls.ca_key = create_test_ca("Test OCSP Root CA")
        cls.good_cert, cls.good_key = create_test_cert(
            cls.ca_cert, cls.ca_key, cn="team_ocsp_good", uids=["8888001"]
        )
        cls.revoked_cert, cls.revoked_key = create_test_cert(
            cls.ca_cert, cls.ca_key, cn="team_ocsp_revoked", uids=["8888002"]
        )
        # DB thu hồi chỉ chứa revoked_cert
        cls.revoked_serial_hex = hex(cls.revoked_cert.serial_number)
        cls.revoked_db = [{
            "serial":     cls.revoked_serial_hex,
            "revoked_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "reason":     "keyCompromise",
        }]
        cls.empty_db = []

    # ─── Test 1: OCSP Good ───────────────────────────────────────────────────

    def test_ocsp_good_response(self):
        """Cert tốt → OCSP response có trạng thái GOOD."""
        ocsp_req = _make_ocsp_request(self.good_cert, self.ca_cert)
        resp_der = make_ocsp_response(ocsp_req, self.ca_cert, self.ca_key, self.empty_db)
        resp = ocsp.load_der_ocsp_response(resp_der)
        self.assertEqual(resp.response_status, ocsp.OCSPResponseStatus.SUCCESSFUL)
        self.assertEqual(resp.certificate_status, ocsp.OCSPCertStatus.GOOD)

    # ─── Test 2: OCSP Revoked ────────────────────────────────────────────────

    def test_ocsp_revoked_response(self):
        """Cert revoked → OCSP response có trạng thái REVOKED."""
        ocsp_req = _make_ocsp_request(self.revoked_cert, self.ca_cert)
        resp_der = make_ocsp_response(ocsp_req, self.ca_cert, self.ca_key, self.revoked_db)
        resp = ocsp.load_der_ocsp_response(resp_der)
        self.assertEqual(resp.response_status, ocsp.OCSPResponseStatus.SUCCESSFUL)
        self.assertEqual(resp.certificate_status, ocsp.OCSPCertStatus.REVOKED)

    # ─── Test 3: OCSP HTTP server thực sự hoạt động ─────────────────────────

    def test_ocsp_server_starts_and_responds(self):
        """OCSP HTTP server start/stop và trả về response qua HTTP."""
        with tempfile.NamedTemporaryFile(
            suffix=".json", mode="w", delete=False, encoding="utf-8"
        ) as f:
            import json
            json.dump(self.empty_db, f)
            db_path = f.name

        try:
            responder = OCSPResponder(self.ca_cert, self.ca_key, db_path=db_path, port=0)
            responder.start()
            time.sleep(0.1)  # Chờ server khởi động
            status = check_ocsp(self.good_cert, self.ca_cert, responder.url)
            responder.stop()
            self.assertEqual(status, "good")
        finally:
            os.unlink(db_path)

    # ─── Test 4: verify_cert_with_ocsp không ném lỗi với cert tốt ──────────

    def test_verify_cert_with_ocsp_good(self):
        """verify_cert_with_ocsp không ném lỗi khi cert hợp lệ."""
        with tempfile.NamedTemporaryFile(
            suffix=".json", mode="w", delete=False, encoding="utf-8"
        ) as f:
            import json
            json.dump(self.empty_db, f)
            db_path = f.name

        try:
            responder = OCSPResponder(self.ca_cert, self.ca_key, db_path=db_path, port=0)
            responder.start()
            time.sleep(0.1)
            # Không ném lỗi
            verify_cert_with_ocsp(self.good_cert, self.ca_cert, responder.url)
            responder.stop()
        finally:
            os.unlink(db_path)

    # ─── Test 5: verify_cert_with_ocsp ném lỗi với cert bị thu hồi ─────────

    def test_verify_cert_with_ocsp_revoked(self):
        """verify_cert_with_ocsp ném ValueError khi cert bị thu hồi."""
        with tempfile.NamedTemporaryFile(
            suffix=".json", mode="w", delete=False, encoding="utf-8"
        ) as f:
            import json
            json.dump(self.revoked_db, f)
            db_path = f.name

        try:
            responder = OCSPResponder(self.ca_cert, self.ca_key, db_path=db_path, port=0)
            responder.start()
            time.sleep(0.1)
            with self.assertRaises(ValueError) as ctx:
                verify_cert_with_ocsp(self.revoked_cert, self.ca_cert, responder.url)
            self.assertIn("thu hồi", str(ctx.exception).lower())
            responder.stop()
        finally:
            os.unlink(db_path)


if __name__ == "__main__":
    unittest.main()
