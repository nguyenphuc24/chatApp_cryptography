"""
test_e2e_chat.py – Kiểm thử mã hoá đầu cuối (E2E Chat):
  - Server (hoặc kẻ nghe lén) không giải mã được tin nhắn (không có K, không có private key)
  - Người không nằm trong danh sách người nhận (không có wrap) không đọc được
  - Chữ ký RSA-PSS bị giả mạo / sửa đổi -> bên nhận từ chối (trả về None)
  - Replay gói tin E2E (seq <= last_seq) -> bên nhận từ chối
  - Người nhận hợp lệ giải mã chính xác nội dung
  - Giả mạo sender: nếu sender bị đổi hoặc chữ ký không khớp chứng chỉ người gửi -> từ chối
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from crypto_utils import rsa_encrypt
import e2e
from test_helpers import create_test_ca, create_test_cert


class TestE2EChat(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ca_cert, cls.ca_key = create_test_ca("E2E Test CA")

        cls.alice_cert, cls.alice_key = create_test_cert(
            cls.ca_cert, cls.ca_key, cn="alice", uids=["1111111"]
        )
        cls.bob_cert, cls.bob_key = create_test_cert(
            cls.ca_cert, cls.ca_key, cn="bob", uids=["2222222"]
        )
        cls.eve_cert, cls.eve_key = create_test_cert(
            cls.ca_cert, cls.ca_key, cn="eve", uids=["3333333"]
        )

        cls.roster = {
            "alice": cls.alice_cert,
            "bob": cls.bob_cert,
            "eve": cls.eve_cert,
        }

    def test_e2e_encrypt_decrypt_valid(self):
        msg = "Hi Bob, this is a secret end-to-end message from Alice!"
        recipients = {"bob": self.bob_cert, "alice": self.alice_cert}

        payload = e2e.e2e_encrypt_msg(
            message=msg,
            my_cn="alice",
            seq=1,
            my_priv_key=self.alice_key,
            recipients=recipients,
        )

        # Bob decrypts
        bob_last_seq = {}
        bob_received = e2e.e2e_decrypt_msg(
            payload=payload,
            sender_cn="alice",
            my_cn="bob",
            my_priv_key=self.bob_key,
            roster=self.roster,
            last_seq=bob_last_seq,
        )
        self.assertEqual(bob_received, msg)
        self.assertEqual(bob_last_seq.get("alice"), 1)

    def test_eavesdropper_without_wrap_cannot_decrypt(self):
        msg = "Private between Alice and Bob only"
        # Only Bob and Alice are in recipients; Eve is not
        recipients = {"bob": self.bob_cert, "alice": self.alice_cert}

        payload = e2e.e2e_encrypt_msg(
            message=msg,
            my_cn="alice",
            seq=1,
            my_priv_key=self.alice_key,
            recipients=recipients,
        )

        eve_last_seq = {}
        eve_received = e2e.e2e_decrypt_msg(
            payload=payload,
            sender_cn="alice",
            my_cn="eve",
            my_priv_key=self.eve_key,
            roster=self.roster,
            last_seq=eve_last_seq,
        )
        self.assertIsNone(eve_received, "Eve must not be able to decrypt without a wrap for Eve")

    def test_tampered_signature_rejected(self):
        msg = "Message to be tampered"
        recipients = {"bob": self.bob_cert}

        payload = e2e.e2e_encrypt_msg(
            message=msg,
            my_cn="alice",
            seq=1,
            my_priv_key=self.alice_key,
            recipients=recipients,
        )

        # Tamper signature
        sig_bytes = bytearray(bytes.fromhex(payload["sig"]))
        sig_bytes[5] ^= 0x01
        payload["sig"] = bytes(sig_bytes).hex()

        bob_last_seq = {}
        bob_received = e2e.e2e_decrypt_msg(
            payload=payload,
            sender_cn="alice",
            my_cn="bob",
            my_priv_key=self.bob_key,
            roster=self.roster,
            last_seq=bob_last_seq,
        )
        self.assertIsNone(bob_received, "Tampered signature must be rejected")

    def test_replay_seq_rejected(self):
        msg1 = "First message"
        msg2 = "Replayed message"
        recipients = {"bob": self.bob_cert}

        p1 = e2e.e2e_encrypt_msg(msg1, "alice", 1, self.alice_key, recipients)
        p2 = e2e.e2e_encrypt_msg(msg2, "alice", 1, self.alice_key, recipients)  # same seq 1

        bob_last_seq = {}
        res1 = e2e.e2e_decrypt_msg(p1, "alice", "bob", self.bob_key, self.roster, bob_last_seq)
        self.assertEqual(res1, msg1)
        self.assertEqual(bob_last_seq["alice"], 1)

        # Replay attempt with seq=1
        res2 = e2e.e2e_decrypt_msg(p2, "alice", "bob", self.bob_key, self.roster, bob_last_seq)
        self.assertIsNone(res2, "Message with same or earlier seq must be rejected as replay")

    def test_spoofed_sender_rejected(self):
        # Eve signs a message pretending to be Alice
        msg = "I am Alice (actually Eve)"
        recipients = {"bob": self.bob_cert}

        # Eve encrypts and signs with Eve's key
        payload = e2e.e2e_encrypt_msg(
            message=msg,
            my_cn="alice",  # Eve claims cn=alice in transcript
            seq=1,
            my_priv_key=self.eve_key,  # but signs with Eve's private key
            recipients=recipients,
        )

        bob_last_seq = {}
        # Bob checks with sender_cn="alice" using Alice's public key from roster
        bob_received = e2e.e2e_decrypt_msg(
            payload=payload,
            sender_cn="alice",
            my_cn="bob",
            my_priv_key=self.bob_key,
            roster=self.roster,
            last_seq=bob_last_seq,
        )
        self.assertIsNone(bob_received, "Bob must reject message signed by Eve's key when checking against Alice")


if __name__ == "__main__":
    unittest.main()
