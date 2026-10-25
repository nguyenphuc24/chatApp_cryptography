"""
test_replay.py – Kiểm thử seq và timestamp trong Session:
  - Gói có seq lặp (bằng seq trước) -> bị từ chối, session đóng
  - Gói có seq lùi (nhỏ hơn seq trước) -> bị từ chối, session đóng
  - Gói nhảy cóc seq (bỏ số thứ tự) -> bị từ chối, session đóng
  - Gói có timestamp cũ hơn 30s -> bị từ chối, session đóng
  - Gói có timestamp trong tương lai quá 10s -> bị từ chối, session đóng
  - Gói có seq tăng dần từ 1 và timestamp hợp lệ -> được chấp nhận
"""

import json
import os
import socket
import sys
import time
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from crypto_utils import encrypt_then_MAC
import framing
from session import Session


class TestReplayAndTimestamp(unittest.TestCase):
    def setUp(self):
        self.sock_a, self.sock_b = socket.socketpair()
        self.key_aes = os.urandom(32)
        self.key_hmac = os.urandom(32)
        self.session_b = Session(self.sock_b, self.key_aes, self.key_hmac, peer_cn="alice")

    def tearDown(self):
        self.sock_a.close()
        self.session_b.close()

    def _send_custom_pkt(self, seq: int, ts: float, msg_type="E2E_MSG", payload=None):
        if payload is None:
            payload = {"msg": "test"}
        pkt = {
            "type": msg_type,
            "sender": "alice",
            "seq": seq,
            "payload": payload,
            "timestamp": ts,
        }
        raw = json.dumps(pkt, ensure_ascii=False).encode()
        frame = encrypt_then_MAC(raw, self.key_aes, self.key_hmac)
        framing.send_frame(self.sock_a, frame)

    def test_valid_seq_sequence(self):
        now = time.time()
        self._send_custom_pkt(seq=1, ts=now)
        self._send_custom_pkt(seq=2, ts=now + 0.1)
        self._send_custom_pkt(seq=3, ts=now + 0.2)

        p1 = self.session_b.recv()
        p2 = self.session_b.recv()
        p3 = self.session_b.recv()

        self.assertIsNotNone(p1)
        self.assertIsNotNone(p2)
        self.assertIsNotNone(p3)
        self.assertEqual(p1["seq"], 1)
        self.assertEqual(p2["seq"], 2)
        self.assertEqual(p3["seq"], 3)

    def test_replay_same_seq_rejected(self):
        now = time.time()
        self._send_custom_pkt(seq=1, ts=now)
        # Replay packet 1
        self._send_custom_pkt(seq=1, ts=now)

        p1 = self.session_b.recv()
        self.assertIsNotNone(p1)
        p2 = self.session_b.recv()
        self.assertIsNone(p2, "Replayed seq=1 must be rejected and return None")
        self.assertTrue(self.session_b.closed)

    def test_backward_seq_rejected(self):
        now = time.time()
        self._send_custom_pkt(seq=1, ts=now)
        self._send_custom_pkt(seq=2, ts=now)
        self._send_custom_pkt(seq=1, ts=now)  # Backward seq

        p1 = self.session_b.recv()
        p2 = self.session_b.recv()
        self.assertIsNotNone(p1)
        self.assertIsNotNone(p2)
        p3 = self.session_b.recv()
        self.assertIsNone(p3, "Backward seq must be rejected")
        self.assertTrue(self.session_b.closed)

    def test_gap_in_seq_rejected(self):
        now = time.time()
        self._send_custom_pkt(seq=1, ts=now)
        # Skip seq 2, jump directly to 3
        self._send_custom_pkt(seq=3, ts=now)

        p1 = self.session_b.recv()
        self.assertIsNotNone(p1)
        p2 = self.session_b.recv()
        self.assertIsNone(p2, "Skipped seq (gap) must be rejected")
        self.assertTrue(self.session_b.closed)

    def test_expired_timestamp_rejected(self):
        old_time = time.time() - 35.0  # 35 seconds ago (> 30s limit)
        self._send_custom_pkt(seq=1, ts=old_time)

        p = self.session_b.recv()
        self.assertIsNone(p, "Packet older than 30s must be rejected")
        self.assertTrue(self.session_b.closed)

    def test_future_timestamp_rejected(self):
        future_time = time.time() + 15.0  # 15s in the future (> 10s limit)
        self._send_custom_pkt(seq=1, ts=future_time)

        p = self.session_b.recv()
        self.assertIsNone(p, "Packet with timestamp > 10s in the future must be rejected")
        self.assertTrue(self.session_b.closed)


if __name__ == "__main__":
    unittest.main()
