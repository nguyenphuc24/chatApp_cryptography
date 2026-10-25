"""
test_timeout.py – Kiểm thử idle timeout và heartbeat:
  - Nếu không nhận được dữ liệu (hoặc PING) quá IDLE_TIMEOUT -> đóng session
  - Nếu có luồng heartbeat gửi PING định kỳ -> kết nối được duy trì
"""

import os
import socket
import sys
import time
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

import session
from session import MT_PING, MT_PONG, Session


class TestTimeoutAndHeartbeat(unittest.TestCase):
    def setUp(self):
        self._orig_ping_interval = session.PING_INTERVAL
        self._orig_idle_timeout = session.IDLE_TIMEOUT

        # Set small timeouts for fast testing
        session.PING_INTERVAL = 0.05
        session.IDLE_TIMEOUT = 0.2

    def tearDown(self):
        session.PING_INTERVAL = self._orig_ping_interval
        session.IDLE_TIMEOUT = self._orig_idle_timeout

    def test_idle_timeout_closes_session(self):
        sock_a, sock_b = socket.socketpair()
        key_aes = os.urandom(32)
        key_hmac = os.urandom(32)

        s_a = Session(sock_a, key_aes, key_hmac, peer_cn="b")
        s_b = Session(sock_b, key_aes, key_hmac, peer_cn="a")

        # Start heartbeat on s_a; it checks idle timeout
        s_a.start_heartbeat()

        # s_b does not send anything to s_a
        # Wait for IDLE_TIMEOUT (0.2s) to pass
        time.sleep(0.35)

        self.assertTrue(s_a.closed, "Session A should be closed after idle timeout without incoming packets")

        s_a.close()
        s_b.close()

    def test_active_ping_keeps_connection_alive(self):
        sock_a, sock_b = socket.socketpair()
        key_aes = os.urandom(32)
        key_hmac = os.urandom(32)

        s_a = Session(sock_a, key_aes, key_hmac, peer_cn="b")
        s_b = Session(sock_b, key_aes, key_hmac, peer_cn="a")

        # Send packets from B to A periodically to keep A active
        # Run for 0.4s (which is 2x the 0.2s idle timeout)
        start_time = time.monotonic()
        while time.monotonic() - start_time < 0.4:
            s_b.send(MT_PING, {})
            pkt = s_a.recv()
            self.assertIsNotNone(pkt)
            time.sleep(0.04)

        self.assertFalse(s_a.closed, "Session A should remain alive while receiving packets within timeout window")

        s_a.close()
        s_b.close()


if __name__ == "__main__":
    unittest.main()
