"""
test_server_graceful_shutdown.py – Kiểm thử cơ chế thoát an toàn (graceful shutdown) của Server:
  - Socket accept không bị block vô tận (settimeout 1.0s)
  - Khi gọi stop():
    + Cờ _running được đặt thành False
    + Listening socket được đóng
    + Mọi client session đang kết nối được gửi MT_DISCONNECT và đóng socket
    + Luồng server kết thúc kịp thời (không treo process)
    + Hàm stop() có tính idempotent (gọi nhiều lần không gây lỗi)
"""

import os
import socket
import sys
import tempfile
import threading
import time
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

import handshake
import pki
from server import SecureChatServer
from session import MT_DISCONNECT, Session


class TestServerGracefulShutdown(unittest.TestCase):

    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.storage_dir = self.tmp_dir.name

        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        pki_dir = os.path.join(base_dir, "pki")
        self.ca_cert = pki.load_cert_from_file(os.path.join(pki_dir, "ca.crt"))
        self.srv_cert = pki.load_cert_from_file(os.path.join(pki_dir, "server.crt"))
        self.srv_key = pki.load_private_key_from_file(os.path.join(pki_dir, "server.key"))

        self.team1_cert = pki.load_cert_from_file(os.path.join(pki_dir, "team1", "client.crt"))
        self.team1_key = pki.load_private_key_from_file(os.path.join(pki_dir, "team1", "client.key"))
        self.team2_cert = pki.load_cert_from_file(os.path.join(pki_dir, "team2", "client.crt"))
        self.team2_key = pki.load_private_key_from_file(os.path.join(pki_dir, "team2", "client.key"))

        # Chọn cổng khả dụng
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            self.port = s.getsockname()[1]

        self.server = SecureChatServer(
            host="127.0.0.1",
            port=self.port,
            ca_cert=self.ca_cert,
            server_cert=self.srv_cert,
            server_key=self.srv_key,
            storage_dir=self.storage_dir,
        )

        self.srv_thread = threading.Thread(target=self.server.start, daemon=True)
        self.srv_thread.start()
        time.sleep(0.15)

    def tearDown(self):
        self.server.stop()
        self.tmp_dir.cleanup()

    def test_shutdown_unblocks_and_terminates(self):
        """Kiểm tra server tắt ngay lập tức kể cả khi không có kết nối nào."""
        self.assertTrue(self.server._running)
        self.assertTrue(self.srv_thread.is_alive())

        start = time.monotonic()
        self.server.stop()
        self.srv_thread.join(timeout=2.0)
        elapsed = time.monotonic() - start

        self.assertFalse(self.srv_thread.is_alive(), "Luồng server phải kết thúc, không bị block.")
        self.assertLess(elapsed, 2.0, "Thời gian thoát phải dưới 2 giây.")
        self.assertFalse(self.server._running)

    def test_shutdown_disconnects_all_active_clients(self):
        """Kiểm tra khi server dừng, các client kết nối nhận được MT_DISCONNECT và phiên bị đóng."""
        # Kết nối Client 1
        sock1 = socket.socket()
        sock1.connect(("127.0.0.1", self.port))
        s1 = handshake.client_handshake(sock1, self.ca_cert, self.team1_cert, self.team1_key, ["2412716", "2412760"])

        # Kết nối Client 2
        sock2 = socket.socket()
        sock2.connect(("127.0.0.1", self.port))
        s2 = handshake.client_handshake(sock2, self.ca_cert, self.team2_cert, self.team2_key, ["2312716", "2312760"])

        time.sleep(0.1)
        with self.server._lock:
            self.assertEqual(len(self.server._sessions), 2)

        # Dừng server
        self.server.stop()
        self.srv_thread.join(timeout=2.0)

        # Client 1 nhận gói MT_DISCONNECT (sau khi nhận SYS_MSG nếu có)
        pkts1 = []
        while True:
            p = s1.recv()
            if p is None:
                break
            pkts1.append(p)
            if p.get("type") == MT_DISCONNECT:
                break
        self.assertTrue(any(p.get("type") == MT_DISCONNECT for p in pkts1), "Client 1 phải nhận MT_DISCONNECT")

        # Client 2 nhận gói MT_DISCONNECT
        pkts2 = []
        while True:
            p = s2.recv()
            if p is None:
                break
            pkts2.append(p)
            if p.get("type") == MT_DISCONNECT:
                break
        self.assertTrue(any(p.get("type") == MT_DISCONNECT for p in pkts2), "Client 2 phải nhận MT_DISCONNECT")

        # Cả 2 socket client đóng
        s1.close()
        s2.close()

    def test_stop_is_idempotent(self):
        """Gọi stop() nhiều lần không được gây lỗi ngoại lệ."""
        self.server.stop()
        self.server.stop()
        self.server.stop()
        self.assertFalse(self.server._running)


if __name__ == "__main__":
    unittest.main()
