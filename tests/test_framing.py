"""
test_framing.py – Kiểm thử lớp framing TCP (độ dài 4 byte big-endian, MAX_FRAME 64 KiB):
  - Gửi payload > MAX_FRAME -> ValueError
  - Nhận frame có header > MAX_FRAME -> None
  - Đọc từng mảnh nhỏ (phân mảnh TCP) vẫn ghép đủ payload
  - EOF giữa chừng -> None
  - Gửi nhận payload bình thường roundtrip
"""

import os
import socket
import struct
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

import framing


class TestFraming(unittest.TestCase):
    def setUp(self):
        self.sock_a, self.sock_b = socket.socketpair()

    def tearDown(self):
        self.sock_a.close()
        self.sock_b.close()

    def test_send_and_recv_normal(self):
        payload = b"Hello, this is a normal test frame."
        framing.send_frame(self.sock_a, payload)
        received = framing.recv_frame(self.sock_b)
        self.assertEqual(received, payload)

    def test_send_oversized_frame_raises(self):
        oversized = b"X" * (framing.MAX_FRAME + 1)
        with self.assertRaises(ValueError):
            framing.send_frame(self.sock_a, oversized)

    def test_recv_oversized_header_returns_none(self):
        # Malicious peer sends length > MAX_FRAME
        bad_len = framing.MAX_FRAME + 100
        header = struct.pack("!I", bad_len)
        self.sock_a.sendall(header)
        received = framing.recv_frame(self.sock_b)
        self.assertIsNone(received, "Header claiming > MAX_FRAME must return None to close connection")

    def test_fragmented_delivery(self):
        # Send frame payload in tiny 3-byte chunks
        payload = b"Chunked payload delivered in multiple fragments!"
        frame = struct.pack("!I", len(payload)) + payload
        for i in range(0, len(frame), 3):
            self.sock_a.sendall(frame[i : i + 3])
        received = framing.recv_frame(self.sock_b)
        self.assertEqual(received, payload)

    def test_eof_during_header(self):
        self.sock_a.sendall(b"\x00\x00")  # Only 2 bytes of 4-byte header
        self.sock_a.close()
        received = framing.recv_frame(self.sock_b)
        self.assertIsNone(received)

    def test_eof_during_payload(self):
        # Header says 10 bytes, but only send 5 before closing
        self.sock_a.sendall(struct.pack("!I", 10) + b"12345")
        self.sock_a.close()
        received = framing.recv_frame(self.sock_b)
        self.assertIsNone(received)


if __name__ == "__main__":
    unittest.main()
