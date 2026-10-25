"""
test_concurrency.py – Kiểm thử an toàn luồng (thread-safety) khi gửi đồng thời:
  - Hai luồng cùng gọi session.send() (mỗi luồng 500 gói, tổng 1000 gói)
  - Bên nhận nhận đủ 1000 gói theo đúng thứ tự seq từ 1 đến 1000
  - Không có gói nào bị lỗi khung hay lỗi HMAC do race condition
"""

import os
import socket
import sys
import threading
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from session import Session


class TestConcurrency(unittest.TestCase):
    def test_concurrent_sending_preserves_seq_and_hmac(self):
        sock_sender, sock_receiver = socket.socketpair()
        key_aes = os.urandom(32)
        key_hmac = os.urandom(32)

        session_sender = Session(sock_sender, key_aes, key_hmac, peer_cn="receiver")
        session_receiver = Session(sock_receiver, key_aes, key_hmac, peer_cn="sender")

        total_per_thread = 500
        received_packets = []
        recv_errors = []

        def receiver_worker():
            for _ in range(total_per_thread * 2):
                pkt = session_receiver.recv()
                if pkt is None:
                    recv_errors.append("recv returned None")
                    break
                received_packets.append(pkt)

        recv_thread = threading.Thread(target=receiver_worker)
        recv_thread.start()

        def sender_worker(thread_id: int):
            for i in range(total_per_thread):
                session_sender.send("E2E_MSG", {"tid": thread_id, "idx": i}, sender="sender")

        t1 = threading.Thread(target=sender_worker, args=(1,))
        t2 = threading.Thread(target=sender_worker, args=(2,))

        t1.start()
        t2.start()

        t1.join(timeout=10)
        t2.join(timeout=10)
        recv_thread.join(timeout=10)

        session_sender.close()
        session_receiver.close()

        self.assertEqual(recv_errors, [])
        self.assertEqual(len(received_packets), total_per_thread * 2)

        # Verify seq numbers are strictly 1..1000 without gaps or duplicates
        seqs = [pkt["seq"] for pkt in received_packets]
        expected_seqs = list(range(1, total_per_thread * 2 + 1))
        self.assertEqual(seqs, expected_seqs)

        # Verify that all 500 from t1 and 500 from t2 are received
        t1_count = sum(1 for pkt in received_packets if pkt["payload"]["tid"] == 1)
        t2_count = sum(1 for pkt in received_packets if pkt["payload"]["tid"] == 2)
        self.assertEqual(t1_count, total_per_thread)
        self.assertEqual(t2_count, total_per_thread)


if __name__ == "__main__":
    unittest.main()
