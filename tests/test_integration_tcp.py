"""
test_integration_tcp.py – Kiểm thử tích hợp toàn diện qua TCP socket thật:
  - Khởi động SecureChatServer trên localhost
  - Client Alice (team1) và Client Bob (team2) kết nối, bắt tay PKI thành công
  - Alice gửi tin nhắn chat E2E -> Bob nhận và giải mã chính xác
  - Alice gửi file E2E -> Server lưu trữ an toàn (không đọc được nội dung)
  - Bob lấy danh sách file và tải file về -> giải mã và xác minh SHA-256 hoàn hảo
"""

import os
import socket
import sys
import tempfile
import threading
import time
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

import e2e
import framing
import handshake
import pki
from server import SecureChatServer
from session import (
    MT_E2E_MSG,
    MT_FILE_E2E_CHUNK,
    MT_FILE_E2E_END,
    MT_FILE_E2E_START,
    MT_FILE_GET_REQ,
    MT_FILE_LIST_REQ,
    MT_FILE_LIST_RESP,
    MT_ROSTER_REQ,
    MT_ROSTER_RESP,
    Session,
)
from test_helpers import create_test_ca, create_test_cert


class TestTCPIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ca_cert, cls.ca_key = create_test_ca("Integration Root CA")
        cls.srv_cert, cls.srv_key = create_test_cert(
            cls.ca_cert, cls.ca_key, cn="chat-server"
        )
        cls.alice_cert, cls.alice_key = create_test_cert(
            cls.ca_cert, cls.ca_key, cn="alice", uids=["2312001"]
        )
        cls.bob_cert, cls.bob_key = create_test_cert(
            cls.ca_cert, cls.ca_key, cn="bob", uids=["2312002"]
        )

    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.storage_dir = os.path.join(self.tmp_dir.name, "server_storage")
        os.makedirs(self.storage_dir, exist_ok=True)

        # Find a free local port
        probe = socket.socket()
        probe.bind(("127.0.0.1", 0))
        self.port = probe.getsockname()[1]
        probe.close()

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
        time.sleep(0.1)  # wait for bind/listen

    def tearDown(self):
        self.server.stop()
        self.tmp_dir.cleanup()

    def _connect_client(self, cert, key, mssv_list) -> Session:
        sock = socket.socket()
        sock.connect(("127.0.0.1", self.port))
        return handshake.client_handshake(sock, self.ca_cert, cert, key, mssv_list)

    def _recv_type(self, session: Session, expected_type: str, timeout: float = 3.0) -> dict:
        start = time.monotonic()
        while time.monotonic() - start < timeout:
            pkt = session.recv()
            if pkt is None:
                raise ValueError("Session closed while waiting for packet")
            if pkt.get("type") == expected_type:
                return pkt
        raise TimeoutError(f"Timed out waiting for packet type '{expected_type}'")

    def test_full_chat_and_file_transfer_over_tcp(self):
        # 1. Alice and Bob connect to Server
        alice_session = self._connect_client(self.alice_cert, self.alice_key, ["2312001"])
        bob_session = self._connect_client(self.bob_cert, self.bob_key, ["2312002"])

        # 2. Alice requests roster
        alice_session.send(MT_ROSTER_REQ, {})
        roster_pkt = self._recv_type(alice_session, MT_ROSTER_RESP)

        roster = {}
        for entry in roster_pkt["payload"].get("roster", []):
            c = pki.load_cert(entry["cert_pem"].encode())
            pki.verify_cert(c, self.ca_cert)
            roster[entry["cn"]] = c

        self.assertIn("alice", roster)
        self.assertIn("bob", roster)

        # 3. Alice sends E2E Chat Message to Bob
        secret_message = "Confidential instructions for the cryptography assignment."
        e2e_payload = e2e.e2e_encrypt_msg(
            message=secret_message,
            my_cn="alice",
            seq=1,
            my_priv_key=self.alice_key,
            recipients={"bob": roster["bob"], "alice": roster["alice"]},
        )
        alice_session.send(MT_E2E_MSG, e2e_payload, sender="alice")

        # Bob receives the relayed message
        bob_pkt = self._recv_type(bob_session, MT_E2E_MSG)
        self.assertEqual(bob_pkt["sender"], "alice")  # Verified by server

        bob_last_seq = {}
        decrypted_message = e2e.e2e_decrypt_msg(
            payload=bob_pkt["payload"],
            sender_cn=bob_pkt["sender"],
            my_cn="bob",
            my_priv_key=self.bob_key,
            roster=roster,
            last_seq=bob_last_seq,
        )
        self.assertEqual(decrypted_message, secret_message)

        # 4. Alice prepares and sends E2E File to Bob
        sample_file_path = os.path.join(self.tmp_dir.name, "assignment.pdf")
        file_content = b"PDF-1.7 Test Document Content " * 300  # Multi-chunk
        with open(sample_file_path, "wb") as f:
            f.write(file_content)

        file_meta, file_chunks = e2e.e2e_prepare_file(
            path=sample_file_path,
            my_cn="alice",
            seq=1,
            my_priv_key=self.alice_key,
            recipients={"bob": roster["bob"], "alice": roster["alice"]},
        )

        alice_session.send(MT_FILE_E2E_START, file_meta, sender="alice")
        for chunk in file_chunks:
            alice_session.send(MT_FILE_E2E_CHUNK, chunk, sender="alice")
        alice_session.send(MT_FILE_E2E_END, {"chunks": len(file_chunks)}, sender="alice")

        # Wait briefly for server to finalize storage
        time.sleep(0.15)

        # 5. Bob queries file list from server
        bob_session.send(MT_FILE_LIST_REQ, {})
        list_pkt = self._recv_type(bob_session, MT_FILE_LIST_RESP)
        file_entries = list_pkt["payload"].get("files", [])
        self.assertTrue(any(f["name"] == "assignment.pdf" for f in file_entries))

        # 6. Bob downloads the file
        bob_session.send(MT_FILE_GET_REQ, {"name": "assignment.pdf"})
        dl_start = self._recv_type(bob_session, MT_FILE_E2E_START)
        recv_meta = dl_start["payload"].get("meta", dl_start["payload"])
        sender_cn = dl_start.get("sender") or recv_meta.get("sender")

        recv_chunks = []
        for _ in range(recv_meta["chunks"]):
            cpkt = self._recv_type(bob_session, MT_FILE_E2E_CHUNK)
            recv_chunks.append(cpkt["payload"])

        dl_end = self._recv_type(bob_session, MT_FILE_E2E_END)
        self.assertEqual(dl_end["type"], MT_FILE_E2E_END)

        # 7. Bob assembles and verifies the downloaded file E2E
        bob_file_seq = {}
        downloaded_bytes = e2e.e2e_assemble_file(
            meta=recv_meta,
            chunks=recv_chunks,
            my_cn="bob",
            my_priv_key=self.bob_key,
            roster=roster,
            sender_cn=sender_cn,
            last_file_seq=bob_file_seq,
        )
        self.assertEqual(downloaded_bytes, file_content)

        alice_session.close()
        bob_session.close()


if __name__ == "__main__":
    unittest.main()
