"""
test_handshake.py – Kiểm thử luồng bắt tay và các thuộc tính an toàn:
  - Bắt tay hợp lệ qua socketpair
  - MitM: server đưa chứng chỉ tự ký hoặc CA không tin cậy -> client từ chối
  - Khai mạo danh MSSV: UID trong client_cert khác mssv_list -> server từ chối
  - Chữ ký giả mạo: ký bằng khoá riêng khác -> server từ chối
  - Client cert do CA lạ ký -> server từ chối
  - Bảo mật danh tính: MSSV không xuất hiện dạng rõ trên wire
  - Chống replay: Gói HANDSHAKE_INIT cũ bị server từ chối vì nonce thay đổi
"""

import os
import socket
import sys
import threading
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

import framing
import handshake
import pki
from test_helpers import create_test_ca, create_test_cert


class InterceptingSocket:
    """Socket bọc để ghi lại toàn bộ byte truyền qua mạng nhằm kiểm tra lộ thông tin rõ."""

    def __init__(self, real_sock: socket.socket):
        self.real_sock = real_sock
        self.recorded_sent = bytearray()
        self.recorded_recv = bytearray()

    def sendall(self, data: bytes):
        self.recorded_sent.extend(data)
        return self.real_sock.sendall(data)

    def recv(self, bufsize: int, flags: int = 0):
        data = self.real_sock.recv(bufsize, flags)
        self.recorded_recv.extend(data)
        return data

    def close(self):
        return self.real_sock.close()

    def settimeout(self, timeout):
        return self.real_sock.settimeout(timeout)


class TestHandshake(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ca_cert, cls.ca_key = create_test_ca("Trusted Root CA")
        cls.untrusted_ca_cert, cls.untrusted_ca_key = create_test_ca("Untrusted Root CA")

        cls.srv_cert, cls.srv_key = create_test_cert(
            cls.ca_cert, cls.ca_key, cn="chat-server"
        )
        cls.client_cert, cls.client_key = create_test_cert(
            cls.ca_cert, cls.ca_key, cn="team1", uids=["2312345", "2312346"]
        )

    def test_valid_handshake(self):
        c_sock, s_sock = socket.socketpair()
        c_session = None
        s_session = None
        errs = []

        def run_server():
            nonlocal s_session
            try:
                s_session = handshake.server_handshake(
                    s_sock, self.ca_cert, self.srv_cert, self.srv_key
                )
            except Exception as e:
                errs.append(("server", e))

        def run_client():
            nonlocal c_session
            try:
                c_session = handshake.client_handshake(
                    c_sock, self.ca_cert, self.client_cert, self.client_key, ["2312345", "2312346"]
                )
            except Exception as e:
                errs.append(("client", e))

        t_srv = threading.Thread(target=run_server)
        t_cli = threading.Thread(target=run_client)
        t_srv.start()
        t_cli.start()
        t_srv.join(timeout=3)
        t_cli.join(timeout=3)

        self.assertEqual(errs, [], f"Handshake failed with errors: {errs}")
        self.assertIsNotNone(c_session)
        self.assertIsNotNone(s_session)
        self.assertEqual(s_session.peer_cn, "team1")

        # Test communicating after handshake
        c_session.send("E2E_MSG", {"msg": "hello server"}, sender="team1")
        pkt = s_session.recv()
        self.assertIsNotNone(pkt)
        self.assertEqual(pkt["payload"]["msg"], "hello server")

        c_session.close()
        s_session.close()

    def test_mitm_untrusted_server_cert(self):
        # Server presents a cert signed by untrusted CA
        fake_srv_cert, fake_srv_key = create_test_cert(
            self.untrusted_ca_cert, self.untrusted_ca_key, cn="chat-server"
        )
        c_sock, s_sock = socket.socketpair()
        client_err = []

        def run_server():
            try:
                handshake.server_handshake(s_sock, self.ca_cert, fake_srv_cert, fake_srv_key)
            except Exception:
                pass
            finally:
                s_sock.close()

        def run_client():
            try:
                handshake.client_handshake(
                    c_sock, self.ca_cert, self.client_cert, self.client_key, ["2312345", "2312346"]
                )
            except Exception as e:
                client_err.append(e)
            finally:
                c_sock.close()

        t_srv = threading.Thread(target=run_server)
        t_cli = threading.Thread(target=run_client)
        t_srv.start()
        t_cli.start()
        t_srv.join(timeout=3)
        t_cli.join(timeout=3)

        c_sock.close()
        s_sock.close()

        self.assertEqual(len(client_err), 1)
        self.assertIsInstance(client_err[0], ValueError)
        self.assertIn("Chữ ký chứng chỉ không hợp lệ", str(client_err[0]))

    def test_mssv_mismatch_rejected(self):
        # Client declares MSSVs that do not match its certificate UIDs
        c_sock, s_sock = socket.socketpair()
        server_err = []

        def run_server():
            try:
                handshake.server_handshake(s_sock, self.ca_cert, self.srv_cert, self.srv_key)
            except Exception as e:
                server_err.append(e)
            finally:
                s_sock.close()

        def run_client():
            try:
                handshake.client_handshake(
                    c_sock, self.ca_cert, self.client_cert, self.client_key, ["9999999"]
                )
            except Exception:
                pass
            finally:
                c_sock.close()

        t_srv = threading.Thread(target=run_server)
        t_cli = threading.Thread(target=run_client)
        t_srv.start()
        t_cli.start()
        t_srv.join(timeout=3)
        t_cli.join(timeout=3)

        self.assertEqual(len(server_err), 1)
        self.assertIn("không khớp MSSV khai báo", str(server_err[0]))

    def test_wrong_signature_key_rejected(self):
        # Client signs transcript with another key (not the one in client_cert)
        wrong_key = pki.load_private_key(
            self.srv_key.private_bytes(
                pki.serialization.Encoding.PEM,
                pki.serialization.PrivateFormat.TraditionalOpenSSL,
                pki.serialization.NoEncryption(),
            )
        )
        c_sock, s_sock = socket.socketpair()
        server_err = []

        def run_server():
            try:
                handshake.server_handshake(s_sock, self.ca_cert, self.srv_cert, self.srv_key)
            except Exception as e:
                server_err.append(e)
            finally:
                s_sock.close()

        def run_client():
            try:
                handshake.client_handshake(
                    c_sock, self.ca_cert, self.client_cert, wrong_key, ["2312345", "2312346"]
                )
            except Exception:
                pass
            finally:
                c_sock.close()

        t_srv = threading.Thread(target=run_server)
        t_cli = threading.Thread(target=run_client)
        t_srv.start()
        t_cli.start()
        t_srv.join(timeout=3)
        t_cli.join(timeout=3)

        self.assertEqual(len(server_err), 1)
        self.assertIn("Chữ ký HANDSHAKE_INIT không hợp lệ", str(server_err[0]))

    def test_untrusted_client_cert_rejected(self):
        fake_client_cert, fake_client_key = create_test_cert(
            self.untrusted_ca_cert, self.untrusted_ca_key, cn="fake-team", uids=["2312345"]
        )
        c_sock, s_sock = socket.socketpair()
        server_err = []

        def run_server():
            try:
                handshake.server_handshake(s_sock, self.ca_cert, self.srv_cert, self.srv_key)
            except Exception as e:
                server_err.append(e)
            finally:
                s_sock.close()

        def run_client():
            try:
                handshake.client_handshake(
                    c_sock, self.ca_cert, fake_client_cert, fake_client_key, ["2312345"]
                )
            except Exception:
                pass
            finally:
                c_sock.close()

        t_srv = threading.Thread(target=run_server)
        t_cli = threading.Thread(target=run_client)
        t_srv.start()
        t_cli.start()
        t_srv.join(timeout=3)
        t_cli.join(timeout=3)

        c_sock.close()
        s_sock.close()

        self.assertEqual(len(server_err), 1)
        self.assertIn("Chữ ký chứng chỉ không hợp lệ", str(server_err[0]))

    def test_mssv_not_leaked_in_wire_bytes(self):
        raw_c_sock, raw_s_sock = socket.socketpair()
        c_sock = InterceptingSocket(raw_c_sock)
        s_sock = InterceptingSocket(raw_s_sock)

        mssv_1 = "2312345"
        mssv_2 = "2312346"

        t_srv = threading.Thread(
            target=lambda: handshake.server_handshake(
                s_sock, self.ca_cert, self.srv_cert, self.srv_key
            )
        )
        t_cli = threading.Thread(
            target=lambda: handshake.client_handshake(
                c_sock, self.ca_cert, self.client_cert, self.client_key, [mssv_1, mssv_2]
            )
        )
        t_srv.start()
        t_cli.start()
        t_srv.join(timeout=3)
        t_cli.join(timeout=3)

        c_sock.close()
        s_sock.close()

        all_wire_bytes = bytes(c_sock.recorded_sent) + bytes(s_sock.recorded_sent)
        self.assertNotIn(
            mssv_1.encode(),
            all_wire_bytes,
            f"MSSV {mssv_1} MUST NOT appear in plaintext on the wire!",
        )
        self.assertNotIn(
            mssv_2.encode(),
            all_wire_bytes,
            f"MSSV {mssv_2} MUST NOT appear in plaintext on the wire!",
        )

    def test_replay_init_rejected(self):
        # 1. Complete valid handshake once and capture the INIT packet
        raw_c_sock, raw_s_sock = socket.socketpair()
        c_sock = InterceptingSocket(raw_c_sock)

        t_srv = threading.Thread(
            target=lambda: handshake.server_handshake(
                raw_s_sock, self.ca_cert, self.srv_cert, self.srv_key
            )
        )
        t_cli = threading.Thread(
            target=lambda: handshake.client_handshake(
                c_sock, self.ca_cert, self.client_cert, self.client_key, ["2312345", "2312346"]
            )
        )
        t_srv.start()
        t_cli.start()
        t_srv.join(timeout=3)
        t_cli.join(timeout=3)
        c_sock.close()
        raw_s_sock.close()

        captured_sent = bytes(c_sock.recorded_sent)

        # 2. Start a new server handshake and replay captured data to it
        c_replay, s_new = socket.socketpair()
        server_err = []

        def run_new_server():
            try:
                handshake.server_handshake(s_new, self.ca_cert, self.srv_cert, self.srv_key)
            except Exception as e:
                server_err.append(e)

        t_srv2 = threading.Thread(target=run_new_server)
        t_srv2.start()

        # Read HELLO from new server
        _ = framing.recv_frame(c_replay)
        # Replay the old INIT frame (which was sent in response to the old HELLO)
        c_replay.sendall(captured_sent)

        t_srv2.join(timeout=3)
        c_replay.close()
        s_new.close()

        self.assertEqual(len(server_err), 1)
        # The new server nonce is different, so the signature verification on T fails
        self.assertIn("Chữ ký HANDSHAKE_INIT không hợp lệ", str(server_err[0]))


if __name__ == "__main__":
    unittest.main()
