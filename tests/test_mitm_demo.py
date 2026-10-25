"""
test_mitm_demo.py – Man-in-the-Middle (MitM) attack demonstration tests:
  - Scenario 1: MitM Proxy replaces server certificate with a rogue certificate
    -> Client verifies server cert against trusted CA root, detects invalid signature, and terminates immediately.
  - Scenario 2: Active MitM modifies wire ciphertext in transit after handshake
    -> Receiver's Encrypt-then-MAC layer detects corrupted HMAC and drops connection immediately.
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
from test_helpers import create_test_ca, create_test_cert


class TestMitMDemo(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # 1. Trusted PKI
        cls.trusted_ca_cert, cls.trusted_ca_key = create_test_ca("Trusted University Root CA")
        cls.real_srv_cert, cls.real_srv_key = create_test_cert(
            cls.trusted_ca_cert, cls.trusted_ca_key, cn="chat-server"
        )
        cls.client_cert, cls.client_key = create_test_cert(
            cls.trusted_ca_cert, cls.trusted_ca_key, cn="team1", uids=["2312345"]
        )

        # 2. Rogue attacker PKI
        cls.eve_ca_cert, cls.eve_ca_key = create_test_ca("Eve Rogue Root CA")
        cls.fake_srv_cert, cls.fake_srv_key = create_test_cert(
            cls.eve_ca_cert, cls.eve_ca_key, cn="chat-server"
        )

    def test_mitm_cert_substitution_prevented(self):
        """
        Scenario 1: Attacker intercepts handshake and presents a certificate signed by rogue CA.
        Client detects the untrusted certificate signature and aborts handshake.
        """
        c_sock, proxy_c_sock = socket.socketpair()
        client_errors = []

        def client_thread():
            try:
                handshake.client_handshake(
                    c_sock,
                    self.trusted_ca_cert,
                    self.client_cert,
                    self.client_key,
                    ["2312345"],
                )
            except Exception as e:
                client_errors.append(str(e))
            finally:
                c_sock.close()

        def mitm_proxy_thread():
            try:
                # Proxy sends fake server cert signed by rogue CA
                handshake.server_handshake(
                    proxy_c_sock,
                    self.trusted_ca_cert,
                    self.fake_srv_cert,
                    self.fake_srv_key,
                )
            except Exception:
                pass
            finally:
                proxy_c_sock.close()

        t_cli = threading.Thread(target=client_thread)
        t_mitm = threading.Thread(target=mitm_proxy_thread)

        t_cli.start()
        t_mitm.start()

        t_cli.join(timeout=3)
        t_mitm.join(timeout=3)

        self.assertEqual(len(client_errors), 1)
        self.assertIn("Chữ ký chứng chỉ không hợp lệ", client_errors[0])

    def test_mitm_wire_tampering_prevented(self):
        """
        Scenario 2: Active attacker flips 1 byte on the wire during message transmission.
        EtM HMAC check fails and connection is torn down immediately.
        """
        c_sock, s_sock = socket.socketpair()
        c_session = None
        s_session = None

        def run_server():
            nonlocal s_session
            s_session = handshake.server_handshake(
                s_sock, self.trusted_ca_cert, self.real_srv_cert, self.real_srv_key
            )

        def run_client():
            nonlocal c_session
            c_session = handshake.client_handshake(
                c_sock, self.trusted_ca_cert, self.client_cert, self.client_key, ["2312345"]
            )

        t_s = threading.Thread(target=run_server)
        t_c = threading.Thread(target=run_client)
        t_s.start()
        t_c.start()
        t_s.join(timeout=3)
        t_c.join(timeout=3)

        self.assertIsNotNone(c_session)
        self.assertIsNotNone(s_session)

        # Connect a proxy bridge between client socket and server socket for a post-handshake message
        # We simulate the wire tampering directly by reading from socket, altering byte, and delivering
        c_session.send("E2E_MSG", {"text": "Transfer 1000 USD to Bob"}, sender="team1")

        # Read the raw frame that client sent to s_sock
        raw_frame = framing.recv_frame(s_sock)
        self.assertIsNotNone(raw_frame)
        tampered_frame = bytearray(raw_frame)
        tampered_frame[20] ^= 0x01  # Flip bit

        # Re-inject the tampered frame back into a new socketpair where s_session listens
        sock_fake_in, sock_fake_out = socket.socketpair()
        s_session.sock = sock_fake_out
        framing.send_frame(sock_fake_in, bytes(tampered_frame))

        tampered_result = s_session.recv()
        self.assertIsNone(tampered_result, "Server must reject tampered frame and return None")
        self.assertTrue(s_session.closed)

        sock_fake_in.close()
        sock_fake_out.close()
        c_sock.close()
        s_sock.close()
        c_session.close()
        s_session.close()


if __name__ == "__main__":
    unittest.main()
