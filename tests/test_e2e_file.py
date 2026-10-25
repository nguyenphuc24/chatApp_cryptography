"""
test_e2e_file.py – Kiểm thử mã hoá đầu cuối truyền file (E2E File):
  - Chuẩn bị file và lắp ráp file roundtrip thành công
  - SHA-256 sai -> từ chối (trả về None)
  - Chunk đảo thứ tự -> từ chối (trả về None)
  - Thiếu chunk -> từ chối (trả về None)
  - Vượt quá MAX_FILE (10 MiB) -> ValueError
  - Người nhận không có wrap -> từ chối (trả về None)
"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

import e2e
from test_helpers import create_test_ca, create_test_cert


class TestE2EFile(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ca_cert, cls.ca_key = create_test_ca("File Test CA")

        cls.alice_cert, cls.alice_key = create_test_cert(cls.ca_cert, cls.ca_key, cn="alice")
        cls.bob_cert, cls.bob_key = create_test_cert(cls.ca_cert, cls.ca_key, cn="bob")
        cls.eve_cert, cls.eve_key = create_test_cert(cls.ca_cert, cls.ca_key, cn="eve")

        cls.roster = {
            "alice": cls.alice_cert,
            "bob": cls.bob_cert,
            "eve": cls.eve_cert,
        }

    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.test_file_path = os.path.join(self.tmp_dir.name, "sample.txt")
        # 12 KiB file to produce 3 chunks of 4 KiB
        self.original_data = b"Hello, secure world! " * 600
        with open(self.test_file_path, "wb") as f:
            f.write(self.original_data)

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_file_e2e_roundtrip(self):
        recipients = {"bob": self.bob_cert, "alice": self.alice_cert}
        meta, chunks = e2e.e2e_prepare_file(
            path=self.test_file_path,
            my_cn="alice",
            seq=1,
            my_priv_key=self.alice_key,
            recipients=recipients,
        )

        self.assertEqual(meta["chunks"], len(chunks))

        bob_last_seq = {}
        assembled = e2e.e2e_assemble_file(
            meta=meta,
            chunks=chunks,
            my_cn="bob",
            my_priv_key=self.bob_key,
            roster=self.roster,
            sender_cn="alice",
            last_file_seq=bob_last_seq,
        )
        self.assertEqual(assembled, self.original_data)
        self.assertEqual(bob_last_seq.get("alice"), 1)

    def test_corrupted_sha256_rejected(self):
        recipients = {"bob": self.bob_cert}
        meta, chunks = e2e.e2e_prepare_file(
            self.test_file_path, "alice", 1, self.alice_key, recipients
        )

        # Corrupt one chunk payload
        chunk_data = bytearray(bytes.fromhex(chunks[0]["data"]))
        chunk_data[25] ^= 0x01
        chunks[0]["data"] = bytes(chunk_data).hex()

        bob_last_seq = {}
        assembled = e2e.e2e_assemble_file(
            meta=meta,
            chunks=chunks,
            my_cn="bob",
            my_priv_key=self.bob_key,
            roster=self.roster,
            sender_cn="alice",
            last_file_seq=bob_last_seq,
        )
        self.assertIsNone(assembled, "Corrupted chunk or SHA mismatch must cause assemble to return None")

    def test_out_of_order_chunks_rejected(self):
        recipients = {"bob": self.bob_cert}
        meta, chunks = e2e.e2e_prepare_file(
            self.test_file_path, "alice", 1, self.alice_key, recipients
        )

        # Invert chunk index claims
        chunks[0]["idx"] = 1
        chunks[1]["idx"] = 0

        bob_last_seq = {}
        assembled = e2e.e2e_assemble_file(
            meta=meta,
            chunks=chunks,
            my_cn="bob",
            my_priv_key=self.bob_key,
            roster=self.roster,
            sender_cn="alice",
            last_file_seq=bob_last_seq,
        )
        self.assertIsNone(assembled, "Disordered chunks must be rejected")

    def test_missing_chunk_rejected(self):
        recipients = {"bob": self.bob_cert}
        meta, chunks = e2e.e2e_prepare_file(
            self.test_file_path, "alice", 1, self.alice_key, recipients
        )

        # Drop the last chunk
        chunks_incomplete = chunks[:-1]

        bob_last_seq = {}
        assembled = e2e.e2e_assemble_file(
            meta=meta,
            chunks=chunks_incomplete,
            my_cn="bob",
            my_priv_key=self.bob_key,
            roster=self.roster,
            sender_cn="alice",
            last_file_seq=bob_last_seq,
        )
        self.assertIsNone(assembled, "Incomplete chunks must be rejected")

    def test_exceeding_max_file_raises(self):
        huge_file_path = os.path.join(self.tmp_dir.name, "huge.bin")
        # Write > 10 MiB
        with open(huge_file_path, "wb") as f:
            f.seek(e2e.MAX_FILE + 10)
            f.write(b"0")

        with self.assertRaises(ValueError) as ctx:
            e2e.e2e_prepare_file(
                huge_file_path, "alice", 1, self.alice_key, {"bob": self.bob_cert}
            )
        self.assertIn("vượt giới hạn MAX_FILE", str(ctx.exception))

    def test_non_recipient_cannot_decrypt_file(self):
        # Alice sends file to Bob only; Eve tries to assemble
        recipients = {"bob": self.bob_cert}
        meta, chunks = e2e.e2e_prepare_file(
            self.test_file_path, "alice", 1, self.alice_key, recipients
        )

        eve_last_seq = {}
        assembled = e2e.e2e_assemble_file(
            meta=meta,
            chunks=chunks,
            my_cn="eve",
            my_priv_key=self.eve_key,
            roster=self.roster,
            sender_cn="alice",
            last_file_seq=eve_last_seq,
        )
        self.assertIsNone(assembled, "Eve without a wrap must not be able to decrypt the file")


if __name__ == "__main__":
    unittest.main()
