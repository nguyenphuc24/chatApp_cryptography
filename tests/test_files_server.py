"""
test_files_server.py – Kiểm thử logic lưu trữ và an toàn file phía server:
  - validate_filename: chấp nhận tên hợp lệ, chặn path traversal (../), tên bắt đầu bằng '.', ký tự cấm
  - _unique_name: chống ghi đè, tự động thêm số thứ tự 'file (1).ext', 'file (2).ext'
  - Server file transfer lifecycle: dọn dẹp file tạm .tmp_* khi số chunk không khớp hoặc upload bị huỷ
"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from e2e import validate_filename
from server import _unique_name, SecureChatServer


class TestFilesServer(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.storage_dir = self.tmp_dir.name

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_validate_filename_valid(self):
        valid_names = [
            "document.pdf",
            "report_2026.docx",
            "archive-v1.0.tar.gz",
            "my_data_file.csv",
            "image123.PNG",
        ]
        for name in valid_names:
            self.assertEqual(validate_filename(name), name)

    def test_validate_filename_path_traversal(self):
        bad_names = [
            "../secret.txt",
            "..\\windows_file.txt",
            "/etc/passwd",
            "C:\\boot.ini",
            "..",
            ".",
        ]
        for name in bad_names:
            with self.assertRaises(ValueError, msg=f"Should reject traversal: {name}"):
                validate_filename(name)

    def test_validate_filename_hidden_or_empty(self):
        bad_names = [
            ".bashrc",
            ".gitignore",
            "",
            "   ",
        ]
        for name in bad_names:
            with self.assertRaises(ValueError, msg=f"Should reject: {name}"):
                validate_filename(name)

    def test_validate_filename_illegal_chars(self):
        bad_names = [
            "file;rm -rf /",
            "file|pipe.txt",
            "file*wildcard.txt",
            "file\x00null.txt",
            "file name with spaces.txt",
        ]
        for name in bad_names:
            with self.assertRaises(ValueError, msg=f"Should reject illegal chars: {name}"):
                validate_filename(name)

    def test_unique_name_prevents_overwrite(self):
        name = "data.txt"
        # First file: data.txt
        u1 = _unique_name(self.storage_dir, name)
        self.assertEqual(u1, "data.txt")
        # Simulate saving data.txt.json
        with open(os.path.join(self.storage_dir, u1 + ".json"), "w") as f:
            f.write("{}")

        # Second file with same name -> data (1).txt
        u2 = _unique_name(self.storage_dir, name)
        self.assertEqual(u2, "data (1).txt")
        with open(os.path.join(self.storage_dir, u2 + ".json"), "w") as f:
            f.write("{}")

        # Third file -> data (2).txt
        u3 = _unique_name(self.storage_dir, name)
        self.assertEqual(u3, "data (2).txt")

    def test_temp_file_cleanup_on_mismatched_chunks(self):
        server = SecureChatServer(storage_dir=self.storage_dir)

        # Mock an upload state with declared chunks = 2, but only 1 received
        tmp_path = os.path.join(self.storage_dir, ".tmp_test123.json")
        with open(tmp_path, "w") as f:
            f.write("partial data")

        upload = {
            "meta": {"name": "test.txt", "chunks": 2, "size": 100},
            "chunks": [{"idx": 0, "data": "aabb"}],  # only 1 chunk
            "tmp": tmp_path,
            "name": "test.txt",
            "sender": "team1",
        }

        # Cancel upload should remove the temporary file
        server._cancel_upload(upload)
        self.assertFalse(
            os.path.exists(tmp_path), "Cancelled upload must clean up temporary .tmp_* file"
        )


if __name__ == "__main__":
    unittest.main()
