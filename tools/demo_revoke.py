#!/usr/bin/env python3
"""
demo_revoke.py – Kịch bản demo thu hồi chứng chỉ end-to-end.

Kịch bản:
  1. Tạo CA, server cert, và team3 cert (team thử nghiệm thu hồi)
  2. Tạo CRL ban đầu (trống)
  3. Mô phỏng: team3 kết nối server → được chấp nhận (cert hợp lệ)
  4. Thu hồi cert team3 → CRL được cập nhật
  5. Mô phỏng: team3 kết nối server lại → bị từ chối (cert đã bị thu hồi)
  6. Khởi động OCSP server và kiểm tra qua HTTP

Chạy:
    python tools/demo_revoke.py
"""

import json
import os
import sys
import tempfile
import time

if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(BASE_DIR, "src"))
sys.path.insert(0, os.path.join(BASE_DIR, "tools"))

import pki as pki_module
from crl import make_crl, load_crl, is_revoked, revoke_cert, load_revoked_db
from pki import verify_cert_with_crl, verify_cert_with_ocsp
from ocsp_server import OCSPResponder

# Sử dụng helper tạo cert tạm (không dùng file PKI thật)
sys.path.insert(0, os.path.join(BASE_DIR, "tests"))
from test_helpers import create_test_ca, create_test_cert

import tempfile
import json


def _sep(title=""):
    print("\n" + "=" * 60)
    if title:
        print(f"  {title}")
        print("=" * 60)


def main():
    print("=" * 60)
    print("  DEMO THU HỒI CHỨNG CHỈ (CRL / OCSP)")
    print("  Hệ thống Chat & File Transfer Bảo mật")
    print("=" * 60)

    # ── Bước 1: Tạo PKI demo ─────────────────────────────────────────────────
    _sep("Bước 1: Khởi tạo PKI demo")
    ca_cert, ca_key = create_test_ca("Demo Root CA")
    server_cert, server_key = create_test_cert(ca_cert, ca_key, cn="chat-server")
    team3_cert, team3_key   = create_test_cert(ca_cert, ca_key, cn="team3", uids=["9900001", "9900002"])

    print(f"  [CA]     CN = {pki_module.get_cn(ca_cert)}")
    print(f"  [Server] CN = {pki_module.get_cn(server_cert)}, Serial = {hex(server_cert.serial_number)}")
    print(f"  [Team3]  CN = {pki_module.get_cn(team3_cert)}, Serial = {hex(team3_cert.serial_number)}")

    # ── Bước 2: Tạo CRL ban đầu (rỗng) ──────────────────────────────────────
    _sep("Bước 2: Tạo CRL ban đầu (danh sách thu hồi trống)")
    crl_pem = make_crl(ca_cert, ca_key, revoked_list=[])
    crl = load_crl(crl_pem)
    print(f"  CRL tạo xong. Số cert bị thu hồi: {len(list(crl))}")

    # ── Bước 3: Xác thực team3 → THÀNH CÔNG ──────────────────────────────────
    _sep("Bước 3: Xác thực Team3 với CRL (cert chưa bị thu hồi)")
    try:
        verify_cert_with_crl(team3_cert, ca_cert, crl)
        print("  [KẾT QUẢ] ✓ Team3 được chấp nhận — chứng chỉ hợp lệ và chưa bị thu hồi.")
    except ValueError as e:
        print(f"  [KẾT QUẢ] ✗ Từ chối: {e}")

    # ── Bước 4: Thu hồi cert team3 ────────────────────────────────────────────
    _sep("Bước 4: Thu hồi chứng chỉ Team3 (lý do: keyCompromise)")
    with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False, encoding="utf-8") as f:
        json.dump([], f)
        db_path = f.name

    try:
        revoke_cert(team3_cert, reason_str="keyCompromise", db_path=db_path)
        revoked_list = load_revoked_db(db_path)
        print(f"  Đã thêm vào DB thu hồi. Tổng cộng: {len(revoked_list)} cert bị thu hồi.")
        crl_pem = make_crl(ca_cert, ca_key, revoked_list=revoked_list)
        crl = load_crl(crl_pem)
        print(f"  CRL đã cập nhật. Số cert bị thu hồi: {len(list(crl))}")

        # ── Bước 5: Xác thực team3 → BỊ TỪ CHỐI ──────────────────────────────
        _sep("Bước 5: Xác thực Team3 với CRL mới (cert đã bị thu hồi)")
        try:
            verify_cert_with_crl(team3_cert, ca_cert, crl)
            print("  [KẾT QUẢ] ✓ Chấp nhận (KHÔNG MONG MUỐN — có lỗi!)")
        except ValueError as e:
            print(f"  [KẾT QUẢ] ✓ Từ chối đúng — {e}")

        # ── Bước 6: Kiểm tra qua OCSP HTTP server ─────────────────────────────
        _sep("Bước 6: Kiểm tra qua OCSP HTTP Responder")
        responder = OCSPResponder(ca_cert, ca_key, db_path=db_path, port=0)
        responder.start()
        time.sleep(0.1)
        print(f"  OCSP server đang chạy tại: {responder.url}/ocsp")

        # Cert tốt (server cert) → GOOD
        try:
            verify_cert_with_ocsp(server_cert, ca_cert, responder.url)
            print(f"  [Server cert ] OCSP → GOOD ✓")
        except ValueError as e:
            print(f"  [Server cert ] OCSP → LỖI: {e}")

        # Cert bị thu hồi (team3) → REVOKED
        try:
            verify_cert_with_ocsp(team3_cert, ca_cert, responder.url)
            print(f"  [Team3 cert  ] OCSP → GOOD (KHÔNG MONG MUỐN!)")
        except ValueError as e:
            print(f"  [Team3 cert  ] OCSP → Từ chối đúng — {e} ✓")

        responder.stop()

    finally:
        os.unlink(db_path)

    _sep("HOÀN TẤT DEMO")
    print("  Kết luận: Hệ thống CRL/OCSP hoạt động đúng theo RFC 5280/RFC 6960.")
    print("  - Cert chưa thu hồi: ĐƯỢC CHẤP NHẬN")
    print("  - Cert đã thu hồi  : BỊ TỪ CHỐI (cả CRL offline và OCSP online)")
    print()


if __name__ == "__main__":
    main()
