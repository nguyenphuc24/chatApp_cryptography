#!/usr/bin/env python3
"""
demo_webserver.py – Demo Web Server HTTPS/TLS cấp phát chứng chỉ bởi CA nội bộ.

Mục tiêu (Mục 1.2 Đề bài):
  "Hệ thống CA hoạt động thực tế, cấp phát chứng thư cho Web Server (HTTPS/TLS)
   kèm kịch bản thử nghiệm xác thực."

Chức năng:
  1. Khởi động Web Server phục vụ HTTPS tại https://127.0.0.1:8443
  2. Sử dụng chứng chỉ pki/server.crt và khóa riêng pki/server.key do Root CA ký
  3. Hỗ trợ chế độ --test: Tự động kết nối HTTPS, xác minh chứng chỉ với pki/ca.crt
     và in chuỗi chứng thư số thực nghiệm.

Chạy:
  # Chạy máy chủ HTTPS:
  python tools/demo_webserver.py

  # Chạy kiểm thử xác thực tự động:
  python tools/demo_webserver.py --test
"""

import argparse
import http.server
import os
import ssl
import sys
import threading
import time
import urllib.request

if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

BASE_DIR   = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WEB_DIR    = os.path.join(BASE_DIR, "web")
PKI_DIR    = os.path.join(BASE_DIR, "pki")
CA_CRT     = os.path.join(PKI_DIR, "ca.crt")
SERVER_CRT = os.path.join(PKI_DIR, "server.crt")
SERVER_KEY = os.path.join(PKI_DIR, "server.key")


class SecureHandler(http.server.SimpleHTTPRequestHandler):
    """Handler phục vụ các tệp tĩnh trong thư mục web/."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=WEB_DIR, **kwargs)

    def log_message(self, format, *args):
        ts = time.strftime("%H:%M:%S")
        sys.stdout.write(f"[{ts}] [HTTPS WebServer] {format % args}\n")
        sys.stdout.flush()


def run_server(port: int = 8443, host: str = "127.0.0.1"):
    if not os.path.exists(SERVER_CRT) or not os.path.exists(SERVER_KEY):
        print(f"[LỖI] Không tìm thấy chứng chỉ hoặc khóa: {SERVER_CRT}, {SERVER_KEY}")
        print("Vui lòng chạy 'python tools/make_pki.py' trước để sinh hạ tầng PKI.")
        sys.exit(1)

    # Cấu hình SSL/TLS context cho Server
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    # Ràng buộc TLS >= 1.2
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certfile=SERVER_CRT, keyfile=SERVER_KEY)

    server_address = (host, port)
    httpd = http.server.HTTPServer(server_address, SecureHandler)
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)

    print("=" * 65)
    print("  DEMO WEB SERVER HTTPS / TLS (X.509 CA-ISSUED CERTIFICATE)")
    print("=" * 65)
    print(f"  Địa chỉ phục vụ  : https://{host}:{port}/")
    print(f"  Chứng chỉ Server : {os.path.relpath(SERVER_CRT, BASE_DIR)}")
    print(f"  Root CA xác thực : {os.path.relpath(CA_CRT, BASE_DIR)}")
    print(f"  Thư mục tài nguyên: {os.path.relpath(WEB_DIR, BASE_DIR)}")
    print("  Nhấn Ctrl+C để dừng máy chủ.")
    print("=" * 65)

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[HTTPS WebServer] Nhận Ctrl+C. Đang dừng máy chủ...")
    finally:
        httpd.server_close()
        print("[HTTPS WebServer] Máy chủ đã tắt an toàn.")


def run_verification_test(port: int = 8443, host: str = "127.0.0.1"):
    """Kịch bản thử nghiệm xác thực HTTPS với Root CA nội bộ."""
    print("=" * 65)
    print("  KIỂM THỬ XÁC THỰC HTTPS VỚI ROOT CA NỘI BỘ (TEST CLIENT)")
    print("=" * 65)

    # 1. Khởi động Web Server trong thread nền
    server_thread = threading.Thread(target=run_server, args=(port, host), daemon=True)
    server_thread.start()
    time.sleep(0.5)

    url = f"https://{host}:{port}/"
    print(f"\n[1] Gửi yêu cầu HTTPS GET tới: {url}")
    print(f"[2] Sử dụng CA Bundle: {CA_CRT}")

    # Tạo SSL Context cho client chỉ tin tưởng Root CA nội bộ
    client_ctx = ssl.create_default_context(cafile=CA_CRT)

    try:
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, context=client_ctx, timeout=5) as response:
            status = response.status
            body = response.read().decode("utf-8")

        print(f"[3] Kết nối HTTPS thành công! HTTP Status: {status}")
        self_check = "Hạ tầng Khóa Công khai" in body
        print(f"[4] Nội dung HTML phản hồi hợp lệ: {self_check}")
        print("\n" + "=" * 65)
        print("  XÁC NHẬN: CHỨNG CHỈ WEB SERVER ĐƯỢC ROOT CA CẤP PHÁT VÀ XÁC THỰC!")
        print("=" * 65)
        return True
    except ssl.SSLCertVerificationError as e:
        print(f"[LỖI XÁC THỰC CHỨNG CHỈ] {e}")
        return False
    except Exception as e:
        print(f"[LỖI KẾT NỐI] {e}")
        return False


def main():
    parser = argparse.ArgumentParser(description="Demo Web Server HTTPS dùng chứng chỉ do CA cấp")
    parser.add_argument("--port", type=int, default=8443, help="Cổng HTTPS (mặc định: 8443)")
    parser.add_argument("--host", default="127.0.0.1", help="Địa chỉ host (mặc định: 127.0.0.1)")
    parser.add_argument("--test", action="store_true", help="Chạy kịch bản tự động kiểm thử xác thực HTTPS")
    args = parser.parse_args()

    if args.test:
        success = run_verification_test(port=args.port, host=args.host)
        sys.exit(0 if success else 1)
    else:
        run_server(port=args.port, host=args.host)


if __name__ == "__main__":
    main()

