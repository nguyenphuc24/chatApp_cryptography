"""
framing.py – Khung truyền TCP: [ length (4B big-endian) ][ payload ].

Hằng số:
    MAX_FRAME = 64 * 1024  (64 KiB)

Hàm:
    send_frame(sock, data: bytes) -> None
        Gửi frame. Ném ValueError nếu data > MAX_FRAME.
    recv_frame(sock) -> bytes | None
        Nhận frame. Trả về None khi:
          - EOF / kết nối đóng
          - Timeout hoặc lỗi socket
          - Kích thước frame > MAX_FRAME (nguy cơ DoS)
        Caller nên đóng kết nối khi nhận được None.
"""

import socket as _socket
import struct

MAX_FRAME: int = 64 * 1024  # 64 KiB — ngưỡng chống frame quá lớn


class FrameTooLargeError(ValueError):
    """Ném ra khi độ dài frame nhận được vượt quá MAX_FRAME (phòng vệ chống DoS)."""
    pass


def send_frame(sock: _socket.socket, data: bytes) -> None:
    """Gửi một frame: 4-byte header || payload."""
    if len(data) > MAX_FRAME:
        raise FrameTooLargeError(f"Frame quá lớn: {len(data)} bytes > MAX_FRAME={MAX_FRAME}")
    sock.sendall(struct.pack("!I", len(data)) + data)


def recv_frame(sock: _socket.socket) -> bytes | None:
    """
    Nhận đúng một frame. Trả về payload bytes hoặc None khi EOF / đóng kết nối.
    Ném FrameTooLargeError nếu frame vượt quá MAX_FRAME để caller ghi nhận log.
    """
    header = _recv_exact(sock, 4)
    if header is None:
        return None
    n = struct.unpack("!I", header)[0]
    if n > MAX_FRAME:
        # Frame quá lớn → ném lỗi để phân biệt rõ với EOF
        raise FrameTooLargeError(f"Độ dài frame khai báo ({n} bytes) vượt quá MAX_FRAME ({MAX_FRAME} bytes)")
    return _recv_exact(sock, n)


def _recv_exact(sock: _socket.socket, n: int) -> bytes | None:
    """Đọc đúng n bytes từ socket. Trả về None khi EOF, lỗi hoặc timeout."""
    buf = b""
    while len(buf) < n:
        try:
            chunk = sock.recv(n - len(buf))
        except (_socket.timeout, OSError):
            return None
        if not chunk:
            return None  # EOF
        buf += chunk
    return buf
