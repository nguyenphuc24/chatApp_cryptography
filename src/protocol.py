# {
#   "type"      : "MESSAGE",
#   "sender"    : "client",
#   "payload"   : { "content": "Hello!" },
#   "timestamp" : 1715000000.123,
#   "signature" : "a3f9c1d2..."
# }



import json 
import time
import struct
import socket
import secrets
from enum import Enum

class MessageType(Enum):
    HANDSHAKE_INIT      = 'HANDSHAKE_INIT'
    HANDSHAKE_RESPONSE  = 'HANDSHAKE_RESPONSE'
    HANDSHAKE_ACK       = 'HANDSHAKE_ACK'

    MESSAGE             = 'MESSAGE'
    MESSAGE_ACK         = 'MESSAGE_ACK'

    FILE_TRANSFER_START = "FILE_TRANSFER_START" 
    FILE_TRANSFER_DATA  = "FILE_TRANSFER_DATA"   
    FILE_TRANSFER_END   = "FILE_TRANSFER_END"    

    # Điều khiển
    PING       = "PING"
    PONG       = "PONG"
    DISCONNECT = "DISCONNECT"
    ERROR      = "ERROR"


class Packet:
    def __init__(self, msg_type: str, sender: str, payload: dict[str, object]):
        self.type = msg_type
        self.sender = sender
        self.payload = payload
        self.timestamp =  time.time()
        self.signature = None

    def to_json(self) -> str:
        return json.dumps({
            "type"      : self.type,
            "sender"    : self.sender,
            "payload"   : self.payload,
            "timestamp" : self.timestamp,
            "signature" : self.signature,
        })
    
    def to_bytes(self) -> bytes:
        self.to_json().encode()

    @staticmethod
    def from_json(json_data: str) -> 'Packet':
        data = json.loads(json_data)
        pkt  = Packet(data["type"], data["sender"], data["payload"])
        pkt.timestamp = data.get("timestamp", time.time())
        pkt.signature = data.get("signature")
        return pkt

    @staticmethod
    def from_byte(bytes_stream: bytes) -> 'Packet':
        return Packet.from_json(bytes_stream.decode())



def send_msg(sock: socket.socket, data: bytes) -> None:
    header = struct.pack("!I", len(data))
    sock.sendall(header + data)

def recv_msg(sock: socket.socket) -> bytes | None :
    header = _recv_exact(sock, 4)

    if header is None:
        return None

    n = struct.unpack("!I", header)[0]
    return _recv_exact(sock, n)

def _recv_exact(sock: socket.socket, n: int) -> bytes | None :
    buf = b""
    while len(buf) < n :
        try: 
            chunk = sock.recv(n - len(buf))
        except (socket.timeout, BlockingIOError):
            continue
        except Exception:
            return None
        if not chunk : return None
        buf += chunk
    return buf



def make_handshake_init(client_pub_pem: str, mssv_list: list,
                        encrypted_session_key_hex: str) -> Packet:
    msg = "Hello, We are" + ", ".join(str(m) for m in mssv_list)
    return Packet(MessageType.HANDSHAKE_INIT.value, "client", {
        "message"               : msg,
        "mssv_list"             : [str(m) for m in mssv_list],
        "public_key"            : client_pub_pem,
        "session_key_encrypted" : encrypted_session_key_hex
    })

def make_handshake_response(server_pub_pem: str) -> Packet:
    return Packet(MessageType.HANDSHAKE_RESPONSE.value, "server", {
        "public_key"    : server_pub_pem,
        "server_nonce"  : secrets.token_hex(16) 
    })

def make_handshake_ok() -> Packet:
    return Packet(MessageType.HANDSHAKE_RESPONSE.value, "server", {
        "status" : "HANDSHAKE_OK"
    })

def make_handshake_ack() -> Packet:
    return Packet(MessageType.HANDSHAKE_ACK.value, "client", {"status" : "OK"})

def make_message(content: str, sender: str) -> Packet:
    return Packet(MessageType.MESSAGE.value, sender, {"content": content})


def make_message_ack(sender: str = "server") -> Packet:
    return Packet(MessageType.MESSAGE_ACK.value, sender, {"status": "received"})

def make_file_start(filename: str, filesize: int, checksum_sha256: str) -> Packet:
    return Packet(MessageType.FILE_TRANSFER_START.value, "client", {
        "filename" : filename,
        "filesize" : filesize,
        "checksum" : checksum_sha256,
        "chunk_size": 4096,
    })


def make_file_data(chunk_number: int, chunk_bytes: bytes) -> Packet:
    return Packet(MessageType.FILE_TRANSFER_DATA.value, "client", {
        "chunk_number": chunk_number,
        "data"        : chunk_bytes.hex(),
        "chunk_size"  : len(chunk_bytes),
    })

def make_file_end() -> Packet:
    return Packet(MessageType.FILE_TRANSFER_END.value, "client", {"status": "EOF"})


def make_disconnect(reason: str = "Normal closure") -> Packet:
    return Packet(MessageType.DISCONNECT.value, "client", {"reason": reason})

def make_error(code: int, message: str, sender: str = "server") -> Packet:
    return Packet(MessageType.ERROR.value, sender, {
        "error_code"   : code,
        "error_message": message,
    })