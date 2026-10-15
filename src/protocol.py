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