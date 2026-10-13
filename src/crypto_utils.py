from typing import Tuple

from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend


def gen_rsa_keypair(key_size: int = 2048) -> Tuple [object, object]:
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )
    return private_key, private_key.public_key()

def serialize_public_key(public_key: object) -> bytes:
    #turn public key to pem for network tranfer
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def deserialize_public_key(key_bytes: bytes) -> object:
    return serialization.load_pem_public_key(
        key_bytes,
        backend=default_backend()
    )


def rsa_encrypt(data: bytes, public_key: object) -> bytes:
    # Encrypt session key
    return public_key.encrypt(
        data,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def rsa_decrypt(cypertext: bytes, private_key : object) -> bytes:
    #decrypt session key 
    return private_key.decrypt(
        cypertext,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )