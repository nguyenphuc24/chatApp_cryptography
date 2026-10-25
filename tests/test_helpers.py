"""
test_helpers.py – Các hàm hỗ trợ sinh chứng chỉ và khoá trong bộ nhớ cho unittest.
"""

import datetime
import os
import sys

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))


def gen_key(key_size: int = 2048) -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend(),
    )


def create_test_ca(common_name: str = "Test Root CA") -> tuple[x509.Certificate, rsa.RSAPrivateKey]:
    key = gen_key()
    now = datetime.datetime.now(datetime.timezone.utc)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "VN"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256(), default_backend())
    )
    return cert, key


def create_test_cert(
    ca_cert: x509.Certificate,
    ca_key: rsa.RSAPrivateKey,
    cn: str,
    uids: list[str] | None = None,
    is_ca: bool = False,
    validity_days: int = 365,
    start_days_offset: int = 0,
) -> tuple[x509.Certificate, rsa.RSAPrivateKey]:
    key = gen_key()
    now = datetime.datetime.now(datetime.timezone.utc)
    not_before = now + datetime.timedelta(days=start_days_offset)
    not_after = not_before + datetime.timedelta(days=validity_days)

    attrs = [
        x509.NameAttribute(NameOID.COUNTRY_NAME, "VN"),
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ]
    if uids:
        for uid in uids:
            attrs.append(x509.NameAttribute(NameOID.USER_ID, uid))

    subject = x509.Name(attrs)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=is_ca, path_length=None), critical=True)
    )
    cert = builder.sign(ca_key, hashes.SHA256(), default_backend())
    return cert, key
