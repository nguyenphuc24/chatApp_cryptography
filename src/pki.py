"""
pki.py – Nạp và kiểm tra chứng chỉ X.509 (dùng chung bởi server và client).

API công khai:
    load_cert(pem: bytes) -> x509.Certificate
    load_cert_from_file(path: str) -> x509.Certificate
    load_private_key(pem: bytes, password=None) -> RSAPrivateKey
    load_private_key_from_file(path: str, password=None) -> RSAPrivateKey
    cert_to_pem(cert) -> str
    cert_to_der(cert) -> bytes
    get_cn(cert) -> str
    get_uids(cert) -> list[str]
    verify_cert(cert, ca_cert, expected_cn=None) -> None
        Ném ValueError nếu không hợp lệ.
"""

import datetime

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding, rsa
from cryptography.x509.oid import NameOID


# ─── Nạp chứng chỉ ────────────────────────────────────────────────────────────

def load_cert(pem: bytes) -> x509.Certificate:
    """Nạp chứng chỉ từ PEM bytes."""
    return x509.load_pem_x509_certificate(pem, default_backend())


def load_cert_from_file(path: str) -> x509.Certificate:
    """Nạp chứng chỉ từ file PEM."""
    with open(path, "rb") as f:
        return load_cert(f.read())


def load_private_key(pem: bytes, password=None):
    """Nạp khoá riêng từ PEM bytes."""
    return serialization.load_pem_private_key(
        pem, password=password, backend=default_backend()
    )


def load_private_key_from_file(path: str, password=None):
    """Nạp khoá riêng từ file PEM."""
    with open(path, "rb") as f:
        return load_private_key(f.read(), password=password)


# ─── Chuyển đổi ────────────────────────────────────────────────────────────────

def cert_to_pem(cert: x509.Certificate) -> str:
    """Chuyển chứng chỉ sang chuỗi PEM (để truyền qua mạng)."""
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def cert_to_der(cert: x509.Certificate) -> bytes:
    """Chuyển chứng chỉ sang DER bytes (để băm khi ký)."""
    return cert.public_bytes(serialization.Encoding.DER)


# ─── Đọc trường Subject ────────────────────────────────────────────────────────

def get_cn(cert: x509.Certificate) -> str:
    """Trả về giá trị CN trong Subject. Chuỗi rỗng nếu không có."""
    attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    return attrs[0].value if attrs else ""


def get_uids(cert: x509.Certificate) -> list[str]:
    """
    Trả về danh sách UID trong Subject (mỗi MSSV là một UID).
    Thứ tự giống thứ tự trong Subject.
    """
    attrs = cert.subject.get_attributes_for_oid(NameOID.USER_ID)
    return [a.value for a in attrs]


# ─── Kiểm tra chứng chỉ ────────────────────────────────────────────────────────

def _cert_not_before(cert: x509.Certificate) -> datetime.datetime:
    """Lấy not_valid_before dạng timezone-aware (tương thích nhiều phiên bản)."""
    try:
        return cert.not_valid_before_utc
    except AttributeError:
        return cert.not_valid_before.replace(tzinfo=datetime.timezone.utc)


def _cert_not_after(cert: x509.Certificate) -> datetime.datetime:
    """Lấy not_valid_after dạng timezone-aware (tương thích nhiều phiên bản)."""
    try:
        return cert.not_valid_after_utc
    except AttributeError:
        return cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)


def verify_cert(
    cert: x509.Certificate,
    ca_cert: x509.Certificate,
    expected_cn: str | None = None,
) -> None:
    """
    Kiểm tra chứng chỉ toàn diện:
      1. Còn trong thời hạn hiệu lực.
      2. Không phải CA (BasicConstraints.ca = False hoặc không có BasicConstraints).
      3. Được ký bởi ca_cert (chữ ký RSA-PKCS1v15-SHA256).
      4. CN khớp expected_cn (nếu được truyền vào).

    Ném ValueError nếu bất kỳ điều kiện nào không thoả.
    """
    now = datetime.datetime.now(datetime.timezone.utc)

    # 1. Kiểm tra hạn sử dụng
    not_before = _cert_not_before(cert)
    not_after  = _cert_not_after(cert)
    if not_before > now:
        raise ValueError(
            f"Chứng chỉ chưa có hiệu lực (not_valid_before={not_before.isoformat()})"
        )
    if not_after < now:
        raise ValueError(
            f"Chứng chỉ đã hết hạn (not_valid_after={not_after.isoformat()})"
        )

    # 2. Không phải CA
    try:
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        if bc.value.ca:
            raise ValueError("Chứng chỉ là CA certificate, không dùng làm leaf.")
    except x509.ExtensionNotFound:
        pass  # Không có BasicConstraints → OK, không phải CA

    # 3. Kiểm tra chữ ký của CA
    ca_pub = ca_cert.public_key()
    if not isinstance(ca_pub, rsa.RSAPublicKey):
        raise ValueError(f"Chỉ hỗ trợ CA dùng RSA (nhận: {type(ca_pub).__name__})")
    try:
        ca_pub.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            asym_padding.PKCS1v15(),
            cert.signature_hash_algorithm,
        )
    except InvalidSignature:
        raise ValueError("Chữ ký chứng chỉ không hợp lệ (không phải do CA này ký).")

    # 4. Kiểm tra CN
    if expected_cn is not None:
        cn = get_cn(cert)
        if cn != expected_cn:
            raise ValueError(
                f"CN không khớp: kỳ vọng '{expected_cn}', nhận được '{cn}'"
            )

    # 5. Kiểm tra KeyUsage (nếu có extension)
    try:
        ku = cert.extensions.get_extension_for_class(x509.KeyUsage)
        if not (ku.value.digital_signature or ku.value.key_encipherment):
            raise ValueError(
                "Chứng chỉ thiếu KeyUsage phù hợp (cần digital_signature hoặc key_encipherment)."
            )
    except x509.ExtensionNotFound:
        pass  # Không có KeyUsage extension → chấp nhận
