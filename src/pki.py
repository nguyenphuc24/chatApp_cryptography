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
    try:     
        with open(path, "rb") as f:
            return load_cert(f.read())
    except Exception as e:
        print("Chưa đăng kí cert với CA")


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
    usage: str | None = None,
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
        ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound:
        if usage is not None:
            raise ValueError("Chứng chỉ thiếu extension KeyUsage.")
        ku = None
    if ku is not None:
        if not (ku.digital_signature or ku.key_encipherment):
            raise ValueError(
                "Chứng chỉ thiếu KeyUsage phù hợp (cần digital_signature hoặc key_encipherment)."
            )
        if usage == "server" and not ku.key_encipherment:
            raise ValueError("Chứng chỉ máy chủ thiếu quyền key_encipherment.")
        if usage == "client" and not ku.digital_signature:
            raise ValueError("Chứng chỉ máy khách thiếu quyền digital_signature.")


# ─── Kiểm tra thu hồi (CRL / OCSP) ───────────────────────────────────────────

def verify_cert_with_crl(
    cert: x509.Certificate,
    ca_cert: x509.Certificate,
    crl,                         # x509.CertificateRevocationList
    expected_cn: str | None = None,
    usage: str | None = None,
) -> None:
    """
    Kiểm tra chứng chỉ đầy đủ, bao gồm kiểm tra CRL offline.

    Ném ValueError nếu:
      - Chứng chỉ không hợp lệ (theo verify_cert).
      - Chứng chỉ nằm trong CRL (đã bị thu hồi).
      - CRL hết hạn (nextUpdate đã qua).
    """
    # 1. Kiểm tra cơ bản trước
    verify_cert(cert, ca_cert, expected_cn=expected_cn, usage=usage)

    # 2. Kiểm tra thời hạn CRL
    now = datetime.datetime.now(datetime.timezone.utc)
    try:
        next_update = crl.next_update_utc
    except AttributeError:
        nu = crl.next_update
        next_update = nu.replace(tzinfo=datetime.timezone.utc) if nu.tzinfo is None else nu
    if next_update < now:
        raise ValueError(
            f"CRL đã hết hạn (nextUpdate={next_update.isoformat()}). Hãy cập nhật CRL."
        )

    # 3. Kiểm tra serial trong CRL
    revoked = crl.get_revoked_certificate_by_serial_number(cert.serial_number)
    if revoked is not None:
        serial_hex = hex(cert.serial_number)
        cn = get_cn(cert)
        raise ValueError(
            f"Chứng chỉ đã bị thu hồi: CN='{cn}', Serial={serial_hex}"
        )


def verify_cert_with_ocsp(
    cert: x509.Certificate,
    ca_cert: x509.Certificate,
    ocsp_url: str,
    expected_cn: str | None = None,
    usage: str | None = None,
) -> None:
    """
    Kiểm tra chứng chỉ đầy đủ, bao gồm kiểm tra OCSP online.

    Ném ValueError nếu:
      - Chứng chỉ không hợp lệ (theo verify_cert).
      - OCSP trả về trạng thái REVOKED.
      - Không kết nối được OCSP server (timeout/lỗi mạng).
    """
    import urllib.request
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.x509 import ocsp

    # 1. Kiểm tra cơ bản trước
    verify_cert(cert, ca_cert, expected_cn=expected_cn, usage=usage)

    # 2. Tạo OCSP Request
    builder = ocsp.OCSPRequestBuilder().add_certificate(cert, ca_cert, hashes.SHA256())
    ocsp_req = builder.build()
    req_der  = ocsp_req.public_bytes(serialization.Encoding.DER)

    # 3. Gửi HTTP POST đến OCSP server
    try:
        req = urllib.request.Request(
            url=ocsp_url.rstrip("/") + "/ocsp",
            data=req_der,
            headers={"Content-Type": "application/ocsp-request"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            resp_der = resp.read()
    except Exception as exc:
        raise ValueError(f"Không kết nối được OCSP server tại {ocsp_url}: {exc}") from exc

    # 4. Parse OCSP Response
    ocsp_resp = ocsp.load_der_ocsp_response(resp_der)
    if ocsp_resp.response_status != ocsp.OCSPResponseStatus.SUCCESSFUL:
        raise ValueError(f"OCSP server trả về lỗi: {ocsp_resp.response_status}")

    cert_status = ocsp_resp.certificate_status
    if cert_status == ocsp.OCSPCertStatus.REVOKED:
        cn = get_cn(cert)
        serial_hex = hex(cert.serial_number)
        raise ValueError(
            f"OCSP: Chứng chỉ đã bị thu hồi: CN='{cn}', Serial={serial_hex}"
        )
    elif cert_status == ocsp.OCSPCertStatus.UNKNOWN:
        raise ValueError(
            f"OCSP: Chứng chỉ không được CA này nhận biết (UNKNOWN)."
        )
    # GOOD → OK
