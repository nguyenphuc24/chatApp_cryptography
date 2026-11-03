"""
crl.py – Quản lý danh sách thu hồi chứng chỉ (Certificate Revocation List - CRL).

Tuân thủ RFC 5280 (X.509 CRL Profile).

API công khai:
    make_crl(ca_cert, ca_key, revoked_list, next_update_hours=24) -> bytes  (PEM)
    load_crl(pem_or_path: bytes | str) -> x509.CertificateRevocationList
    is_revoked(cert, crl) -> bool
    load_revoked_db(db_path: str) -> list[dict]
    save_revoked_db(db_path: str, records: list[dict]) -> None
    revoke_cert(cert, reason_str, db_path) -> None

Cấu trúc DB thu hồi (JSON):
    [
        {
            "serial": "0x1a2b3c...",  # Số serial (hex)
            "revoked_at": "2026-11-03T10:00:00+00:00",  # ISO 8601 UTC
            "reason": "keyCompromise"  # Lý do (RFC 5280 reason codes)
        },
        ...
    ]
"""

import datetime
import json
import os

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID

# ─── Lý do thu hồi (RFC 5280 Section 5.3.1) ──────────────────────────────────

REASON_MAP: dict[str, x509.ReasonFlags] = {
    "unspecified":            x509.ReasonFlags.unspecified,
    "keyCompromise":          x509.ReasonFlags.key_compromise,
    "caCompromise":           x509.ReasonFlags.ca_compromise,
    "affiliationChanged":     x509.ReasonFlags.affiliation_changed,
    "superseded":             x509.ReasonFlags.superseded,
    "cessationOfOperation":   x509.ReasonFlags.cessation_of_operation,
    "certificateHold":        x509.ReasonFlags.certificate_hold,
    "removeFromCRL":          x509.ReasonFlags.remove_from_crl,
    "privilegeWithdrawn":     x509.ReasonFlags.privilege_withdrawn,
    "aACompromise":           x509.ReasonFlags.aa_compromise,
}


# ─── Tạo CRL ─────────────────────────────────────────────────────────────────

def make_crl(
    ca_cert: x509.Certificate,
    ca_key,
    revoked_list: list[dict],
    next_update_hours: int = 24,
) -> bytes:
    """
    Tạo và ký CRL mới theo RFC 5280.

    Args:
        ca_cert:            Chứng chỉ của CA (issuer).
        ca_key:             Khóa riêng của CA để ký CRL.
        revoked_list:       Danh sách dict [{serial, revoked_at, reason}, ...].
        next_update_hours:  CRL hợp lệ trong bao nhiêu giờ kể từ bây giờ.

    Returns:
        CRL dạng PEM bytes.
    """
    now = datetime.datetime.now(datetime.timezone.utc)
    next_update = now + datetime.timedelta(hours=next_update_hours)

    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca_cert.subject)
        .last_update(now)
        .next_update(next_update)
        .add_extension(
            x509.CRLNumber(x509.random_serial_number() % (2**31)),
            critical=False,
        )
    )

    for record in revoked_list:
        serial_hex = record.get("serial", "0x0").lstrip("0x").lstrip("0X") or "0"
        serial_int = int(serial_hex, 16)

        revoked_at_str = record.get("revoked_at", now.isoformat())
        try:
            revoked_at = datetime.datetime.fromisoformat(revoked_at_str)
            if revoked_at.tzinfo is None:
                revoked_at = revoked_at.replace(tzinfo=datetime.timezone.utc)
        except Exception:
            revoked_at = now

        reason_str = record.get("reason", "unspecified")
        reason_flag = REASON_MAP.get(reason_str, x509.ReasonFlags.unspecified)

        revoked_cert_builder = (
            x509.RevokedCertificateBuilder()
            .serial_number(serial_int)
            .revocation_date(revoked_at)
            .add_extension(
                x509.CRLReason(reason_flag),
                critical=False,
            )
        )
        builder = builder.add_revoked_certificate(revoked_cert_builder.build(default_backend()))

    crl = builder.sign(
        private_key=ca_key,
        algorithm=hashes.SHA256(),
        backend=default_backend(),
    )
    return crl.public_bytes(serialization.Encoding.PEM)


# ─── Nạp CRL ─────────────────────────────────────────────────────────────────

def load_crl(pem_or_path) -> x509.CertificateRevocationList:
    """
    Nạp CRL từ PEM bytes hoặc đường dẫn file.

    Args:
        pem_or_path: bytes (PEM) hoặc str (đường dẫn file).

    Returns:
        x509.CertificateRevocationList
    """
    if isinstance(pem_or_path, str):
        with open(pem_or_path, "rb") as f:
            pem_data = f.read()
    elif isinstance(pem_or_path, bytes):
        pem_data = pem_or_path
    else:
        raise TypeError(f"pem_or_path phải là str hoặc bytes, nhận được {type(pem_or_path)}")

    return x509.load_pem_x509_crl(pem_data, default_backend())


# ─── Kiểm tra thu hồi ─────────────────────────────────────────────────────────

def is_revoked(cert: x509.Certificate, crl: x509.CertificateRevocationList) -> bool:
    """
    Kiểm tra xem chứng chỉ có trong CRL không.

    Args:
        cert: Chứng chỉ cần kiểm tra.
        crl:  Danh sách thu hồi đã nạp.

    Returns:
        True nếu bị thu hồi, False nếu còn hiệu lực.
    """
    revoked = crl.get_revoked_certificate_by_serial_number(cert.serial_number)
    return revoked is not None


# ─── Quản lý DB thu hồi (JSON) ───────────────────────────────────────────────

def load_revoked_db(db_path: str) -> list[dict]:
    """
    Nạp danh sách thu hồi từ file JSON. Trả về [] nếu file chưa tồn tại.
    """
    if not os.path.exists(db_path):
        return []
    try:
        with open(db_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, list):
            return data
        return []
    except Exception:
        return []


def save_revoked_db(db_path: str, records: list[dict]) -> None:
    """
    Lưu danh sách thu hồi ra file JSON (ghi nguyên tử qua .tmp).
    """
    tmp_path = db_path + ".tmp"
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(records, f, ensure_ascii=False, indent=2)
    os.replace(tmp_path, db_path)


def revoke_cert(
    cert: x509.Certificate,
    reason_str: str = "unspecified",
    db_path: str = "pki/revoked.json",
) -> None:
    """
    Thêm chứng chỉ vào DB thu hồi.

    Args:
        cert:       Chứng chỉ cần thu hồi.
        reason_str: Lý do thu hồi (xem REASON_MAP).
        db_path:    Đường dẫn file JSON chứa danh sách đã thu hồi.
    """
    if reason_str not in REASON_MAP:
        raise ValueError(
            f"Lý do thu hồi không hợp lệ: '{reason_str}'. "
            f"Chọn một trong: {list(REASON_MAP.keys())}"
        )

    records = load_revoked_db(db_path)
    serial_hex = hex(cert.serial_number)

    # Kiểm tra đã thu hồi chưa
    for r in records:
        if r.get("serial") == serial_hex:
            return  # Đã có rồi, không thêm lại

    now_str = datetime.datetime.now(datetime.timezone.utc).isoformat()
    records.append({
        "serial":     serial_hex,
        "revoked_at": now_str,
        "reason":     reason_str,
    })
    save_revoked_db(db_path, records)

