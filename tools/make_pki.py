#!/usr/bin/env python3
"""
make_pki.py – Tạo CA tự ký, chứng chỉ server và nhóm, quản lý CRL.

Usage:
    # Tạo CA + server cert lần đầu:
    python tools/make_pki.py

    # Tạo thêm chứng chỉ cho nhóm:
    python tools/make_pki.py --team team1 --mssv 2412716 2412760

    # Ghi đè nếu đã tồn tại:
    python tools/make_pki.py --force
    python tools/make_pki.py --team team1 --mssv 2412716 2412760 --force

    # Tạo / cập nhật file CRL:
    python tools/make_pki.py --crl

    # Thu hồi chứng chỉ:
    python tools/make_pki.py --revoke pki/team1/client.crt --reason keyCompromise

Kết quả lưu tại pki/ (tạo tự động):
    pki/ca.crt, pki/ca.key           ← CA tự ký
    pki/ca.crl                       ← Certificate Revocation List (RFC 5280)
    pki/revoked.json                 ← Database lưu vết thu hồi
    pki/server.crt, pki/server.key   ← Server cert (CN=chat-server)
    pki/<team>/client.crt            ← Team cert (CN=<team>, UID=mssv...)
    pki/<team>/client.key

Cảnh báo: Không đưa các file *.key vào repo!
"""

import argparse
import datetime
import ipaddress
import json
import os
import sys

if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PKI_DIR  = os.path.join(BASE_DIR, "pki")

RSA_KEY_SIZE         = 2048
CA_VALIDITY_DAYS     = 3650   # 10 năm
SERVER_VALIDITY_DAYS = 730    # 2 năm
CLIENT_VALIDITY_DAYS = 365    # 1 năm

# URL OCSP và CRL Distribution Point
OCSP_URL = "http://localhost:8080/ocsp"
CRL_URL  = "http://localhost:8080/crl"

# Thông tin MSSV nhóm (nhúng vào CN của CA theo yêu cầu đề bài)
DEFAULT_MSSV_LIST = ["2412716", "2412760"]


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _gen_rsa_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=RSA_KEY_SIZE,
        backend=default_backend(),
    )


def _save_key(key, path: str) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    print(f"  [KEY]  {os.path.relpath(path, BASE_DIR)}")


def _save_cert(cert, path: str) -> None:
    with open(path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    print(f"  [CERT] {os.path.relpath(path, BASE_DIR)}")


def _load_ca() -> tuple:
    """Nạp CA key và cert từ PKI_DIR. Ném FileNotFoundError nếu chưa tồn tại."""
    ca_key_path = os.path.join(PKI_DIR, "ca.key")
    ca_crt_path = os.path.join(PKI_DIR, "ca.crt")
    with open(ca_key_path, "rb") as f:
        ca_key = serialization.load_pem_private_key(
            f.read(), password=None, backend=default_backend()
        )
    with open(ca_crt_path, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
    return ca_key, ca_cert


def _now_utc() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _sign(
    subject_key,
    subject_name: x509.Name,
    issuer_cert: x509.Certificate,
    issuer_key,
    validity_days: int,
    extensions: list,
) -> x509.Certificate:
    """Ký chứng chỉ: subject được ký bởi issuer."""
    now = _now_utc()
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject_name)
        .issuer_name(issuer_cert.subject)
        .public_key(subject_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=validity_days))
    )
    for ext, critical in extensions:
        builder = builder.add_extension(ext, critical=critical)
    return builder.sign(issuer_key, hashes.SHA256(), default_backend())


# ─── Tạo CA ──────────────────────────────────────────────────────────────────

def make_ca(force: bool = False, mssv_list: list[str] | None = None) -> None:
    """Tạo CA tự ký (self-signed root CA) với CN và OU tích hợp MSSV theo yêu cầu đề bài."""
    ca_key_path = os.path.join(PKI_DIR, "ca.key")
    ca_crt_path = os.path.join(PKI_DIR, "ca.crt")

    if not force and os.path.exists(ca_crt_path):
        print("CA đã tồn tại (bỏ qua). Dùng --force để tạo lại.")
        return

    os.makedirs(PKI_DIR, exist_ok=True)
    key = _gen_rsa_key()

    now = _now_utc()
    mssvs = mssv_list if mssv_list else DEFAULT_MSSV_LIST
    ca_cn = f"CA-Root-{'-'.join(mssvs)}"

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "VN"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureChat CA"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, f"Faculty of Computer Science and Engineer – {'-'.join(mssvs)}"),
        x509.NameAttribute(NameOID.COMMON_NAME, ca_cn),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=CA_VALIDITY_DAYS))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
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
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
        .sign(key, hashes.SHA256(), default_backend())
    )

    _save_key(key, ca_key_path)
    _save_cert(cert, ca_crt_path)
    print(f"CA tự ký tạo xong (CN={ca_cn}).")


# ─── Tạo Server cert ──────────────────────────────────────────────────────────

def make_server_cert(force: bool = False) -> None:
    """Tạo chứng chỉ server (CN=chat-server, SAN=localhost/127.0.0.1, kèm CDP và AIA)."""
    srv_key_path = os.path.join(PKI_DIR, "server.key")
    srv_crt_path = os.path.join(PKI_DIR, "server.crt")

    if not force and os.path.exists(srv_crt_path):
        print("Server cert đã tồn tại (bỏ qua). Dùng --force để tạo lại.")
        return

    ca_key, ca_cert = _load_ca()
    srv_key = _gen_rsa_key()

    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "VN"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureChat"),
        x509.NameAttribute(NameOID.COMMON_NAME, "chat-server"),
    ])

    extensions = [
        (x509.BasicConstraints(ca=False, path_length=None), True),
        (
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            True,
        ),
        (x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False),
        (
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
            ]),
            False,
        ),
        (x509.SubjectKeyIdentifier.from_public_key(srv_key.public_key()), False),
        (x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), False),
        # CRL Distribution Points — client có thể tải CRL offline
        (
            x509.CRLDistributionPoints([
                x509.DistributionPoint(
                    full_name=[x509.UniformResourceIdentifier(CRL_URL)],
                    relative_name=None,
                    reasons=None,
                    crl_issuer=None,
                ),
            ]),
            False,
        ),
        # Authority Information Access — OCSP URL để kiểm tra online
        (
            x509.AuthorityInformationAccess([
                x509.AccessDescription(
                    x509.AuthorityInformationAccessOID.OCSP,
                    x509.UniformResourceIdentifier(OCSP_URL),
                ),
            ]),
            False,
        ),
    ]

    srv_cert = _sign(srv_key, subject, ca_cert, ca_key, SERVER_VALIDITY_DAYS, extensions)
    _save_key(srv_key, srv_key_path)
    _save_cert(srv_cert, srv_crt_path)
    print("Server cert tạo xong.")


# ─── Tạo Team (Client) cert ────────────────────────────────────────────────────

def make_team_cert(team_name: str, mssv_list: list[str], force: bool = False) -> None:
    """
    Tạo chứng chỉ cho nhóm kèm CDP và AIA extensions.
    Subject: CN=<team_name>, UID=mssv_1, UID=mssv_2, ...
    """
    team_dir     = os.path.join(PKI_DIR, team_name)
    cli_key_path = os.path.join(team_dir, "client.key")
    cli_crt_path = os.path.join(team_dir, "client.crt")

    if not force and os.path.exists(cli_crt_path):
        print(f"Team cert '{team_name}' đã tồn tại (bỏ qua). Dùng --force để tạo lại.")
        return

    os.makedirs(team_dir, exist_ok=True)
    ca_key, ca_cert = _load_ca()
    cli_key = _gen_rsa_key()

    name_attrs = [
        x509.NameAttribute(NameOID.COUNTRY_NAME, "VN"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureChat"),
        x509.NameAttribute(NameOID.COMMON_NAME, team_name),
    ]
    for mssv in mssv_list:
        name_attrs.append(x509.NameAttribute(NameOID.USER_ID, mssv))

    subject = x509.Name(name_attrs)

    extensions = [
        (x509.BasicConstraints(ca=False, path_length=None), True),
        (
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            True,
        ),
        (x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), False),
        (x509.SubjectKeyIdentifier.from_public_key(cli_key.public_key()), False),
        (x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), False),
        # CRL Distribution Points — server/client có thể tải CRL để kiểm tra offline
        (
            x509.CRLDistributionPoints([
                x509.DistributionPoint(
                    full_name=[x509.UniformResourceIdentifier(CRL_URL)],
                    relative_name=None,
                    reasons=None,
                    crl_issuer=None,
                ),
            ]),
            False,
        ),
        # Authority Information Access — OCSP URL để kiểm tra online
        (
            x509.AuthorityInformationAccess([
                x509.AccessDescription(
                    x509.AuthorityInformationAccessOID.OCSP,
                    x509.UniformResourceIdentifier(OCSP_URL),
                ),
            ]),
            False,
        ),
    ]

    cli_cert = _sign(cli_key, subject, ca_cert, ca_key, CLIENT_VALIDITY_DAYS, extensions)
    _save_key(cli_key, cli_key_path)
    _save_cert(cli_cert, cli_crt_path)
    print(f"Team cert '{team_name}' (MSSV: {', '.join(mssv_list)}) tạo xong.")


# ─── Tạo CRL ──────────────────────────────────────────────────────────────────

def make_crl_file(force: bool = False) -> None:
    """Tạo CRL ban đầu (trống hoặc có các cert đã thu hồi) và lưu vào pki/ca.crl."""
    crl_path = os.path.join(PKI_DIR, "ca.crl")
    if not force and os.path.exists(crl_path):
        print("CRL đã tồn tại (bỏ qua). Dùng --force để tạo lại.")
        return

    ca_key, ca_cert = _load_ca()

    # Nạp danh sách thu hồi từ DB JSON (nếu có)
    db_path = os.path.join(PKI_DIR, "revoked.json")
    revoked_list = []
    if os.path.exists(db_path):
        try:
            with open(db_path, "r", encoding="utf-8") as f:
                revoked_list = json.load(f)
        except Exception:
            pass

    # Import crl module
    sys.path.insert(0, os.path.join(BASE_DIR, "src"))
    from crl import make_crl
    crl_pem = make_crl(ca_cert, ca_key, revoked_list)

    with open(crl_path, "wb") as f:
        f.write(crl_pem)
    print(f"  [CRL]  {os.path.relpath(crl_path, BASE_DIR)}")
    print("CRL tạo xong.")


def revoke_and_update_crl(cert_path: str, reason: str = "unspecified") -> None:
    """Thu hồi một chứng chỉ và cập nhật CRL."""
    sys.path.insert(0, os.path.join(BASE_DIR, "src"))
    import pki
    from crl import revoke_cert, make_crl, load_revoked_db

    ca_key, ca_cert = _load_ca()
    cert = pki.load_cert_from_file(cert_path)
    db_path = os.path.join(PKI_DIR, "revoked.json")

    revoke_cert(cert, reason_str=reason, db_path=db_path)
    revoked_list = load_revoked_db(db_path)

    crl_pem = make_crl(ca_cert, ca_key, revoked_list)
    crl_path = os.path.join(PKI_DIR, "ca.crl")
    with open(crl_path, "wb") as f:
        f.write(crl_pem)

    import pki as pki_module
    cn = pki_module.get_cn(cert)
    serial = hex(cert.serial_number)
    print(f"  [REVOKED] CN={cn}, Serial={serial}, Reason={reason}")
    print(f"  [CRL]     Đã cập nhật {os.path.relpath(crl_path, BASE_DIR)}")


# ─── Main ─────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Công cụ tạo PKI cho Secure Chat"
    )
    parser.add_argument("--force",  action="store_true",
                        help="Ghi đè nếu đã tồn tại")
    parser.add_argument("--team",   default=None,
                        help="Tên nhóm (để tạo team cert)")
    parser.add_argument("--mssv",   nargs="+", default=[],
                        help="Danh sách MSSV của nhóm")
    parser.add_argument("--crl",    action="store_true",
                        help="Tạo/cập nhật CRL từ danh sách thu hồi hiện tại")
    parser.add_argument("--revoke", default=None,
                        help="Đường dẫn cert cần thu hồi (ví dụ: pki/team1/client.crt)")
    parser.add_argument("--reason", default="unspecified",
                        help="Lý do thu hồi: keyCompromise / cessationOfOperation / ...")
    args = parser.parse_args()

    print("=== Tạo PKI cho Secure Chat ===")

    if args.revoke:
        # Chế độ thu hồi chứng chỉ
        print(f"  Thu hồi chứng chỉ: {args.revoke} (reason={args.reason})")
        revoke_and_update_crl(args.revoke, reason=args.reason)
        print("\nThu hồi hoàn tất.")
        return

    force_ca = args.force and not args.team and not args.crl
    make_ca(force=force_ca)
    make_server_cert(force=force_ca)

    if args.team:
        if not args.mssv:
            print("Lỗi: --mssv cần có ít nhất một MSSV", file=sys.stderr)
            sys.exit(1)
        make_team_cert(args.team, args.mssv, force=args.force)

    if args.crl:
        make_crl_file(force=args.force)

    verify_all(args.team, args.mssv)
    print("\nHoàn tất. Không đưa file *.key vào repo!")


def verify_all(team: str | None, mssv: list) -> None:
    sys.path.insert(0, os.path.join(BASE_DIR, "src"))
    import pki
    ca = pki.load_cert_from_file(os.path.join(PKI_DIR, "ca.crt"))
    pki.verify_cert(pki.load_cert_from_file(os.path.join(PKI_DIR, "server.crt")),
                    ca, expected_cn="chat-server", usage="server")
    if team:
        pki.verify_cert(pki.load_cert_from_file(os.path.join(PKI_DIR, team, "client.crt")),
                        ca, expected_cn=team, usage="client")
    print("  [OK]   Kiểm tra lại chứng chỉ vừa tạo")


if __name__ == "__main__":
    main()
