import base64
import hashlib
import json
import os
import secrets

from cryptography.fernet import Fernet


def _build_fernet_key() -> bytes:
    raw_key = os.environ.get('DATA_ENCRYPTION_KEY', '').strip()
    if raw_key:
        return raw_key.encode('utf-8')

    # Fallback for local dev: derives a deterministic key from SECRET_KEY.
    secret_key = os.environ.get('SECRET_KEY', 'dev-secret-key')
    digest = hashlib.sha256(secret_key.encode('utf-8')).digest()
    return base64.urlsafe_b64encode(digest)


def get_fernet() -> Fernet:
    return Fernet(_build_fernet_key())


def encrypt_json(payload: dict) -> str:
    fernet = get_fernet()
    raw = json.dumps(payload, separators=(',', ':')).encode('utf-8')
    return fernet.encrypt(raw).decode('utf-8')


def decrypt_json(token: str) -> dict:
    fernet = get_fernet()
    raw = fernet.decrypt(token.encode('utf-8'))
    return json.loads(raw.decode('utf-8'))


def generate_otp_code() -> str:
    # 6-digit OTP with leading zeros preserved.
    return f"{secrets.randbelow(1000000):06d}"
