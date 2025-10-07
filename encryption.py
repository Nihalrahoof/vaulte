import os
from cryptography.fernet import Fernet, InvalidToken
from flask import current_app

def get_fernet() -> Fernet:
    # Prefer app config, fallback to environment
    key = current_app.config.get("ENCRYPTION_KEY") or os.environ.get("ENCRYPTION_KEY")
    if not key:
        raise RuntimeError(
            "ENCRYPTION_KEY is not set. Generate one with Fernet.generate_key() and set it in your environment."
        )
    if isinstance(key, str):
        key = key.encode("utf-8")
    return Fernet(key)

def encrypt_value(value: str) -> bytes:
    f = get_fernet()
    return f.encrypt(value.encode("utf-8"))

def decrypt_value(token: bytes) -> str:
    f = get_fernet()
    try:
        return f.decrypt(token).decode("utf-8")
    except InvalidToken:
        return "[decrypt error]"
