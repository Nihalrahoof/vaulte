import secrets
import os
from flask import session, current_app

def allowed_file(filename: str) -> bool:
    if "." not in filename:
        return False
    ext = filename.rsplit(".", 1)[1].lower()
    return ext in current_app.config.get("ALLOWED_EXTENSIONS", set())

def ensure_user_upload_dir(user_id: int) -> str:
    base = current_app.config["UPLOAD_FOLDER"]
    user_dir = os.path.join(base, str(user_id))
    os.makedirs(user_dir, exist_ok=True)
    return user_dir

_CSFR_KEY = "_csrf_token"

def generate_csrf_token() -> str:
    # Reuse existing token for the session to avoid accidental mismatches
    token = session.get(_CSFR_KEY)
    if not token:
        token = secrets.token_urlsafe(32)
        session[_CSFR_KEY] = token
    return token

def validate_csrf_token(token: str) -> bool:
    return token and session.get(_CSFR_KEY) == token
