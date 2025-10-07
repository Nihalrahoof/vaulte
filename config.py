import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
INSTANCE_DIR = BASE_DIR / "instance"
INSTANCE_DIR.mkdir(exist_ok=True)

class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-change-me")
    # Use sqlite by default, override with DATABASE_URL if needed
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL",
        f"sqlite:///{(INSTANCE_DIR / 'app.db').as_posix()}",
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # File uploads
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16 MB
    # Prefer Railway's mounted volume if available; fall back to local uploads
    # Common Railway env var: RAILWAY_VOLUME_MOUNT_PATH. Default mount is often /mnt/data
    _railway_mount = os.environ.get("RAILWAY_VOLUME_MOUNT_PATH") or "/mnt/data"
    if os.path.ismount(_railway_mount) or os.path.exists(_railway_mount):
        _uploads_base = Path(_railway_mount) / "uploads"
    else:
        _uploads_base = BASE_DIR / "uploads"
    UPLOAD_FOLDER = _uploads_base.as_posix()
    ALLOWED_EXTENSIONS = {"pdf"}

    # Crypto key for Fernet encryption of sensitive fields
    ENCRYPTION_KEY = os.environ.get("ENCRYPTION_KEY")  # base64 urlsafe key

    # Cookies / session hardening
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = os.environ.get("FLASK_ENV") == "production"
