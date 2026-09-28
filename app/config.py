import os
from datetime import timedelta

class Config:
    SECRET_KEY = os.getenv("FLASK_SECRET_KEY")
    if not SECRET_KEY:
        raise RuntimeError("FLASK_SECRET_KEY must be configured")

    SQLALCHEMY_DATABASE_URI = os.getenv(
        "DATABASE_URL",
        "sqlite:///patient_records.db"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Session hardening
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = os.getenv("SESSION_COOKIE_SECURE", "0") == "1"
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)

    # Upload limits
    MAX_CONTENT_LENGTH = 10 * 1024 * 1024  # 10 MB

    # S3 is optional for local development. If S3_BUCKET is set,
    # reports are stored privately in S3; otherwise they are stored
    # outside the static directory in local storage.
    S3_BUCKET = os.getenv("S3_BUCKET")
    AWS_REGION = os.getenv("AWS_DEFAULT_REGION", "ap-south-1")
    UPLOAD_DIR = os.getenv(
        "UPLOAD_DIR",
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "private_uploads")
    )

    RATELIMIT_STORAGE_URI = os.getenv("RATELIMIT_STORAGE_URI", "memory://")
