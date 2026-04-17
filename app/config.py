import os

class Config:
    """Flask application configuration loaded from environment variables."""

    DATABASE_URL = os.getenv("DATABASE_URL")
    SQLALCHEMY_DATABASE_URI = DATABASE_URL
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SECRET_KEY = os.getenv("SECRET")
    if not SECRET_KEY:
        raise RuntimeError(
            "Environment variable SECRET is not set. "
            "Generate one with: python -c \"import secrets; print(secrets.token_hex(32))\" "
            "and add it to your .env file."
        )
