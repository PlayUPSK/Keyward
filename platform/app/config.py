import os


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-only-change-me")
    DB_BACKEND = os.environ.get("DB_BACKEND", "sqlite")
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL") or (
        "sqlite:///keyward-dev.db"
        if DB_BACKEND == "sqlite"
        else "postgresql+psycopg://keyward:keyward@localhost:5432/keyward"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    JSON_SORT_KEYS = False
    SSH_CA_KEY_PATH = os.environ.get("SSH_CA_KEY_PATH", "./dev_ca/ssh_user_ca")
    SSH_CERT_TTL_SECONDS = int(os.environ.get("SSH_CERT_TTL_SECONDS", "300"))
    RATE_LIMIT_WINDOW_SECONDS = int(os.environ.get("RATE_LIMIT_WINDOW_SECONDS", "60"))
    RATE_LIMIT_MAX_REQUESTS = int(os.environ.get("RATE_LIMIT_MAX_REQUESTS", "120"))
    CERT_REQUEST_REPLAY_WINDOW_SECONDS = int(os.environ.get("CERT_REQUEST_REPLAY_WINDOW_SECONDS", "300"))
    DEVICE_ENROLLMENT_REAUTH_SECONDS = int(os.environ.get("DEVICE_ENROLLMENT_REAUTH_SECONDS", "300"))
    SERVER_ENROLLMENT_DEFAULT_TTL_MINUTES = int(os.environ.get("SERVER_ENROLLMENT_DEFAULT_TTL_MINUTES", "15"))
    SERVER_ENROLLMENT_MAX_TTL_MINUTES = int(os.environ.get("SERVER_ENROLLMENT_MAX_TTL_MINUTES", "1440"))
    SERVER_ENROLLMENT_MAX_USES_LIMIT = int(os.environ.get("SERVER_ENROLLMENT_MAX_USES_LIMIT", "100"))
    LOCAL_AUTH_ENABLED = os.environ.get("LOCAL_AUTH_ENABLED", "1") == "1"
    REGISTRATION_ENABLED = os.environ.get("REGISTRATION_ENABLED", "1") == "1"
    DEV_AUTH_ENABLED = os.environ.get("DEV_AUTH_ENABLED", "0") == "1"
    ALLOWED_LOGIN_DOMAINS = [
        domain.strip().lower()
        for domain in os.environ.get("ALLOWED_LOGIN_DOMAINS", "example.com,localhost").split(",")
        if domain.strip()
    ]
    FIRST_USER_ADMIN = os.environ.get("FIRST_USER_ADMIN", "1") == "1"
    OIDC_ISSUER_URL = os.environ.get("OIDC_ISSUER_URL")
    OIDC_CLIENT_ID = os.environ.get("OIDC_CLIENT_ID")
    SAML_METADATA_URL = os.environ.get("SAML_METADATA_URL")
    SCIM_ENABLED = os.environ.get("SCIM_ENABLED", "0") == "1"


class TestConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
