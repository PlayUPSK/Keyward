import secrets
from datetime import timedelta

from app.models.base import utcnow


def create_server_enrollment_token(payload: dict) -> dict:
    expires_at = utcnow() + timedelta(minutes=15)
    return {
        "token": secrets.token_urlsafe(32),
        "expires_at": expires_at.isoformat(),
        "server_name": payload.get("hostname"),
    }
