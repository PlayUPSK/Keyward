import secrets
from datetime import timedelta

from app.models.base import utcnow


def start_device_enrollment(payload: dict) -> dict:
    challenge = secrets.token_urlsafe(32)
    expires_at = utcnow() + timedelta(minutes=10)
    return {
        "enrollment_id": secrets.token_urlsafe(16),
        "challenge": challenge,
        "expires_at": expires_at.isoformat(),
        "status": "pending",
        "device_name": payload.get("name"),
    }
