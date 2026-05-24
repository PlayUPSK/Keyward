import uuid
from datetime import datetime, timezone

from app import db


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class TimestampMixin:
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)
    updated_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=utcnow,
        onupdate=utcnow,
    )


class UUIDPrimaryKeyMixin:
    id = db.Column(db.Uuid(), primary_key=True, default=uuid.uuid4)
