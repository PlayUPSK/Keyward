from app import db
from app.models.base import TimestampMixin, UUIDPrimaryKeyMixin


class DeviceEnrollment(UUIDPrimaryKeyMixin, TimestampMixin, db.Model):
    __tablename__ = "device_enrollments"

    user_email = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Uuid(), db.ForeignKey("users.id"))
    device_name = db.Column(db.Text, nullable=False)
    platform = db.Column(db.Text, nullable=False)
    challenge = db.Column(db.Text, nullable=False, unique=True)
    user_code = db.Column(db.Text, unique=True)
    status = db.Column(db.Text, nullable=False, default="pending")
    expires_at = db.Column(db.DateTime(timezone=True), nullable=False)
    approved_at = db.Column(db.DateTime(timezone=True))
    completed_at = db.Column(db.DateTime(timezone=True))
    enrollment_metadata = db.Column("metadata", db.JSON, nullable=False, default=dict)


class ServerEnrollmentToken(UUIDPrimaryKeyMixin, TimestampMixin, db.Model):
    __tablename__ = "server_enrollment_tokens"

    hostname = db.Column(db.Text, nullable=False)
    token_hash = db.Column(db.Text, nullable=False, unique=True)
    status = db.Column(db.Text, nullable=False, default="pending")
    expires_at = db.Column(db.DateTime(timezone=True), nullable=False)
    redeemed_by_server_id = db.Column(db.Uuid(), db.ForeignKey("servers.id"))
    redeemed_at = db.Column(db.DateTime(timezone=True))
    token_metadata = db.Column("metadata", db.JSON, nullable=False, default=dict)
