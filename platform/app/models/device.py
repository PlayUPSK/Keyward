from app import db
from app.models.base import TimestampMixin, UUIDPrimaryKeyMixin, utcnow


class Device(UUIDPrimaryKeyMixin, TimestampMixin, db.Model):
    __tablename__ = "devices"

    user_id = db.Column(db.Uuid(), db.ForeignKey("users.id"), nullable=False)
    name = db.Column(db.Text, nullable=False)
    platform = db.Column(db.Text, nullable=False)
    trust_level = db.Column(db.Text, nullable=False, default="software")
    status = db.Column(db.Text, nullable=False, default="pending")
    hardware_backed = db.Column(db.Boolean, nullable=False, default=False)
    public_key = db.Column(db.Text, nullable=False)
    certificate_pem = db.Column(db.Text)
    fingerprint = db.Column(db.Text, nullable=False, unique=True)
    posture = db.Column(db.JSON, nullable=False, default=dict)
    last_seen_at = db.Column(db.DateTime(timezone=True))
    revoked_at = db.Column(db.DateTime(timezone=True))


class DeviceEvent(UUIDPrimaryKeyMixin, db.Model):
    __tablename__ = "device_events"

    device_id = db.Column(db.Uuid(), db.ForeignKey("devices.id"), nullable=False)
    event_type = db.Column(db.Text, nullable=False)
    event_metadata = db.Column("metadata", db.JSON, nullable=False, default=dict)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)
