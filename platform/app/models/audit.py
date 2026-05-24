from app import db
from app.models.base import UUIDPrimaryKeyMixin, utcnow


class AuditEvent(UUIDPrimaryKeyMixin, db.Model):
    __tablename__ = "audit_events"

    event_type = db.Column(db.Text, nullable=False)
    actor_user_id = db.Column(db.Uuid(), db.ForeignKey("users.id"))
    actor_device_id = db.Column(db.Uuid(), db.ForeignKey("devices.id"))
    target_type = db.Column(db.Text)
    target_id = db.Column(db.Uuid())
    source_ip = db.Column(db.String(45))
    user_agent = db.Column(db.Text)
    outcome = db.Column(db.Text, nullable=False)
    reason = db.Column(db.Text)
    event_metadata = db.Column("metadata", db.JSON, nullable=False, default=dict)
    previous_hash = db.Column(db.Text)
    event_hash = db.Column(db.Text)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)
