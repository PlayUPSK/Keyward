from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID

from app import db
from app.models.base import TimestampMixin, UUIDPrimaryKeyMixin, utcnow


class Policy(UUIDPrimaryKeyMixin, TimestampMixin, db.Model):
    __tablename__ = "policies"

    name = db.Column(db.Text, nullable=False)
    priority = db.Column(db.Integer, nullable=False, default=1000)
    enabled = db.Column(db.Boolean, nullable=False, default=True)
    effect = db.Column(db.Text, nullable=False)
    conditions = db.Column(JSONB, nullable=False, default=dict)
    actions = db.Column(JSONB, nullable=False, default=dict)
    created_by = db.Column(UUID(as_uuid=True), db.ForeignKey("users.id"))


class AccessGrant(UUIDPrimaryKeyMixin, db.Model):
    __tablename__ = "access_grants"

    subject_type = db.Column(db.Text, nullable=False)
    subject_id = db.Column(UUID(as_uuid=True), nullable=False)
    server_scope_type = db.Column(db.Text, nullable=False)
    server_scope_id = db.Column(UUID(as_uuid=True))
    unix_principals = db.Column(ARRAY(db.Text), nullable=False)
    policy_id = db.Column(UUID(as_uuid=True), db.ForeignKey("policies.id"))
    valid_from = db.Column(db.DateTime(timezone=True))
    valid_until = db.Column(db.DateTime(timezone=True))
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)


class ApprovalRequest(UUIDPrimaryKeyMixin, db.Model):
    __tablename__ = "approval_requests"

    user_id = db.Column(UUID(as_uuid=True), db.ForeignKey("users.id"), nullable=False)
    device_id = db.Column(UUID(as_uuid=True), db.ForeignKey("devices.id"), nullable=False)
    server_id = db.Column(UUID(as_uuid=True), db.ForeignKey("servers.id"), nullable=False)
    requested_principal = db.Column(db.Text, nullable=False)
    status = db.Column(db.Text, nullable=False)
    reason = db.Column(db.Text)
    expires_at = db.Column(db.DateTime(timezone=True), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)
