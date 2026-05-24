from app import db
from app.models.base import TimestampMixin, UUIDPrimaryKeyMixin


class IntegrationSetting(UUIDPrimaryKeyMixin, TimestampMixin, db.Model):
    __tablename__ = "integration_settings"

    provider = db.Column(db.Text, nullable=False, unique=True)
    enabled = db.Column(db.Boolean, nullable=False, default=False)
    status = db.Column(db.Text, nullable=False, default="not_configured")
    settings = db.Column(db.JSON, nullable=False, default=dict)
    last_test_at = db.Column(db.DateTime(timezone=True))
    last_sync_at = db.Column(db.DateTime(timezone=True))
