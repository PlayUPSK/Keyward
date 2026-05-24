from app import db
from app.models.base import TimestampMixin, UUIDPrimaryKeyMixin


class CertificateRequestNonce(UUIDPrimaryKeyMixin, TimestampMixin, db.Model):
    __tablename__ = "certificate_request_nonces"

    device_id = db.Column(db.Uuid(), db.ForeignKey("devices.id"), nullable=False)
    request_id = db.Column(db.Text, nullable=False)
    nonce = db.Column(db.Text, nullable=False)
    expires_at = db.Column(db.DateTime(timezone=True), nullable=False)

    __table_args__ = (
        db.UniqueConstraint("device_id", "request_id", name="uq_cert_nonce_device_request"),
        db.UniqueConstraint("device_id", "nonce", name="uq_cert_nonce_device_nonce"),
    )
