from app import db
from app.models.base import UUIDPrimaryKeyMixin, utcnow


class SSHCertificateIssuance(UUIDPrimaryKeyMixin, db.Model):
    __tablename__ = "ssh_certificate_issuances"

    request_id = db.Column(db.Text, nullable=False, unique=True)
    user_id = db.Column(db.Uuid(), db.ForeignKey("users.id"), nullable=False)
    device_id = db.Column(db.Uuid(), db.ForeignKey("devices.id"), nullable=False)
    server_id = db.Column(db.Uuid(), db.ForeignKey("servers.id"), nullable=False)
    ssh_principal = db.Column(db.Text, nullable=False)
    public_key_fingerprint = db.Column(db.Text, nullable=False)
    cert_key_id = db.Column(db.Text, nullable=False)
    serial = db.Column(db.BigInteger, nullable=False, unique=True)
    valid_after = db.Column(db.DateTime(timezone=True), nullable=False)
    valid_before = db.Column(db.DateTime(timezone=True), nullable=False)
    policy_decision = db.Column(db.JSON, nullable=False)
    source_ip = db.Column(db.String(45))
    issued_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)
