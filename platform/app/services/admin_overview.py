from datetime import timedelta

from app.models.audit import AuditEvent
from app.models.device import Device
from app.models.policy import AccessGrant, Policy
from app.models.server import Server
from app.models.ssh_certificate import SSHCertificateIssuance
from app.models.base import utcnow


def dashboard_summary() -> dict:
    since = utcnow() - timedelta(hours=24)
    return {
        "devices": {
            "total": Device.query.count(),
            "trusted": Device.query.filter_by(status="trusted").count(),
            "revoked": Device.query.filter_by(status="revoked").count(),
            "suspended": Device.query.filter_by(status="suspended").count(),
        },
        "servers": {
            "total": Server.query.count(),
            "enrolled": Server.query.filter_by(status="enrolled").count(),
            "pending": Server.query.filter_by(status="pending").count(),
        },
        "access": {
            "policies": Policy.query.count(),
            "enabled_policies": Policy.query.filter_by(enabled=True).count(),
            "grants": AccessGrant.query.count(),
            "certificates_24h": SSHCertificateIssuance.query.filter(SSHCertificateIssuance.issued_at >= since).count(),
        },
        "audit": {
            "events_24h": AuditEvent.query.filter(AuditEvent.created_at >= since).count(),
            "denials_24h": AuditEvent.query.filter(AuditEvent.created_at >= since, AuditEvent.outcome == "denied").count(),
        },
    }
