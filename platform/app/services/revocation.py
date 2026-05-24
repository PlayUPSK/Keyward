from flask import current_app
from uuid import UUID

from app import db
from app.models.device import Device
from app.models.identity import User
from app.models.policy import Policy
from app.models.server import Server
from app.models.ssh_certificate import SSHCertificateIssuance
from app.models.base import utcnow
from app.services.policy_engine import evaluate_access
from app.services.timeparse import ensure_aware


def get_revocation_state(server_id: str | None = None) -> dict:
    revoked_devices = Device.query.filter(Device.status != "trusted").all()
    revoked_serials: set[int] = set()
    revoked_reasons: dict[int, str] = {}

    now = utcnow()
    active_issuances_query = SSHCertificateIssuance.query.filter(
        SSHCertificateIssuance.valid_before > now,
    )
    scoped_server_id = _parse_uuid(server_id)
    if scoped_server_id is not None:
        active_issuances_query = active_issuances_query.filter(
            SSHCertificateIssuance.server_id == scoped_server_id,
        )
    active_issuances = active_issuances_query.all()
    default_ttl_seconds = current_app.config.get("SSH_CERT_TTL_SECONDS", 300)

    for issuance in active_issuances:
        reason = _revocation_reason_for_issuance(issuance, default_ttl_seconds)
        if reason:
            revoked_serials.add(issuance.serial)
            revoked_reasons[issuance.serial] = reason

    return {
        "revoked_devices": [
            {
                "device_id": str(device.id),
                "fingerprint": device.fingerprint,
                "status": device.status,
                "revoked_at": device.revoked_at.isoformat() if device.revoked_at else None,
            }
            for device in revoked_devices
        ],
        "revoked_certificate_serials": sorted(revoked_serials),
        "revoked_certificate_reasons": {
            str(serial): revoked_reasons[serial]
            for serial in sorted(revoked_reasons)
        },
        "generated_at": now.isoformat(),
    }


def _revocation_reason_for_issuance(issuance: SSHCertificateIssuance, default_ttl_seconds: int) -> str | None:
    device = db.session.get(Device, issuance.device_id)
    if device is None:
        return "device_missing"

    user = db.session.get(User, issuance.user_id)
    if user is None or user.status != "active":
        return "user_not_active"

    server = db.session.get(Server, issuance.server_id)
    if server is None:
        return "server_missing"

    decision = evaluate_access(
        device=device,
        server=server,
        ssh_principal=issuance.ssh_principal,
        source_ip=issuance.source_ip,
        default_ttl_seconds=default_ttl_seconds,
    )
    if decision.decision != "allow":
        return decision.reason

    original_policy_id = (issuance.policy_decision or {}).get("matched_policy_id")
    if original_policy_id:
        policy = _policy_by_id(original_policy_id)
        if policy is None:
            return "policy_deleted"
        if (policy.actions or {}).get("invalidated"):
            return "policy_invalidated"
        if not policy.enabled:
            return "policy_disabled"
        if original_policy_id != decision.matched_policy_id:
            return "policy_changed"

    original_grant_id = (issuance.policy_decision or {}).get("matched_grant_id")
    if original_grant_id and original_grant_id != decision.matched_grant_id:
        return "access_grant_changed"

    if ensure_aware(issuance.valid_before) <= utcnow():
        return None
    return None


def _policy_by_id(policy_id: str) -> Policy | None:
    try:
        return db.session.get(Policy, UUID(policy_id))
    except ValueError:
        return None


def _parse_uuid(value: str | None) -> UUID | None:
    if not value:
        return None
    try:
        return UUID(value)
    except ValueError:
        return None
