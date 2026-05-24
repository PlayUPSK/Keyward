import json
from datetime import datetime, timedelta, timezone
from uuid import UUID

from flask import current_app

from app import db
from app.models.device import Device
from app.models.server import Server
from app.models.ssh_certificate import SSHCertificateIssuance
from app.models.base import utcnow
from app.services.audit import record_audit_event
from app.services.device_crypto import verify_device_signature
from app.services.policy_engine import evaluate_access
from app.services.replay import reserve_certificate_request_nonce
from app.services.ssh_signer import SSHSigningError, generate_serial, sign_user_certificate


REQUIRED_CERT_REQUEST_FIELDS = {
    "request_id",
    "device_id",
    "server",
    "ssh_principal",
    "ephemeral_ssh_public_key",
    "nonce",
    "timestamp",
    "signature",
}


def request_ssh_certificate(payload: dict) -> dict:
    missing = sorted(REQUIRED_CERT_REQUEST_FIELDS - payload.keys())
    if missing:
        return {
            "decision": "deny",
            "reason": "missing_required_fields",
            "missing": missing,
        }

    try:
        device_id = UUID(payload["device_id"])
    except ValueError:
        return {
            "decision": "deny",
            "reason": "invalid_device_id",
        }

    device = db.session.get(Device, device_id)
    if device is None or device.status != "trusted":
        _audit_cert_denial(payload, "device_not_trusted")
        return {
            "decision": "deny",
            "reason": "device_not_trusted",
        }

    existing_request = SSHCertificateIssuance.query.filter_by(request_id=payload["request_id"]).one_or_none()
    if existing_request is not None:
        _audit_cert_denial(payload, "duplicate_request_id", device=device)
        return {
            "decision": "deny",
            "reason": "duplicate_request_id",
        }

    reserved, replay_reason = reserve_certificate_request_nonce(
        device=device,
        request_id=payload["request_id"],
        nonce=payload["nonce"],
        window_seconds=current_app.config["CERT_REQUEST_REPLAY_WINDOW_SECONDS"],
    )
    if not reserved:
        _audit_cert_denial(payload, replay_reason, device=device)
        return {
            "decision": "deny",
            "reason": replay_reason,
        }

    timestamp_ok, timestamp_reason = _validate_timestamp(payload["timestamp"])
    if not timestamp_ok:
        _audit_cert_denial(payload, timestamp_reason, device=device)
        return {
            "decision": "deny",
            "reason": timestamp_reason,
        }

    canonical_request = _canonical_certificate_request(payload)
    verified, verify_reason = verify_device_signature(
        public_key_pem=device.public_key,
        message=canonical_request,
        signature_b64=payload["signature"],
    )
    if not verified:
        _audit_cert_denial(payload, "device_signature_invalid", device=device)
        return {
            "decision": "deny",
            "reason": "device_signature_invalid",
            "detail": verify_reason,
        }

    server = _resolve_server(payload["server"])
    if server is None or server.status != "enrolled":
        _audit_cert_denial(payload, "server_not_enrolled", device=device)
        return {
            "decision": "deny",
            "reason": "server_not_enrolled",
        }

    now = utcnow()
    default_ttl_seconds = current_app.config["SSH_CERT_TTL_SECONDS"]
    policy_decision = evaluate_access(
        device=device,
        server=server,
        ssh_principal=payload["ssh_principal"],
        source_ip=payload.get("source_ip"),
        default_ttl_seconds=default_ttl_seconds,
    )
    if policy_decision.decision != "allow":
        record_audit_event(
            event_type="ssh_certificate.denied",
            outcome="denied",
            reason=policy_decision.reason,
            actor_user_id=device.user_id,
            actor_device_id=device.id,
            target_type="server",
            target_id=server.id,
            source_ip=payload.get("source_ip"),
            metadata={"request_id": payload["request_id"], "policy_decision": policy_decision.as_dict()},
        )
        db.session.commit()
        return {
            "decision": "deny",
            "reason": policy_decision.reason,
            "policy_decision": policy_decision.as_dict(),
        }

    ttl_seconds = min(policy_decision.ttl_seconds, default_ttl_seconds)
    serial = generate_serial()
    cert_key_id = (
        f"request={payload['request_id']};"
        f"user={device.user_id};"
        f"device={device.id};"
        f"server={server.id}"
    )

    try:
        certificate = sign_user_certificate(
            ca_key_path=current_app.config["SSH_CA_KEY_PATH"],
            public_key=payload["ephemeral_ssh_public_key"],
            key_id=cert_key_id,
            serial=serial,
            principals=[payload["ssh_principal"]],
            ttl_seconds=ttl_seconds,
        )
    except SSHSigningError as exc:
        record_audit_event(
            event_type="ssh_certificate.denied",
            outcome="error",
            reason="certificate_signing_failed",
            actor_user_id=device.user_id,
            actor_device_id=device.id,
            target_type="server",
            target_id=server.id,
            metadata={"request_id": payload["request_id"], "detail": str(exc)},
        )
        db.session.commit()
        return {
            "decision": "deny",
            "reason": "certificate_signing_failed",
            "detail": str(exc),
        }

    valid_before = now + timedelta(seconds=ttl_seconds)
    issuance = SSHCertificateIssuance(
        request_id=payload["request_id"],
        user_id=device.user_id,
        device_id=device.id,
        server_id=server.id,
        ssh_principal=payload["ssh_principal"],
        public_key_fingerprint=payload.get("public_key_fingerprint", "unknown"),
        cert_key_id=cert_key_id,
        serial=serial,
        valid_after=now,
        valid_before=valid_before,
        policy_decision={
            **policy_decision.as_dict(),
        },
        source_ip=payload.get("source_ip"),
        issued_at=now,
    )
    db.session.add(issuance)
    record_audit_event(
        event_type="ssh_certificate.issued",
        outcome="success",
        reason=policy_decision.reason,
        actor_user_id=device.user_id,
        actor_device_id=device.id,
        target_type="server",
        target_id=server.id,
        source_ip=payload.get("source_ip"),
        metadata={
            "request_id": payload["request_id"],
            "serial": serial,
            "ssh_principal": payload["ssh_principal"],
            "policy_decision": policy_decision.as_dict(),
        },
    )
    db.session.commit()

    return {
        "decision": "allow",
        "reason": policy_decision.reason,
        "valid_after": now.isoformat(),
        "valid_before": valid_before.isoformat(),
        "certificate": certificate,
        "serial": serial,
        "key_id": cert_key_id,
        "constraints": policy_decision.constraints,
        "policy_decision": policy_decision.as_dict(),
    }


def _resolve_server(server_ref: str) -> Server | None:
    try:
        server_id = UUID(server_ref)
    except ValueError:
        server_id = None
    if server_id is not None:
        server = db.session.get(Server, server_id)
        if server is not None:
            return server
    return Server.query.filter_by(hostname=server_ref).one_or_none()


def _canonical_certificate_request(payload: dict) -> bytes:
    canonical = {
        "device_id": payload["device_id"],
        "ephemeral_ssh_public_key": payload["ephemeral_ssh_public_key"].strip(),
        "nonce": payload["nonce"],
        "request_id": payload["request_id"],
        "server": payload["server"],
        "ssh_principal": payload["ssh_principal"],
        "timestamp": payload["timestamp"],
    }
    return json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _validate_timestamp(timestamp: str) -> tuple[bool, str | None]:
    try:
        parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError:
        return False, "invalid_timestamp"
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)

    now = utcnow()
    if parsed < now - timedelta(minutes=2):
        return False, "request_timestamp_too_old"
    if parsed > now + timedelta(seconds=30):
        return False, "request_timestamp_in_future"
    return True, None


def _audit_cert_denial(payload: dict, reason: str, device: Device | None = None) -> None:
    record_audit_event(
        event_type="ssh_certificate.denied",
        outcome="denied",
        reason=reason,
        actor_user_id=device.user_id if device else None,
        actor_device_id=device.id if device else None,
        source_ip=payload.get("source_ip"),
        metadata={"request_id": payload.get("request_id"), "server": payload.get("server")},
    )
    db.session.commit()
