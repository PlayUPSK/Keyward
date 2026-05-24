import secrets
import string
import uuid
from datetime import datetime, timedelta
from urllib.parse import urlparse

from flask import current_app
from werkzeug.security import check_password_hash

from app import db
from app.models.device import Device
from app.models.enrollment import DeviceEnrollment
from app.models.identity import User
from app.models.base import utcnow
from app.services.audit import record_audit_event
from app.services.device_crypto import verify_enrollment_signature
from app.services.device_posture import evaluate_device_enrollment_posture
from app.services.timeparse import ensure_aware
from app.services.portal import accessible_servers_for_user


USER_CODE_ALPHABET = string.ascii_uppercase + string.digits


def start_device_enrollment(payload: dict) -> dict:
    user_email = payload.get("user_email")
    device_name = payload.get("name")
    platform = payload.get("platform", "unknown")
    if not user_email or not device_name:
        return {
            "error": "user_email and name are required",
            "status": "invalid",
        }

    challenge = secrets.token_urlsafe(32)
    expires_at = utcnow() + timedelta(minutes=10)
    enrollment = DeviceEnrollment(
        user_email=user_email.lower(),
        device_name=device_name,
        platform=platform,
        challenge=challenge,
        expires_at=expires_at,
        enrollment_metadata={
            "requested_trust_level": payload.get("requested_trust_level", "software"),
            "callback_url": payload.get("callback_url"),
        },
    )
    db.session.add(enrollment)
    db.session.commit()

    return {
        "enrollment_id": str(enrollment.id),
        "challenge": challenge,
        "expires_at": expires_at.isoformat(),
        "status": "pending",
        "device_name": device_name,
    }


def start_device_login_enrollment(payload: dict) -> tuple[dict, int]:
    device_name = payload.get("name")
    platform = payload.get("platform", "unknown")
    callback_url = payload.get("callback_url")
    if not device_name:
        return {"error": "name is required"}, 400
    if callback_url and not _valid_local_callback_url(callback_url):
        return {"error": "invalid_callback_url"}, 400

    challenge = secrets.token_urlsafe(32)
    user_code = _generate_user_code()
    expires_at = utcnow() + timedelta(minutes=10)
    enrollment = DeviceEnrollment(
        user_email="",
        device_name=device_name,
        platform=platform,
        challenge=challenge,
        user_code=user_code,
        status="awaiting_user",
        expires_at=expires_at,
        enrollment_metadata={
            "requested_trust_level": payload.get("requested_trust_level", "software"),
            "callback_url": callback_url,
        },
    )
    db.session.add(enrollment)
    db.session.commit()

    return {
        "enrollment_id": str(enrollment.id),
        "user_code": user_code,
        "verification_uri": "/devices/approve",
        "verification_uri_complete": f"/devices/approve?code={user_code}",
        "expires_at": expires_at.isoformat(),
        "interval_seconds": 3,
        "status": enrollment.status,
    }, 201


def poll_device_login_enrollment(enrollment_id: str) -> tuple[dict, int]:
    enrollment, error = _get_enrollment(enrollment_id)
    if error:
        return error
    if ensure_aware(enrollment.expires_at) < utcnow():
        enrollment.status = "expired"
        db.session.commit()
        return {"status": "expired", "error": "enrollment_expired"}, 410
    if enrollment.status == "awaiting_user":
        return {"status": enrollment.status}, 202
    if enrollment.status == "approved":
        return {
            "status": enrollment.status,
            "enrollment_id": str(enrollment.id),
            "challenge": enrollment.challenge,
            "device_name": enrollment.device_name,
            "user_email": enrollment.user_email,
            "expires_at": enrollment.expires_at.isoformat(),
        }, 200
    return {"status": enrollment.status}, 409


def pending_enrollment_for_code(user_code: str) -> DeviceEnrollment | None:
    if not user_code:
        return None
    return DeviceEnrollment.query.filter_by(user_code=user_code.strip().upper()).one_or_none()


def approve_device_enrollment(
    user,
    user_code: str,
    *,
    password: str | None = None,
    authenticated_at: str | None = None,
) -> tuple[dict, int]:
    enrollment = pending_enrollment_for_code(user_code)
    if enrollment is None:
        return {"error": "enrollment_not_found"}, 404
    if enrollment.status != "awaiting_user":
        return {"error": "enrollment_not_awaiting_user"}, 409
    if ensure_aware(enrollment.expires_at) < utcnow():
        enrollment.status = "expired"
        db.session.commit()
        return {"error": "enrollment_expired"}, 410
    step_up_ok, step_up_reason = _device_enrollment_step_up_ok(
        user,
        password=password,
        authenticated_at=authenticated_at,
    )
    if not step_up_ok:
        record_audit_event(
            event_type="device.enrollment_approval_denied",
            outcome="denied",
            actor_user_id=user.id,
            target_type="device_enrollment",
            target_id=enrollment.id,
            reason=step_up_reason,
            metadata={"device_name": enrollment.device_name, "platform": enrollment.platform},
        )
        db.session.commit()
        return {"error": step_up_reason}, 403

    enrollment.user_id = user.id
    enrollment.user_email = user.email
    enrollment.status = "approved"
    enrollment.approved_at = utcnow()
    record_audit_event(
        event_type="device.enrollment_approved",
        outcome="success",
        actor_user_id=user.id,
        target_type="device_enrollment",
        target_id=enrollment.id,
        metadata={"device_name": enrollment.device_name, "platform": enrollment.platform},
    )
    db.session.commit()
    return {"status": "approved", "enrollment_id": str(enrollment.id)}, 200


def enrollment_callback_url(enrollment: DeviceEnrollment) -> str | None:
    return (enrollment.enrollment_metadata or {}).get("callback_url")


def finish_device_enrollment(payload: dict) -> tuple[dict, int]:
    enrollment_id = payload.get("enrollment_id")
    public_key = payload.get("public_key")
    fingerprint = payload.get("fingerprint")
    challenge_signature = payload.get("challenge_signature")

    if not enrollment_id or not public_key or not fingerprint or not challenge_signature:
        return {"error": "enrollment_id, public_key, fingerprint, and challenge_signature are required"}, 400

    try:
        enrollment_uuid = uuid.UUID(enrollment_id)
    except ValueError:
        return {"error": "invalid_enrollment_id"}, 400

    enrollment = db.session.get(DeviceEnrollment, enrollment_uuid)
    if enrollment is None:
        return {"error": "enrollment_not_found"}, 404
    if enrollment.status != "approved":
        return {"error": "enrollment_not_approved"}, 409
    if ensure_aware(enrollment.expires_at) < utcnow():
        enrollment.status = "expired"
        db.session.commit()
        return {"error": "enrollment_expired"}, 410

    verified, reason = verify_enrollment_signature(
        public_key_pem=public_key,
        challenge=enrollment.challenge,
        signature_b64=challenge_signature,
    )
    if not verified:
        return {"error": "challenge_signature_invalid", "reason": reason}, 400

    user = db.session.get(User, enrollment.user_id) if enrollment.user_id else None
    if user is None:
        user = User.query.filter_by(email=enrollment.user_email).one_or_none()
    if user is None:
        user = User(
            id=uuid.uuid4(),
            email=enrollment.user_email,
            display_name=enrollment.user_email,
            status="active",
        )
        db.session.add(user)
        db.session.flush()

    posture = _clean_posture(payload.get("posture", {}))
    posture_ok, posture_reason, posture_context = evaluate_device_enrollment_posture(posture)
    if not posture_ok:
        record_audit_event(
            event_type="device.enrollment_posture_denied",
            outcome="denied",
            actor_user_id=user.id,
            target_type="device_enrollment",
            target_id=enrollment.id,
            reason=posture_reason,
            metadata={
                "device_name": enrollment.device_name,
                "platform": enrollment.platform,
                "posture": posture_context,
            },
        )
        db.session.commit()
        return {"error": posture_reason, "posture": posture_context}, 403

    device = Device.query.filter_by(fingerprint=fingerprint).one_or_none()
    was_existing = device is not None
    if device is None:
        device = Device(
            user_id=user.id,
            name=enrollment.device_name,
            platform=enrollment.platform,
            trust_level="software",
            status="trusted",
            hardware_backed=False,
            public_key=public_key,
            fingerprint=fingerprint,
            posture=posture,
            last_seen_at=utcnow(),
        )
        db.session.add(device)
    else:
        device.user_id = user.id
        device.name = enrollment.device_name or device.name
        device.platform = enrollment.platform or device.platform
        device.public_key = public_key
        device.status = "trusted"
        device.revoked_at = None
        if posture:
            device.posture = posture
        device.last_seen_at = utcnow()
    enrollment.status = "completed"
    enrollment.completed_at = utcnow()
    record_audit_event(
        event_type="device.reenrolled" if was_existing else "device.enrolled",
        outcome="success",
        actor_user_id=user.id,
        actor_device_id=device.id,
        target_type="device",
        target_id=device.id,
        metadata={
            "platform": device.platform,
            "fingerprint": device.fingerprint,
            "device_fingerprint": (device.posture or {}).get("device_fingerprint"),
            "hostname": (device.posture or {}).get("hostname"),
            "reenrolled": was_existing,
        },
    )
    db.session.commit()

    return {
        "device_id": str(device.id),
        "user_id": str(user.id),
        "status": device.status,
        "trust_level": device.trust_level,
    }, 201


def update_device_inventory(device_id: str, payload: dict) -> tuple[dict, int]:
    try:
        device_uuid = uuid.UUID(device_id)
    except ValueError:
        return {"error": "invalid_device_id"}, 400

    device = db.session.get(Device, device_uuid)
    if device is None:
        return {"error": "device_not_found"}, 404
    if device.status == "revoked":
        return {"error": "device_revoked", "status": device.status}, 403

    posture = _clean_posture(payload.get("posture", {}))
    if posture:
        device.posture = posture
    device.last_seen_at = utcnow()
    record_audit_event(
        event_type="device.inventory_updated",
        outcome="success",
        actor_device_id=device.id,
        target_type="device",
        target_id=device.id,
        metadata={
            "hostname": posture.get("hostname"),
            "device_fingerprint": posture.get("device_fingerprint"),
            "os": posture.get("os"),
            "hardware": posture.get("hardware", {}),
        },
    )
    db.session.commit()
    return {
        "device_id": str(device.id),
        "status": device.status,
        "last_seen_at": device.last_seen_at.isoformat(),
    }, 200


def revoke_device(device_id: str, payload: dict) -> tuple[dict, int]:
    try:
        device_uuid = uuid.UUID(device_id)
    except ValueError:
        return {"error": "invalid_device_id"}, 400

    device = db.session.get(Device, device_uuid)
    if device is None:
        return {"error": "device_not_found"}, 404

    device.status = "revoked"
    device.revoked_at = utcnow()
    record_audit_event(
        event_type="device.revoked",
        outcome="success",
        actor_device_id=device.id,
        target_type="device",
        target_id=device.id,
        reason=payload.get("reason"),
    )
    db.session.commit()
    return {"device_id": str(device.id), "status": device.status, "revoked_at": device.revoked_at.isoformat()}, 200


def set_device_status(device_id: str, status: str, payload: dict | None = None) -> tuple[dict, int]:
    if status not in {"trusted", "suspended", "revoked"}:
        return {"error": "invalid_device_status"}, 400
    payload = payload or {}
    try:
        device_uuid = uuid.UUID(device_id)
    except ValueError:
        return {"error": "invalid_device_id"}, 400

    device = db.session.get(Device, device_uuid)
    if device is None:
        return {"error": "device_not_found"}, 404

    device.status = status
    if status == "revoked":
        device.revoked_at = utcnow()
    record_audit_event(
        event_type=f"device.{status}",
        outcome="success",
        actor_device_id=device.id,
        target_type="device",
        target_id=device.id,
        reason=payload.get("reason"),
    )
    db.session.commit()
    return {"device_id": str(device.id), "status": device.status}, 200


def device_access_summary(device_id: str) -> tuple[dict, int]:
    try:
        device_uuid = uuid.UUID(device_id)
    except ValueError:
        return {"error": "invalid_device_id"}, 400

    device = db.session.get(Device, device_uuid)
    if device is None:
        return {"error": "device_not_found"}, 404
    if device.status != "trusted":
        return {"error": "device_not_trusted", "status": device.status}, 403

    user = db.session.get(User, device.user_id)
    if user is None or user.status != "active":
        return {"error": "user_not_active", "status": user.status if user else "missing"}, 403
    device.last_seen_at = utcnow()
    db.session.commit()
    return {
        "company": "Keyward",
        "user": {
            "id": str(user.id),
            "email": user.email,
            "display_name": user.display_name,
        },
        "device": {
            "id": str(device.id),
            "name": device.name,
            "platform": device.platform,
            "status": device.status,
            "trust_level": device.trust_level,
            "posture": device.posture or {},
        },
        "servers": accessible_servers_for_user(device.user_id),
    }, 200


def _get_enrollment(enrollment_id: str) -> tuple[DeviceEnrollment | None, tuple[dict, int] | None]:
    try:
        enrollment_uuid = uuid.UUID(enrollment_id)
    except ValueError:
        return None, ({"error": "invalid_enrollment_id"}, 400)
    enrollment = db.session.get(DeviceEnrollment, enrollment_uuid)
    if enrollment is None:
        return None, ({"error": "enrollment_not_found"}, 404)
    return enrollment, None


def _generate_user_code() -> str:
    while True:
        raw = "".join(secrets.choice(USER_CODE_ALPHABET) for _ in range(8))
        code = f"{raw[:4]}-{raw[4:]}"
        if DeviceEnrollment.query.filter_by(user_code=code).one_or_none() is None:
            return code


def _valid_local_callback_url(callback_url: str) -> bool:
    parsed = urlparse(callback_url)
    return (
        parsed.scheme == "http"
        and parsed.hostname in {"127.0.0.1", "localhost"}
        and parsed.port is not None
        and parsed.path == "/callback"
    )


def _clean_posture(value) -> dict:
    if not isinstance(value, dict):
        return {}
    return value


def _device_enrollment_step_up_ok(user, *, password: str | None, authenticated_at: str | None) -> tuple[bool, str | None]:
    if user.auth_provider == "local":
        if not user.password_hash or not password:
            return False, "password_confirmation_required"
        if not check_password_hash(user.password_hash, password):
            return False, "password_confirmation_invalid"
        return True, None

    try:
        parsed = datetime.fromisoformat((authenticated_at or "").replace("Z", "+00:00"))
    except ValueError:
        return False, "recent_sso_login_required"
    max_age = current_app.config["DEVICE_ENROLLMENT_REAUTH_SECONDS"]
    if ensure_aware(parsed) < utcnow() - timedelta(seconds=max_age):
        return False, "recent_sso_login_required"
    return True, None
