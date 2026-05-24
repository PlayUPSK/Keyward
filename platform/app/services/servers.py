import secrets
import hashlib
import ipaddress
import fnmatch
import uuid
from datetime import timedelta

from flask import current_app

from app import db
from app.models.base import utcnow
from app.models.enrollment import ServerEnrollmentToken
from app.models.server import Server
from app.services.audit import record_audit_event
from app.services.timeparse import ensure_aware


def create_server_enrollment_token(payload: dict, actor_user_id=None) -> dict:
    hostname_pattern = str(payload.get("hostname") or "").strip()
    if not hostname_pattern:
        return {
            "error": "hostname pattern is required",
            "status": "invalid",
        }

    allowed_cidrs, cidr_error = _parse_allowed_cidrs(payload.get("allowed_cidrs"))
    if cidr_error:
        return {"error": cidr_error, "status": "invalid"}

    max_uses = _bounded_int(
        payload.get("max_uses"),
        default=1,
        minimum=1,
        maximum=current_app.config["SERVER_ENROLLMENT_MAX_USES_LIMIT"],
    )
    ttl_minutes = _bounded_int(
        payload.get("ttl_minutes"),
        default=current_app.config["SERVER_ENROLLMENT_DEFAULT_TTL_MINUTES"],
        minimum=1,
        maximum=current_app.config["SERVER_ENROLLMENT_MAX_TTL_MINUTES"],
    )

    raw_token = secrets.token_urlsafe(32)
    token_hash = _hash_token(raw_token)
    expires_at = utcnow() + timedelta(minutes=ttl_minutes)
    token = ServerEnrollmentToken(
        hostname=hostname_pattern,
        token_hash=token_hash,
        expires_at=expires_at,
        token_metadata={
            "environment": payload.get("environment", "lab"),
            "hostname_pattern": hostname_pattern,
            "allowed_cidrs": allowed_cidrs,
            "max_uses": max_uses,
            "redeemed_count": 0,
            "tags": _clean_tags(payload.get("tags")),
            "note": payload.get("note") or "",
        },
    )
    db.session.add(token)
    record_audit_event(
        event_type="server_enrollment_token.created",
        outcome="success",
        actor_user_id=actor_user_id,
        target_type="server_enrollment_token",
        target_id=token.id,
        metadata={
            "hostname_pattern": hostname_pattern,
            "environment": token.token_metadata["environment"],
            "allowed_cidrs": allowed_cidrs,
            "max_uses": max_uses,
            "expires_at": expires_at.isoformat(),
        },
    )
    db.session.commit()

    return {
        "token": raw_token,
        "token_id": str(token.id),
        "expires_at": expires_at.isoformat(),
        "server_name": hostname_pattern,
        "hostname_pattern": hostname_pattern,
        "allowed_cidrs": allowed_cidrs,
        "max_uses": max_uses,
    }


def list_server_enrollment_tokens(limit: int = 50) -> list[ServerEnrollmentToken]:
    return ServerEnrollmentToken.query.order_by(ServerEnrollmentToken.created_at.desc()).limit(limit).all()


def update_server_enrollment_token(token_id: str, payload: dict, actor_user_id=None) -> tuple[dict, int]:
    token = _get_server_enrollment_token(token_id)
    if token is None:
        return {"error": "token_not_found"}, 404
    if token.status != "pending":
        return {"error": "only_pending_tokens_can_be_edited"}, 409

    metadata = dict(token.token_metadata or {})
    hostname_pattern = str(payload.get("hostname") or "").strip()
    if not hostname_pattern:
        return {"error": "hostname pattern is required"}, 400
    allowed_cidrs, cidr_error = _parse_allowed_cidrs(payload.get("allowed_cidrs"))
    if cidr_error:
        return {"error": cidr_error}, 400

    redeemed_count = int(metadata.get("redeemed_count") or 0)
    max_uses = _bounded_int(
        payload.get("max_uses"),
        default=int(metadata.get("max_uses") or 1),
        minimum=max(1, redeemed_count),
        maximum=current_app.config["SERVER_ENROLLMENT_MAX_USES_LIMIT"],
    )

    token.hostname = hostname_pattern
    metadata.update(
        {
            "hostname_pattern": hostname_pattern,
            "environment": payload.get("environment") or metadata.get("environment") or "lab",
            "allowed_cidrs": allowed_cidrs,
            "max_uses": max_uses,
            "note": payload.get("note") or "",
        }
    )
    token.token_metadata = metadata
    record_audit_event(
        event_type="server_enrollment_token.updated",
        outcome="success",
        actor_user_id=actor_user_id,
        target_type="server_enrollment_token",
        target_id=token.id,
        metadata={
            "hostname_pattern": hostname_pattern,
            "environment": metadata.get("environment"),
            "allowed_cidrs": allowed_cidrs,
            "max_uses": max_uses,
        },
    )
    db.session.commit()
    return {"token_id": str(token.id), "status": token.status}, 200


def delete_server_enrollment_token(token_id: str, actor_user_id=None) -> tuple[dict, int]:
    token = _get_server_enrollment_token(token_id)
    if token is None:
        return {"error": "token_not_found"}, 404
    record_audit_event(
        event_type="server_enrollment_token.deleted",
        outcome="success",
        actor_user_id=actor_user_id,
        target_type="server_enrollment_token",
        target_id=token.id,
        metadata={
            "hostname_pattern": (token.token_metadata or {}).get("hostname_pattern") or token.hostname,
            "status": token.status,
        },
    )
    db.session.delete(token)
    db.session.commit()
    return {"token_id": token_id, "status": "deleted"}, 200


def redeem_server_enrollment_token(payload: dict, source_ip: str | None = None) -> tuple[dict, int]:
    raw_token = payload.get("token")
    public_key = payload.get("public_key")
    agent_version = payload.get("agent_version")
    if not raw_token or not public_key:
        return {"error": "token and public_key are required"}, 400

    token = ServerEnrollmentToken.query.filter_by(token_hash=_hash_token(raw_token)).one_or_none()
    if token is None:
        return {"error": "token_not_found"}, 404
    if token.status != "pending":
        return {"error": "token_not_pending"}, 409
    if ensure_aware(token.expires_at) < utcnow():
        token.status = "expired"
        db.session.commit()
        return {"error": "token_expired"}, 410

    metadata = dict(token.token_metadata or {})
    hostname_pattern = str(metadata.get("hostname_pattern") or token.hostname or "").strip()
    requested_hostname = str(payload.get("hostname") or token.hostname or "").strip()
    if not requested_hostname:
        return {"error": "hostname_required"}, 400
    if not _hostname_matches_pattern(requested_hostname, hostname_pattern):
        record_audit_event(
            event_type="server_enrollment.denied",
            outcome="denied",
            target_type="server_enrollment_token",
            target_id=token.id,
            source_ip=source_ip,
            reason="hostname_not_allowed",
            metadata={
                "hostname": requested_hostname,
                "hostname_pattern": hostname_pattern,
            },
        )
        db.session.commit()
        return {"error": "hostname_not_allowed"}, 403

    if not _source_ip_allowed(source_ip, metadata.get("allowed_cidrs") or []):
        record_audit_event(
            event_type="server_enrollment.denied",
            outcome="denied",
            target_type="server_enrollment_token",
            target_id=token.id,
            source_ip=source_ip,
            reason="source_ip_not_allowed",
            metadata={
                "hostname": requested_hostname,
                "hostname_pattern": hostname_pattern,
                "allowed_cidrs": metadata.get("allowed_cidrs") or [],
            },
        )
        db.session.commit()
        return {"error": "source_ip_not_allowed"}, 403

    existing_server = (
        Server.query.filter(Server.hostname == requested_hostname, Server.status != "decommissioned")
        .order_by(Server.created_at.desc())
        .first()
    )
    if existing_server is not None:
        record_audit_event(
            event_type="server_enrollment.denied",
            outcome="denied",
            target_type="server_enrollment_token",
            target_id=token.id,
            source_ip=source_ip,
            reason="hostname_already_enrolled",
            metadata={
                "hostname": requested_hostname,
                "existing_server_id": str(existing_server.id),
            },
        )
        db.session.commit()
        return {"error": "hostname_already_enrolled"}, 409

    server = Server(
        hostname=requested_hostname,
        environment=metadata.get("environment", "lab"),
        status="enrolled",
        agent_version=agent_version,
        public_key=public_key,
        tags={**(metadata.get("tags") or {}), **_clean_tags(payload.get("tags"))},
        last_seen_at=utcnow(),
    )
    db.session.add(server)
    db.session.flush()

    redeemed_count = int(metadata.get("redeemed_count") or 0) + 1
    max_uses = int(metadata.get("max_uses") or 1)
    metadata["redeemed_count"] = redeemed_count
    token.token_metadata = metadata
    if redeemed_count >= max_uses:
        token.status = "redeemed"
    token.redeemed_by_server_id = server.id
    token.redeemed_at = utcnow()
    record_audit_event(
        event_type="server.enrolled",
        outcome="success",
        target_type="server",
        target_id=server.id,
        source_ip=source_ip,
        metadata={
            "hostname": server.hostname,
            "hostname_pattern": hostname_pattern,
            "environment": server.environment,
            "agent_version": agent_version,
            "token_id": str(token.id),
            "redeemed_count": redeemed_count,
            "max_uses": max_uses,
        },
    )
    db.session.commit()

    return {
        "server_id": str(server.id),
        "hostname": server.hostname,
        "status": server.status,
    }, 201


def _hash_token(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def _get_server_enrollment_token(token_id: str) -> ServerEnrollmentToken | None:
    try:
        return db.session.get(ServerEnrollmentToken, uuid.UUID(str(token_id)))
    except ValueError:
        return None


def _bounded_int(value, *, default: int, minimum: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    return max(minimum, min(maximum, parsed))


def _parse_allowed_cidrs(value) -> tuple[list[str], str | None]:
    if value is None:
        return [], None
    if isinstance(value, str):
        raw_values = [item.strip() for item in value.replace("\n", ",").split(",")]
    elif isinstance(value, list):
        raw_values = [str(item).strip() for item in value]
    else:
        return [], "invalid_allowed_cidrs"

    cidrs = []
    for item in raw_values:
        if not item:
            continue
        try:
            cidrs.append(str(ipaddress.ip_network(item, strict=False)))
        except ValueError:
            return [], "invalid_allowed_cidr"
    return sorted(set(cidrs)), None


def _source_ip_allowed(source_ip: str | None, allowed_cidrs: list[str]) -> bool:
    if not allowed_cidrs:
        return True
    if not source_ip:
        return False
    try:
        ip = ipaddress.ip_address(source_ip)
    except ValueError:
        return False
    return any(ip in ipaddress.ip_network(cidr, strict=False) for cidr in allowed_cidrs)


def _hostname_matches_pattern(hostname: str, pattern: str) -> bool:
    if not pattern:
        return False
    normalized_hostname = hostname.strip().lower()
    normalized_pattern = pattern.strip().lower()
    return fnmatch.fnmatchcase(normalized_hostname, normalized_pattern)


def _clean_tags(value) -> dict:
    if not isinstance(value, dict):
        return {}
    return {str(key): str(val) for key, val in value.items() if str(key).strip()}
