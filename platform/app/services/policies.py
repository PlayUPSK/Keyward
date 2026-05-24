import uuid

from app import db
from app.models.identity import Group, User
from app.models.policy import AccessGrant, Policy
from app.models.server import Server, ServerGroup
from app.models.base import utcnow
from app.services.audit import record_audit_event
from app.services.policy_engine import simulate_policy
from app.services.timeparse import parse_datetime


def list_policies() -> list[dict]:
    return [_policy_to_dict(policy) for policy in Policy.query.order_by(Policy.priority.asc()).all()]


def create_policy(payload: dict) -> tuple[dict, int]:
    if not payload.get("name") or payload.get("effect") not in {"allow", "deny"}:
        return {"error": "name and effect allow/deny are required"}, 400

    policy = Policy(
        name=payload["name"],
        priority=int(payload.get("priority", 1000)),
        enabled=bool(payload.get("enabled", True)),
        effect=payload["effect"],
        conditions=payload.get("conditions", {}),
        actions=payload.get("actions", {}),
    )
    db.session.add(policy)
    db.session.commit()
    return _policy_to_dict(policy), 201


def set_policy_enabled(policy_id: str, enabled: bool) -> tuple[dict, int]:
    try:
        parsed_id = uuid.UUID(policy_id)
    except ValueError:
        return {"error": "invalid_policy_id"}, 400
    policy = db.session.get(Policy, parsed_id)
    if policy is None:
        return {"error": "policy_not_found"}, 404
    policy.enabled = enabled
    db.session.commit()
    return _policy_to_dict(policy), 200


def invalidate_policy(policy_id: str, reason: str | None = None) -> tuple[dict, int]:
    try:
        parsed_id = uuid.UUID(policy_id)
    except ValueError:
        return {"error": "invalid_policy_id"}, 400
    policy = db.session.get(Policy, parsed_id)
    if policy is None:
        return {"error": "policy_not_found"}, 404

    actions = dict(policy.actions or {})
    actions["invalidated"] = True
    actions["invalidated_at"] = utcnow().isoformat()
    actions["invalidated_reason"] = reason or "admin_policy_invalidation"
    policy.actions = actions
    policy.enabled = False
    record_audit_event(
        event_type="policy.invalidated",
        outcome="success",
        reason=actions["invalidated_reason"],
        target_type="policy",
        target_id=policy.id,
        metadata={"policy_name": policy.name},
    )
    db.session.commit()
    return _policy_to_dict(policy), 200


def delete_policy(policy_id: str) -> tuple[dict, int]:
    try:
        parsed_id = uuid.UUID(policy_id)
    except ValueError:
        return {"error": "invalid_policy_id"}, 400
    policy = db.session.get(Policy, parsed_id)
    if policy is None:
        return {"error": "policy_not_found"}, 404
    db.session.delete(policy)
    db.session.commit()
    return {"status": "deleted", "policy_id": policy_id}, 200


def list_access_grants() -> list[dict]:
    grants = AccessGrant.query.order_by(AccessGrant.created_at.desc()).all()
    labels = _grant_labels(grants)
    return [_grant_to_dict(grant, **labels) for grant in grants]


def create_access_grant(payload: dict) -> tuple[dict, int]:
    required = {"subject_type", "subject_id", "server_scope_type", "unix_principals"}
    missing = sorted(required - payload.keys())
    if missing:
        return {"error": "missing_required_fields", "missing": missing}, 400
    if payload["subject_type"] not in {"user", "group"}:
        return {"error": "subject_type must be user or group"}, 400
    if payload["server_scope_type"] not in {"server", "server_group", "all"}:
        return {"error": "server_scope_type must be server, server_group, or all"}, 400

    try:
        subject_id = uuid.UUID(payload["subject_id"])
        server_scope_id = (
            uuid.UUID(payload["server_scope_id"])
            if payload.get("server_scope_id")
            else None
        )
    except ValueError:
        return {"error": "invalid_uuid"}, 400

    principals = payload["unix_principals"]
    if not isinstance(principals, list) or not principals:
        return {"error": "unix_principals must be a non-empty list"}, 400

    grant = AccessGrant(
        subject_type=payload["subject_type"],
        subject_id=subject_id,
        server_scope_type=payload["server_scope_type"],
        server_scope_id=server_scope_id,
        unix_principals=principals,
        valid_from=parse_datetime(payload.get("valid_from")),
        valid_until=parse_datetime(payload.get("valid_until")),
    )
    db.session.add(grant)
    db.session.commit()
    return _grant_to_dict_with_labels(grant), 201


def delete_access_grant(grant_id: str) -> tuple[dict, int]:
    try:
        parsed_id = uuid.UUID(grant_id)
    except ValueError:
        return {"error": "invalid_grant_id"}, 400
    grant = db.session.get(AccessGrant, parsed_id)
    if grant is None:
        return {"error": "grant_not_found"}, 404
    db.session.delete(grant)
    db.session.commit()
    return {"status": "deleted", "grant_id": grant_id}, 200


def simulate_access(payload: dict) -> dict:
    return simulate_policy(payload)


def _policy_to_dict(policy: Policy) -> dict:
    return {
        "id": str(policy.id),
        "name": policy.name,
        "priority": policy.priority,
        "enabled": policy.enabled,
        "effect": policy.effect,
        "conditions": policy.conditions,
        "actions": policy.actions,
        "invalidated": bool((policy.actions or {}).get("invalidated")),
        "invalidated_at": (policy.actions or {}).get("invalidated_at"),
        "invalidated_reason": (policy.actions or {}).get("invalidated_reason"),
        "created_at": policy.created_at.isoformat(),
        "updated_at": policy.updated_at.isoformat(),
    }


def _grant_to_dict(
    grant: AccessGrant,
    *,
    user_labels: dict[str, str],
    group_labels: dict[str, str],
    server_labels: dict[str, str],
    server_group_labels: dict[str, str],
    policy_labels: dict[str, str],
) -> dict:
    subject_id = str(grant.subject_id)
    server_scope_id = str(grant.server_scope_id) if grant.server_scope_id else None
    if grant.subject_type == "user":
        subject_name = user_labels.get(subject_id)
    else:
        subject_name = group_labels.get(subject_id)

    if grant.server_scope_type == "server":
        scope_name = server_labels.get(server_scope_id or "")
    elif grant.server_scope_type == "server_group":
        scope_name = server_group_labels.get(server_scope_id or "")
    else:
        scope_name = "All enrolled servers"

    return {
        "id": str(grant.id),
        "subject_type": grant.subject_type,
        "subject_id": subject_id,
        "subject_name": subject_name,
        "subject_display": f"{grant.subject_type}: {subject_name or subject_id}",
        "server_scope_type": grant.server_scope_type,
        "server_scope_id": server_scope_id,
        "server_scope_name": scope_name,
        "server_scope_display": (
            scope_name if grant.server_scope_type == "all" else f"{grant.server_scope_type}: {scope_name or server_scope_id}"
        ),
        "unix_principals": grant.unix_principals,
        "policy_id": str(grant.policy_id) if grant.policy_id else None,
        "policy_name": policy_labels.get(str(grant.policy_id)) if grant.policy_id else None,
        "valid_from": grant.valid_from.isoformat() if grant.valid_from else None,
        "valid_until": grant.valid_until.isoformat() if grant.valid_until else None,
        "created_at": grant.created_at.isoformat(),
    }


def _label_map(model, ids: set[uuid.UUID], attribute: str) -> dict[str, str]:
    if not ids:
        return {}
    records = model.query.filter(model.id.in_(ids)).all()
    return {str(record.id): getattr(record, attribute) for record in records}


def _grant_to_dict_with_labels(grant: AccessGrant) -> dict:
    return _grant_to_dict(grant, **_grant_labels([grant]))


def _grant_labels(grants: list[AccessGrant]) -> dict[str, dict[str, str]]:
    return {
        "user_labels": _label_map(User, {grant.subject_id for grant in grants if grant.subject_type == "user"}, "email"),
        "group_labels": _label_map(Group, {grant.subject_id for grant in grants if grant.subject_type == "group"}, "name"),
        "server_labels": _label_map(
            Server,
            {grant.server_scope_id for grant in grants if grant.server_scope_type == "server" and grant.server_scope_id},
            "hostname",
        ),
        "server_group_labels": _label_map(
            ServerGroup,
            {grant.server_scope_id for grant in grants if grant.server_scope_type == "server_group" and grant.server_scope_id},
            "name",
        ),
        "policy_labels": _label_map(Policy, {grant.policy_id for grant in grants if grant.policy_id}, "name"),
    }
