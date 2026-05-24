import json
import uuid

from app import db
from app.models.audit import AuditEvent


def record_audit_event(
    *,
    event_type: str,
    outcome: str,
    reason: str | None = None,
    actor_user_id=None,
    actor_device_id=None,
    target_type: str | None = None,
    target_id=None,
    source_ip: str | None = None,
    user_agent: str | None = None,
    metadata: dict | None = None,
) -> AuditEvent:
    event = AuditEvent(
        event_type=event_type,
        actor_user_id=actor_user_id,
        actor_device_id=actor_device_id,
        target_type=target_type,
        target_id=target_id,
        source_ip=source_ip,
        user_agent=user_agent,
        outcome=outcome,
        reason=reason,
        event_metadata=metadata or {},
    )
    db.session.add(event)
    return event


def list_audit_events(
    limit: int = 100,
    event_type: str | None = None,
    outcome: str | None = None,
    actor_user_id: str | None = None,
    target_type: str | None = None,
    source_ip: str | None = None,
    reason: str | None = None,
    metadata_query: str | None = None,
) -> list[dict]:
    query = AuditEvent.query
    if event_type:
        query = query.filter_by(event_type=event_type)
    if outcome:
        query = query.filter_by(outcome=outcome)
    if actor_user_id:
        query = query.filter_by(actor_user_id=actor_user_id)
    if target_type:
        query = query.filter_by(target_type=target_type)
    if source_ip:
        query = query.filter(AuditEvent.source_ip.ilike(f"%{source_ip}%"))
    if reason:
        query = query.filter(AuditEvent.reason.ilike(f"%{reason}%"))

    fetch_limit = min(max(limit, 1), 500)
    if metadata_query:
        fetch_limit = min(fetch_limit * 5, 1000)

    events = query.order_by(AuditEvent.created_at.desc()).limit(fetch_limit).all()
    if metadata_query:
        needle = metadata_query.lower()
        events = [event for event in events if needle in _metadata_text(event).lower()]
        events = events[: min(max(limit, 1), 500)]
    return [_event_to_dict(event) for event in events]


def audit_filter_options() -> dict:
    event_types = [row[0] for row in db.session.query(AuditEvent.event_type).distinct().order_by(AuditEvent.event_type.asc()).all() if row[0]]
    outcomes = [row[0] for row in db.session.query(AuditEvent.outcome).distinct().order_by(AuditEvent.outcome.asc()).all() if row[0]]
    target_types = [row[0] for row in db.session.query(AuditEvent.target_type).distinct().order_by(AuditEvent.target_type.asc()).all() if row[0]]
    return {
        "event_types": event_types,
        "outcomes": outcomes,
        "target_types": target_types,
    }


def parse_optional_uuid(value: str | None):
    if not value:
        return None
    return uuid.UUID(value)


def _event_to_dict(event: AuditEvent) -> dict:
    return {
        "id": str(event.id),
        "event_type": event.event_type,
        "actor_user_id": str(event.actor_user_id) if event.actor_user_id else None,
        "actor_device_id": str(event.actor_device_id) if event.actor_device_id else None,
        "target_type": event.target_type,
        "target_id": str(event.target_id) if event.target_id else None,
        "source_ip": event.source_ip,
        "user_agent": event.user_agent,
        "outcome": event.outcome,
        "reason": event.reason,
        "metadata": event.event_metadata,
        "created_at": event.created_at.isoformat(),
    }


def _metadata_text(event: AuditEvent) -> str:
    payload = {
        "metadata": event.event_metadata or {},
        "event_type": event.event_type,
        "reason": event.reason,
        "source_ip": event.source_ip,
        "user_agent": event.user_agent,
        "target_type": event.target_type,
        "target_id": str(event.target_id) if event.target_id else None,
    }
    return json.dumps(payload, sort_keys=True, default=str)
