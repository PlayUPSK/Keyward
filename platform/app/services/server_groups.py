import uuid

from app import db
from app.models.server import Server, ServerGroup, ServerGroupMember


def list_server_groups() -> list[dict]:
    return [_group_to_dict(group) for group in ServerGroup.query.order_by(ServerGroup.name.asc()).all()]


def create_server_group(payload: dict) -> tuple[dict, int]:
    if not payload.get("name"):
        return {"error": "name is required"}, 400

    group = ServerGroup(name=payload["name"], description=payload.get("description"))
    db.session.add(group)
    db.session.commit()
    return _group_to_dict(group), 201


def add_server_to_group(group_id: str, payload: dict) -> tuple[dict, int]:
    server_id = payload.get("server_id")
    if not server_id:
        return {"error": "server_id is required"}, 400
    try:
        group_uuid = uuid.UUID(group_id)
        server_uuid = uuid.UUID(server_id)
    except ValueError:
        return {"error": "invalid_uuid"}, 400

    group = db.session.get(ServerGroup, group_uuid)
    server = db.session.get(Server, server_uuid)
    if group is None:
        return {"error": "server_group_not_found"}, 404
    if server is None:
        return {"error": "server_not_found"}, 404

    existing = ServerGroupMember.query.filter_by(server_id=server.id, group_id=group.id).one_or_none()
    if existing is None:
        db.session.add(ServerGroupMember(server_id=server.id, group_id=group.id))
        db.session.commit()

    return {"server_id": str(server.id), "group_id": str(group.id), "status": "member"}, 200


def _group_to_dict(group: ServerGroup) -> dict:
    members = ServerGroupMember.query.filter_by(group_id=group.id).all()
    return {
        "id": str(group.id),
        "name": group.name,
        "description": group.description,
        "server_ids": [str(member.server_id) for member in members],
        "created_at": group.created_at.isoformat(),
        "updated_at": group.updated_at.isoformat(),
    }
