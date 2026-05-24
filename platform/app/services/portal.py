from app.models.device import Device
from app.models.identity import UserGroup
from app.models.policy import AccessGrant
from app.models.server import Server, ServerGroupMember
from app.models.base import utcnow
from app.services.timeparse import ensure_aware


def user_devices(user_id) -> list[Device]:
    return Device.query.filter_by(user_id=user_id).order_by(Device.created_at.desc()).all()


def accessible_servers_for_user(user_id) -> list[dict]:
    now = utcnow()
    group_ids = {row.group_id for row in UserGroup.query.filter_by(user_id=user_id).all()}
    grants = AccessGrant.query.all()
    results: dict[str, dict] = {}

    for grant in grants:
        if grant.valid_from and ensure_aware(grant.valid_from) > now:
            continue
        if grant.valid_until and ensure_aware(grant.valid_until) < now:
            continue
        if grant.subject_type == "user" and grant.subject_id != user_id:
            continue
        if grant.subject_type == "group" and grant.subject_id not in group_ids:
            continue

        for server in _servers_for_grant(grant):
            entry = results.setdefault(
                str(server.id),
                {
                    "id": str(server.id),
                    "hostname": server.hostname,
                    "environment": server.environment,
                    "status": server.status,
                    "principals": set(),
                },
            )
            entry["principals"].update(grant.unix_principals)

    return [
        {
            **entry,
            "principals": sorted(entry["principals"]),
        }
        for entry in sorted(results.values(), key=lambda item: item["hostname"])
    ]


def _servers_for_grant(grant: AccessGrant) -> list[Server]:
    if grant.server_scope_type == "all":
        return Server.query.order_by(Server.hostname.asc()).all()
    if grant.server_scope_type == "server":
        server = Server.query.filter_by(id=grant.server_scope_id).one_or_none()
        return [server] if server else []
    if grant.server_scope_type == "server_group":
        members = ServerGroupMember.query.filter_by(group_id=grant.server_scope_id).all()
        ids = [member.server_id for member in members]
        if not ids:
            return []
        return Server.query.filter(Server.id.in_(ids)).order_by(Server.hostname.asc()).all()
    return []
