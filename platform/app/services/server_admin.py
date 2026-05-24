import uuid

from app import db
from app.models.server import Server


def set_server_status(server_id: str, status: str) -> tuple[dict, int]:
    if status not in {"pending", "enrolled", "suspended", "retired"}:
        return {"error": "invalid_server_status"}, 400
    try:
        parsed_id = uuid.UUID(server_id)
    except ValueError:
        return {"error": "invalid_server_id"}, 400
    server = db.session.get(Server, parsed_id)
    if server is None:
        return {"error": "server_not_found"}, 404
    server.status = status
    db.session.commit()
    return {"server_id": str(server.id), "status": server.status}, 200
