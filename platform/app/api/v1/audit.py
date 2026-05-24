from flask import Blueprint, jsonify, request

from app.services.audit import list_audit_events

bp = Blueprint("audit", __name__)


@bp.get("/events")
def events_index():
    limit = int(request.args.get("limit", "100"))
    return jsonify(
        {
            "audit_events": list_audit_events(
                limit=limit,
                event_type=request.args.get("event_type"),
                outcome=request.args.get("outcome"),
            )
        }
    )
