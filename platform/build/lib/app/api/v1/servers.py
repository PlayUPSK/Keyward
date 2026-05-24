from flask import Blueprint, jsonify, request

from app.services.servers import create_server_enrollment_token

bp = Blueprint("servers", __name__)


@bp.post("/enrollment-tokens")
def enrollment_tokens():
    payload = request.get_json(silent=True) or {}
    token = create_server_enrollment_token(payload)
    return jsonify(token), 201
