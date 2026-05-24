from flask import Blueprint, jsonify, request

from app.services.servers import create_server_enrollment_token, redeem_server_enrollment_token
from app.services.server_groups import add_server_to_group, create_server_group, list_server_groups
from app.services.server_trust import get_trusted_user_ca
from app.services.revocation import get_revocation_state
from app.services.auth import ADMIN_ROLE, current_user, current_user_roles

bp = Blueprint("servers", __name__)


@bp.post("/enrollment-tokens")
def enrollment_tokens():
    if current_user() is None or ADMIN_ROLE not in current_user_roles():
        return jsonify({"error": "admin_required"}), 403
    payload = request.get_json(silent=True) or {}
    token = create_server_enrollment_token(payload, actor_user_id=current_user().id)
    if token.get("error"):
        return jsonify(token), 400
    return jsonify(token), 201


@bp.post("/enroll")
def enroll():
    payload = request.get_json(silent=True) or {}
    result, status_code = redeem_server_enrollment_token(payload, source_ip=request.remote_addr)
    return jsonify(result), status_code


@bp.get("/trusted-user-ca")
def trusted_user_ca():
    result, status_code = get_trusted_user_ca()
    return jsonify(result), status_code


@bp.get("/revocation-state")
def revocation_state():
    server_id = request.headers.get("X-Keyward-Server-ID") or request.headers.get("X-Passkey-Server-ID")
    return jsonify(get_revocation_state(server_id=server_id))


@bp.get("/groups")
def groups_index():
    return jsonify({"server_groups": list_server_groups()})


@bp.post("/groups")
def groups_create():
    payload = request.get_json(silent=True) or {}
    result, status_code = create_server_group(payload)
    return jsonify(result), status_code


@bp.post("/groups/<group_id>/members")
def groups_add_member(group_id):
    payload = request.get_json(silent=True) or {}
    result, status_code = add_server_to_group(group_id, payload)
    return jsonify(result), status_code
