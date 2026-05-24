from flask import Blueprint, jsonify, request

from app.services.policies import (
    create_access_grant,
    create_policy,
    list_access_grants,
    list_policies,
    simulate_access,
)

bp = Blueprint("policies", __name__)


@bp.get("")
def policies_index():
    return jsonify({"policies": list_policies()})


@bp.post("")
def policies_create():
    payload = request.get_json(silent=True) or {}
    result, status_code = create_policy(payload)
    return jsonify(result), status_code


@bp.post("/simulate")
def policies_simulate():
    payload = request.get_json(silent=True) or {}
    return jsonify(simulate_access(payload))


@bp.get("/access-grants")
def access_grants_index():
    return jsonify({"access_grants": list_access_grants()})


@bp.post("/access-grants")
def access_grants_create():
    payload = request.get_json(silent=True) or {}
    result, status_code = create_access_grant(payload)
    return jsonify(result), status_code
