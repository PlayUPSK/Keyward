from flask import Blueprint, jsonify, request

from app.services.ssh_ca import request_ssh_certificate

bp = Blueprint("ssh_certificates", __name__)


@bp.post("/request")
def request_certificate():
    payload = request.get_json(silent=True) or {}
    result = request_ssh_certificate(payload)
    status_code = 201 if result["decision"] == "allow" else 403
    return jsonify(result), status_code
