from flask import Blueprint, jsonify, request

from app.services.devices import (
    device_access_summary,
    finish_device_enrollment,
    poll_device_login_enrollment,
    revoke_device,
    start_device_login_enrollment,
    update_device_inventory,
)

bp = Blueprint("devices", __name__)


@bp.post("/enroll/start")
def enroll_start():
    return jsonify({"error": "legacy_direct_enrollment_disabled"}), 410


@bp.post("/enroll/start-login")
def enroll_start_login():
    payload = request.get_json(silent=True) or {}
    result, status_code = start_device_login_enrollment(payload)
    return jsonify(result), status_code


@bp.get("/enroll/<enrollment_id>/poll")
def enroll_poll(enrollment_id):
    result, status_code = poll_device_login_enrollment(enrollment_id)
    return jsonify(result), status_code


@bp.post("/enroll/finish")
def enroll_finish():
    payload = request.get_json(silent=True) or {}
    result, status_code = finish_device_enrollment(payload)
    return jsonify(result), status_code


@bp.post("/<device_id>/revoke")
def revoke(device_id):
    payload = request.get_json(silent=True) or {}
    result, status_code = revoke_device(device_id, payload)
    return jsonify(result), status_code


@bp.post("/<device_id>/inventory")
def inventory(device_id):
    payload = request.get_json(silent=True) or {}
    result, status_code = update_device_inventory(device_id, payload)
    return jsonify(result), status_code


@bp.get("/<device_id>/access")
def access(device_id):
    result, status_code = device_access_summary(device_id)
    return jsonify(result), status_code
