from flask import Blueprint, jsonify, request

from app.services.devices import start_device_enrollment

bp = Blueprint("devices", __name__)


@bp.post("/enroll/start")
def enroll_start():
    payload = request.get_json(silent=True) or {}
    enrollment = start_device_enrollment(payload)
    return jsonify(enrollment), 202
