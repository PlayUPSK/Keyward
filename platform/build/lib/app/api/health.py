from flask import Blueprint, jsonify

bp = Blueprint("health", __name__)


@bp.get("/healthz")
def healthz():
    return jsonify({"status": "ok"})


@bp.get("/readyz")
def readyz():
    return jsonify({"status": "ready"})
