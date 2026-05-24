from datetime import timedelta

from app.models.base import utcnow


REQUIRED_CERT_REQUEST_FIELDS = {
    "request_id",
    "device_id",
    "server",
    "ssh_principal",
    "ephemeral_ssh_public_key",
    "nonce",
    "timestamp",
    "signature",
}


def request_ssh_certificate(payload: dict) -> dict:
    missing = sorted(REQUIRED_CERT_REQUEST_FIELDS - payload.keys())
    if missing:
        return {
            "decision": "deny",
            "reason": "missing_required_fields",
            "missing": missing,
        }

    now = utcnow()
    return {
        "decision": "allow",
        "reason": "mvp_policy_placeholder",
        "valid_after": now.isoformat(),
        "valid_before": (now + timedelta(minutes=5)).isoformat(),
        "certificate": None,
        "constraints": {
            "permit_pty": True,
            "permit_agent_forwarding": False,
            "permit_x11_forwarding": False,
        },
    }
