import hashlib
from pathlib import Path

from flask import current_app


def get_trusted_user_ca() -> tuple[dict, int]:
    ca_private_key_path = Path(current_app.config["SSH_CA_KEY_PATH"])
    ca_public_key_path = ca_private_key_path.with_name(ca_private_key_path.name + ".pub")
    if not ca_public_key_path.exists():
        return {
            "error": "trusted_user_ca_not_found",
            "path": str(ca_public_key_path),
        }, 404

    public_key = ca_public_key_path.read_text(encoding="utf-8").strip()
    fingerprint = hashlib.sha256(public_key.encode("utf-8")).hexdigest()
    return {
        "trusted_user_ca_public_key": public_key,
        "fingerprint_sha256": fingerprint,
    }, 200
