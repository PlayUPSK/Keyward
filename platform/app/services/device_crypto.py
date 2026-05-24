import base64
import subprocess
import tempfile
from pathlib import Path


def verify_enrollment_signature(public_key_pem: str, challenge: str, signature_b64: str) -> tuple[bool, str | None]:
    return verify_device_signature(public_key_pem, challenge.encode("utf-8"), signature_b64)


def verify_device_signature(public_key_pem: str, message: bytes, signature_b64: str) -> tuple[bool, str | None]:
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError:
        return _verify_with_openssl(public_key_pem, message, signature_b64)

    try:
        public_key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
    except ValueError:
        return False, "invalid_public_key"

    if not isinstance(public_key, Ed25519PublicKey):
        return False, "unsupported_public_key_type"

    try:
        signature = base64.b64decode(signature_b64, validate=True)
    except ValueError:
        return False, "invalid_signature_encoding"

    try:
        public_key.verify(signature, message)
    except InvalidSignature:
        return False, "invalid_signature"

    return True, None


def _verify_with_openssl(public_key_pem: str, message: bytes, signature_b64: str) -> tuple[bool, str | None]:
    try:
        signature = base64.b64decode(signature_b64, validate=True)
    except ValueError:
        return False, "invalid_signature_encoding"

    with tempfile.TemporaryDirectory(prefix="keyward-device-verify-") as tmpdir:
        tmp_path = Path(tmpdir)
        public_key_path = tmp_path / "device_public.pem"
        signature_path = tmp_path / "challenge.sig"
        message_path = tmp_path / "message.bin"

        public_key_path.write_text(public_key_pem, encoding="utf-8")
        signature_path.write_bytes(signature)
        message_path.write_bytes(message)

        result = subprocess.run(
            [
                "openssl",
                "pkeyutl",
                "-verify",
                "-rawin",
                "-pubin",
                "-inkey",
                str(public_key_path),
                "-sigfile",
                str(signature_path),
                "-in",
                str(message_path),
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            return True, None

        detail = (result.stderr or result.stdout).strip()
        if "operation not supported" in detail.lower():
            return False, "cryptography_dependency_missing"
        return False, "invalid_signature"
