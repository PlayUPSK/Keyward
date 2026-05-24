import os
import secrets
import subprocess
import tempfile
from pathlib import Path


class SSHSigningError(RuntimeError):
    pass


def sign_user_certificate(
    *,
    ca_key_path: str,
    public_key: str,
    key_id: str,
    serial: int,
    principals: list[str],
    ttl_seconds: int,
) -> str:
    ca_path = Path(ca_key_path)
    if not ca_path.exists():
        raise SSHSigningError(f"SSH CA private key does not exist: {ca_key_path}")
    if not principals:
        raise SSHSigningError("at least one principal is required")

    with tempfile.TemporaryDirectory(prefix="keyward-ssh-cert-") as tmpdir:
        pubkey_path = Path(tmpdir) / "request.pub"
        pubkey_path.write_text(public_key.rstrip() + "\n", encoding="utf-8")

        validity = f"+{ttl_seconds}s"
        cmd = [
            "ssh-keygen",
            "-q",
            "-s",
            os.fspath(ca_path),
            "-I",
            key_id,
            "-z",
            str(serial),
            "-n",
            ",".join(principals),
            "-V",
            validity,
            os.fspath(pubkey_path),
        ]
        result = subprocess.run(cmd, check=False, capture_output=True, text=True)
        if result.returncode != 0:
            detail = (result.stderr or result.stdout).strip()
            raise SSHSigningError(detail or "ssh-keygen failed to sign certificate")

        cert_path = Path(tmpdir) / "request-cert.pub"
        if not cert_path.exists():
            raise SSHSigningError("ssh-keygen did not produce a certificate")
        return cert_path.read_text(encoding="utf-8").strip()


def generate_serial() -> int:
    return secrets.randbits(62)
