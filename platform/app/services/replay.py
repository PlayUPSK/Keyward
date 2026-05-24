from datetime import timedelta

from app import db
from app.models.device import Device
from app.models.replay import CertificateRequestNonce
from app.models.base import utcnow


def reserve_certificate_request_nonce(device: Device, request_id: str, nonce: str, window_seconds: int) -> tuple[bool, str | None]:
    now = utcnow()
    CertificateRequestNonce.query.filter(CertificateRequestNonce.expires_at < now).delete()

    existing_request = CertificateRequestNonce.query.filter_by(
        device_id=device.id,
        request_id=request_id,
    ).one_or_none()
    if existing_request is not None:
        db.session.commit()
        return False, "duplicate_request_id"

    existing_nonce = CertificateRequestNonce.query.filter_by(
        device_id=device.id,
        nonce=nonce,
    ).one_or_none()
    if existing_nonce is not None:
        db.session.commit()
        return False, "duplicate_nonce"

    db.session.add(
        CertificateRequestNonce(
            device_id=device.id,
            request_id=request_id,
            nonce=nonce,
            expires_at=now + timedelta(seconds=window_seconds),
        )
    )
    db.session.commit()
    return True, None
