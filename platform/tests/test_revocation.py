from datetime import timedelta

from app import create_app, db
from app.models.base import utcnow
from app.models.device import Device
from app.models.identity import User
from app.models.server import Server
from app.models.ssh_certificate import SSHCertificateIssuance
from app.services.revocation import get_revocation_state


def test_revocation_state_scopes_active_serials_to_server_id():
    app = create_app("app.config.TestConfig")

    with app.app_context():
        db.create_all()

        user = User(email="alice@example.com", display_name="Alice", status="suspended")
        server_one = Server(hostname="host-01", environment="prod", status="enrolled")
        server_two = Server(hostname="host-02", environment="prod", status="enrolled")
        db.session.add_all([user, server_one, server_two])
        db.session.flush()

        device = Device(
            user_id=user.id,
            name="alice-laptop",
            platform="linux",
            status="trusted",
            public_key="ssh-ed25519 AAAA",
            fingerprint="fingerprint-1",
        )
        db.session.add(device)
        db.session.flush()

        now = utcnow()
        db.session.add_all(
            [
                SSHCertificateIssuance(
                    request_id="request-1",
                    user_id=user.id,
                    device_id=device.id,
                    server_id=server_one.id,
                    ssh_principal="root",
                    public_key_fingerprint="pk-1",
                    cert_key_id="key-1",
                    serial=101,
                    valid_after=now,
                    valid_before=now + timedelta(minutes=5),
                    policy_decision={},
                    issued_at=now,
                ),
                SSHCertificateIssuance(
                    request_id="request-2",
                    user_id=user.id,
                    device_id=device.id,
                    server_id=server_two.id,
                    ssh_principal="root",
                    public_key_fingerprint="pk-2",
                    cert_key_id="key-2",
                    serial=202,
                    valid_after=now,
                    valid_before=now + timedelta(minutes=5),
                    policy_decision={},
                    issued_at=now,
                ),
                SSHCertificateIssuance(
                    request_id="request-3",
                    user_id=user.id,
                    device_id=device.id,
                    server_id=server_one.id,
                    ssh_principal="root",
                    public_key_fingerprint="pk-3",
                    cert_key_id="key-3",
                    serial=303,
                    valid_after=now - timedelta(minutes=10),
                    valid_before=now - timedelta(minutes=1),
                    policy_decision={},
                    issued_at=now - timedelta(minutes=10),
                ),
            ]
        )
        db.session.commit()

        scoped = get_revocation_state(server_id=str(server_one.id))
        global_state = get_revocation_state()

    assert scoped["revoked_certificate_serials"] == [101]
    assert global_state["revoked_certificate_serials"] == [101, 202]
