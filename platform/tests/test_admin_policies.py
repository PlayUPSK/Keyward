from app import create_app, db
from app.models.device import Device
from app.models.identity import Group, Role, RoleBinding, User
from app.models.policy import AccessGrant, Policy
from app.models.server import Server, ServerGroup


def test_admin_policies_page_populates_selects_and_details():
    app = create_app("app.config.TestConfig")

    with app.app_context():
        db.create_all()

        admin_user = User(email="admin@example.com", display_name="Admin", auth_provider="local", status="active")
        access_user = User(email="alice@example.com", display_name="Alice", auth_provider="local", status="active")
        group = Group(name="prod-access", source="local")
        admin_role = Role(name="admin", description="admin role")
        server = Server(hostname="db-01", environment="prod", status="trusted", tags={"tier": "database"})
        server_group = ServerGroup(name="production", description="Production servers")
        db.session.add_all([admin_user, access_user, group, admin_role, server, server_group])
        db.session.flush()

        admin_user_id = str(admin_user.id)
        device = Device(
            user_id=access_user.id,
            name="alice-laptop",
            platform="linux",
            status="trusted",
            public_key="ssh-ed25519 AAAA",
            fingerprint="fingerprint-1",
        )
        policy = Policy(
            name="Prod DBA access",
            effect="allow",
            priority=50,
            enabled=True,
            conditions={"device_status": "trusted", "server_environment": "prod", "ssh_principal": "dba"},
            actions={"ttl_seconds": 600, "constraints": {"permit_pty": True, "permit_agent_forwarding": False, "permit_x11_forwarding": False}},
        )
        db.session.add_all([device, policy])
        db.session.add(
            RoleBinding(subject_type="user", subject_id=admin_user.id, role_id=admin_role.id, scope_type="global")
        )
        db.session.add(
            AccessGrant(
                subject_type="user",
                subject_id=access_user.id,
                server_scope_type="server",
                server_scope_id=server.id,
                unix_principals=["dba", "deploy"],
            )
        )
        db.session.commit()

    client = app.test_client()
    with client.session_transaction() as session:
        session["user_id"] = admin_user_id

    response = client.get("/admin/policies")
    html = response.get_data(as_text=True)

    assert response.status_code == 200
    assert "Alice (alice@example.com)" in html
    assert "prod-access (local)" in html
    assert "db-01 (prod, trusted)" in html
    assert "Select user" in html
    assert "Prod DBA access" in html
    assert "Device: trusted" in html
    assert "TTL: 600 seconds" in html
    assert "dba, deploy" in html