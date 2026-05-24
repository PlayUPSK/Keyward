from flask import Blueprint, flash, redirect, render_template, request, url_for

from app import db
from app.models.identity import Group
from app.services.auth import (
    ADMIN_ROLE,
    assign_role,
    create_local_user,
    current_user,
    delete_user,
    list_users_with_roles,
    remove_role,
    require_role,
    reset_local_password,
    set_user_status,
    update_user_profile,
)
from app.services.integrations import list_integrations, sync_integration, test_integration, update_integration
from app.services.device_posture import get_device_posture_policy, update_device_posture_policy
from app.services.admin_overview import dashboard_summary
from app.services.audit import audit_filter_options, list_audit_events
from app.services.devices import revoke_device, set_device_status
from app.services.policies import (
    create_access_grant,
    create_policy,
    delete_access_grant,
    delete_policy,
    invalidate_policy,
    list_access_grants,
    list_policies,
    set_policy_enabled,
)
from app.services.server_admin import set_server_status
from app.services.server_groups import create_server_group, list_server_groups
from app.services.servers import (
    create_server_enrollment_token,
    delete_server_enrollment_token,
    list_server_enrollment_tokens,
    update_server_enrollment_token,
)
from app.models.device import Device
from app.models.server import Server
from app.models.ssh_certificate import SSHCertificateIssuance

bp = Blueprint("admin", __name__, template_folder="templates")


@bp.get("/")
@require_role(ADMIN_ROLE)
def dashboard():
    return render_template(
        "admin/dashboard.html",
        summary=dashboard_summary(),
        recent_events=list_audit_events(limit=12),
        recent_certificates=SSHCertificateIssuance.query.order_by(SSHCertificateIssuance.issued_at.desc()).limit(8).all(),
    )


@bp.get("/policies")
@require_role(ADMIN_ROLE)
def policies():
    users = list_users_with_roles()
    groups = [
        {"id": str(group.id), "name": group.name, "source": group.source}
        for group in Group.query.order_by(Group.name.asc()).all()
    ]
    servers = [
        {
            "id": str(server.id),
            "hostname": server.hostname,
            "environment": server.environment,
            "status": server.status,
        }
        for server in Server.query.order_by(Server.hostname.asc()).all()
    ]
    server_groups = list_server_groups()
    device_statuses = sorted(
        {
            "pending",
            "trusted",
            "revoked",
            *[status for status, in db.session.query(Device.status).distinct().all() if status],
        }
    )
    server_environments = sorted(
        {environment for environment, in db.session.query(Server.environment).distinct().all() if environment}
    )
    return render_template(
        "admin/policies.html",
        policies=list_policies(),
        access_grants=list_access_grants(),
        device_posture_policy=get_device_posture_policy(),
        users=users,
        groups=groups,
        servers=servers,
        server_groups=server_groups,
        subject_options={
            "user": [
                {
                    "value": user["id"],
                    "label": f"{user['display_name'] or user['email']} ({user['email']})",
                }
                for user in users
            ],
            "group": [
                {
                    "value": group["id"],
                    "label": f"{group['name']} ({group['source']})",
                }
                for group in groups
            ],
        },
        scope_options={
            "server": [
                {
                    "value": server["id"],
                    "label": f"{server['hostname']} ({server['environment']}, {server['status']})",
                }
                for server in servers
            ],
            "server_group": [
                {
                    "value": group["id"],
                    "label": f"{group['name']} - {group['description']}" if group["description"] else group["name"],
                }
                for group in server_groups
            ],
            "all": [],
        },
        device_statuses=device_statuses,
        server_environments=server_environments,
    )


@bp.post("/policies")
@require_role(ADMIN_ROLE)
def policies_create():
    effect = request.form.get("effect")
    create_policy(
        {
            "name": request.form.get("name"),
            "effect": effect,
            "priority": request.form.get("priority") or 1000,
            "enabled": request.form.get("enabled") == "on",
            "conditions": _policy_conditions_from_form(request.form),
            "actions": _policy_actions_from_form(request.form, effect),
        }
    )
    return redirect(url_for("admin.policies"))


@bp.post("/policies/<policy_id>/toggle")
@require_role(ADMIN_ROLE)
def policies_toggle(policy_id):
    set_policy_enabled(policy_id, request.form.get("enabled") == "1")
    return redirect(url_for("admin.policies"))


@bp.post("/policies/<policy_id>/invalidate")
@require_role(ADMIN_ROLE)
def policies_invalidate(policy_id):
    invalidate_policy(policy_id, request.form.get("reason"))
    return redirect(url_for("admin.policies"))


@bp.post("/policies/<policy_id>/delete")
@require_role(ADMIN_ROLE)
def policies_delete(policy_id):
    delete_policy(policy_id)
    return redirect(url_for("admin.policies"))


@bp.post("/access-grants")
@require_role(ADMIN_ROLE)
def access_grants_create():
    server_scope_type = request.form.get("server_scope_type")
    create_access_grant(
        {
            "subject_type": request.form.get("subject_type"),
            "subject_id": request.form.get("subject_id"),
            "server_scope_type": server_scope_type,
            "server_scope_id": None if server_scope_type == "all" else request.form.get("server_scope_id") or None,
            "unix_principals": [
                principal.strip()
                for principal in (request.form.get("unix_principals") or "").split(",")
                if principal.strip()
            ],
            "valid_from": request.form.get("valid_from") or None,
            "valid_until": request.form.get("valid_until") or None,
        }
    )
    return redirect(url_for("admin.policies"))


@bp.post("/access-grants/<grant_id>/delete")
@require_role(ADMIN_ROLE)
def access_grants_delete(grant_id):
    delete_access_grant(grant_id)
    return redirect(url_for("admin.policies"))


@bp.post("/policies/device-posture")
@require_role(ADMIN_ROLE)
def policies_device_posture_update():
    update_device_posture_policy(request.form, actor_user_id=current_user().id)
    return redirect(url_for("admin.policies"))


@bp.get("/servers")
@require_role(ADMIN_ROLE)
def servers():
    return render_template(
        "admin/servers.html",
        servers=Server.query.order_by(Server.hostname.asc()).all(),
        server_groups=list_server_groups(),
        enrollment_tokens=list_server_enrollment_tokens(),
    )


@bp.post("/servers/enrollment-tokens")
@require_role(ADMIN_ROLE)
def servers_enrollment_tokens_create():
    token = create_server_enrollment_token(
        {
            "hostname": request.form.get("hostname"),
            "environment": request.form.get("environment") or "lab",
            "allowed_cidrs": request.form.get("allowed_cidrs"),
            "max_uses": request.form.get("max_uses") or 1,
            "ttl_minutes": request.form.get("ttl_minutes") or None,
            "note": request.form.get("note") or "",
        },
        actor_user_id=current_user().id,
    )
    if token.get("error"):
        flash(token["error"], "danger")
    else:
        flash(
            f"Server enrollment token created. Copy now: {token['token']}",
            "success",
        )
    return redirect(url_for("admin.servers"))


@bp.post("/servers/enrollment-tokens/<token_id>/edit")
@require_role(ADMIN_ROLE)
def servers_enrollment_tokens_edit(token_id):
    result, _ = update_server_enrollment_token(
        token_id,
        {
            "hostname": request.form.get("hostname"),
            "environment": request.form.get("environment") or "lab",
            "allowed_cidrs": request.form.get("allowed_cidrs"),
            "max_uses": request.form.get("max_uses") or 1,
            "note": request.form.get("note") or "",
        },
        actor_user_id=current_user().id,
    )
    flash(result.get("error") or "Server enrollment token updated.", "danger" if result.get("error") else "success")
    return redirect(url_for("admin.servers"))


@bp.post("/servers/enrollment-tokens/<token_id>/delete")
@require_role(ADMIN_ROLE)
def servers_enrollment_tokens_delete(token_id):
    result, _ = delete_server_enrollment_token(token_id, actor_user_id=current_user().id)
    flash(result.get("error") or "Server enrollment token deleted.", "danger" if result.get("error") else "success")
    return redirect(url_for("admin.servers"))


@bp.post("/servers/<server_id>/status")
@require_role(ADMIN_ROLE)
def servers_status(server_id):
    set_server_status(server_id, request.form.get("status", "enrolled"))
    return redirect(url_for("admin.servers"))


@bp.post("/server-groups")
@require_role(ADMIN_ROLE)
def server_groups_create():
    create_server_group({"name": request.form.get("name"), "description": request.form.get("description")})
    return redirect(url_for("admin.servers"))


@bp.get("/devices")
@require_role(ADMIN_ROLE)
def devices():
    return render_template("admin/devices.html", devices=Device.query.order_by(Device.created_at.desc()).all())


@bp.post("/devices/<device_id>/revoke")
@require_role(ADMIN_ROLE)
def devices_revoke(device_id):
    revoke_device(device_id, {"reason": request.form.get("reason")})
    return redirect(url_for("admin.devices"))


@bp.post("/devices/<device_id>/status")
@require_role(ADMIN_ROLE)
def devices_status(device_id):
    set_device_status(device_id, request.form.get("status", "trusted"), {"reason": request.form.get("reason")})
    return redirect(url_for("admin.devices"))


@bp.get("/audit")
@require_role(ADMIN_ROLE)
def audit():
    return render_template(
        "admin/audit.html",
        audit_events=list_audit_events(
            limit=int(request.args.get("limit", "100")),
            event_type=request.args.get("event_type") or None,
            outcome=request.args.get("outcome") or None,
            target_type=request.args.get("target_type") or None,
            source_ip=request.args.get("source_ip") or None,
            reason=request.args.get("reason") or None,
            metadata_query=request.args.get("metadata_query") or None,
        ),
        filters=audit_filter_options(),
        selected_filters={
            "event_type": request.args.get("event_type", ""),
            "outcome": request.args.get("outcome", ""),
            "target_type": request.args.get("target_type", ""),
            "source_ip": request.args.get("source_ip", ""),
            "reason": request.args.get("reason", ""),
            "metadata_query": request.args.get("metadata_query", ""),
            "limit": request.args.get("limit", "100"),
        },
    )


@bp.get("/users")
@require_role(ADMIN_ROLE)
def users():
    users = list_users_with_roles()
    return render_template(
        "admin/users.html",
        users=users,
        user_summary={
            "total": len(users),
            "admins": len([user for user in users if "admin" in user["roles"]]),
            "trusted_devices": sum(user["devices"]["trusted"] for user in users),
            "suspended": len([user for user in users if user["status"] == "suspended"]),
        },
    )


@bp.post("/users/<user_id>/roles")
@require_role(ADMIN_ROLE)
def users_assign_role(user_id):
    assign_role(user_id, request.form.get("role", "user"))
    return redirect(url_for("admin.users"))


@bp.post("/users/<user_id>/roles/remove")
@require_role(ADMIN_ROLE)
def users_remove_role(user_id):
    remove_role(user_id, request.form.get("role", "user"))
    return redirect(url_for("admin.users"))


@bp.post("/users/<user_id>/status")
@require_role(ADMIN_ROLE)
def users_set_status(user_id):
    set_user_status(user_id, request.form.get("status", "active"))
    return redirect(url_for("admin.users"))


@bp.post("/users/<user_id>/profile")
@require_role(ADMIN_ROLE)
def users_update_profile(user_id):
    update_user_profile(user_id, request.form.get("display_name"), request.form.get("external_id"))
    return redirect(url_for("admin.users"))


@bp.post("/users/<user_id>/password")
@require_role(ADMIN_ROLE)
def users_reset_password(user_id):
    reset_local_password(user_id, request.form.get("password", ""))
    return redirect(url_for("admin.users"))


@bp.post("/users/<user_id>/delete")
@require_role(ADMIN_ROLE)
def users_delete(user_id):
    delete_user(user_id)
    return redirect(url_for("admin.users"))


@bp.post("/users")
@require_role(ADMIN_ROLE)
def users_create():
    roles = request.form.getlist("roles")
    create_local_user(
        email=request.form.get("email", ""),
        password=request.form.get("password", ""),
        display_name=request.form.get("display_name"),
        roles=roles,
    )
    return redirect(url_for("admin.users"))


@bp.get("/settings")
@require_role(ADMIN_ROLE)
def settings():
    return render_template(
        "admin/settings.html",
        integrations=list_integrations(),
    )


@bp.post("/settings/integrations/<provider>")
@require_role(ADMIN_ROLE)
def settings_integration_update(provider):
    update_integration(provider, request.form)
    return redirect(url_for("admin.settings"))


@bp.post("/settings/integrations/<provider>/test")
@require_role(ADMIN_ROLE)
def settings_integration_test(provider):
    test_integration(provider)
    return redirect(url_for("admin.settings"))


@bp.post("/settings/integrations/<provider>/sync")
@require_role(ADMIN_ROLE)
def settings_integration_sync(provider):
    sync_integration(provider)
    return redirect(url_for("admin.settings"))


def _policy_conditions_from_form(form) -> dict:
    conditions: dict[str, object] = {}
    if form.get("device_status"):
        conditions["device_status"] = form.get("device_status")
    if form.get("server_environment"):
        conditions["server_environment"] = form.get("server_environment")
    if form.get("ssh_principal"):
        conditions["ssh_principal"] = form.get("ssh_principal")
    if form.get("source_ip"):
        conditions["source_ip"] = form.get("source_ip")

    policy_subject_type = form.get("policy_subject_type")
    policy_subject_id = form.get("policy_subject_id")
    if policy_subject_type == "user" and policy_subject_id:
        conditions["user_id"] = policy_subject_id
    if policy_subject_type == "group" and policy_subject_id:
        conditions["group_id"] = policy_subject_id

    server_tag_key = (form.get("server_tag_key") or "").strip()
    server_tag_value = (form.get("server_tag_value") or "").strip()
    if server_tag_key and server_tag_value:
        conditions["server_tags"] = {server_tag_key: server_tag_value}

    return conditions


def _policy_actions_from_form(form, effect: str | None) -> dict:
    if effect == "deny":
        return {
            "reason": (form.get("deny_reason") or "policy_denied").strip() or "policy_denied",
        }

    return {
        "ttl_seconds": int(form.get("ttl_seconds") or form.get("max_cert_ttl") or 300),
        "constraints": {
            "permit_pty": form.get("permit_pty") == "on",
            "permit_agent_forwarding": form.get("permit_agent_forwarding") == "on",
            "permit_x11_forwarding": form.get("permit_x11_forwarding") == "on",
            "require_user_presence": form.get("require_user_presence") == "on",
        },
    }
