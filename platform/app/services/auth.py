import functools
import uuid

from flask import current_app, g, redirect, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

from app import db
from app.models.device import Device
from app.models.identity import Group, Role, RoleBinding, User, UserGroup
from app.models.policy import AccessGrant
from app.models.base import utcnow
from app.services.audit import record_audit_event


ADMIN_ROLE = "admin"
USER_ROLE = "user"


def login_local_user(email: str, password: str) -> tuple[User | None, str | None]:
    normalized_email = email.strip().lower()
    user = User.query.filter_by(email=normalized_email).one_or_none()
    if user is None or not user.password_hash:
        return None, "invalid_credentials"
    if not check_password_hash(user.password_hash, password):
        return None, "invalid_credentials"
    return _complete_login(user, "local")


def register_local_user(email: str, password: str, display_name: str | None = None) -> tuple[User | None, str | None]:
    normalized_email = email.strip().lower()
    if not current_app.config["LOCAL_AUTH_ENABLED"]:
        return None, "local_auth_disabled"
    if not _domain_allowed(normalized_email):
        return None, "domain_not_allowed"
    if len(password) < 8:
        return None, "password_too_short"
    if User.query.filter_by(email=normalized_email).one_or_none() is not None:
        return None, "user_already_exists"

    user = User(
        id=uuid.uuid4(),
        email=normalized_email,
        display_name=display_name or normalized_email,
        auth_provider="local",
        password_hash=generate_password_hash(password),
        password_changed_at=utcnow(),
        status="active",
    )
    db.session.add(user)
    db.session.flush()
    _ensure_role(user, USER_ROLE)
    if current_app.config["FIRST_USER_ADMIN"] and User.query.count() == 1:
        _ensure_role(user, ADMIN_ROLE)
    db.session.commit()
    return user, None


def login_or_create_user(email: str, display_name: str | None = None) -> tuple[User | None, str | None]:
    if not current_app.config["DEV_AUTH_ENABLED"]:
        return None, "dev_auth_disabled"
    normalized_email = email.strip().lower()
    if not _domain_allowed(normalized_email):
        return None, "domain_not_allowed"

    user = User.query.filter_by(email=normalized_email).one_or_none()
    if user is None:
        user = User(
            id=uuid.uuid4(),
            email=normalized_email,
            display_name=display_name or normalized_email,
            auth_provider="dev",
            status="active",
        )
        db.session.add(user)
        db.session.flush()
        _ensure_role(user, USER_ROLE)
        if current_app.config["FIRST_USER_ADMIN"] and User.query.count() == 1:
            _ensure_role(user, ADMIN_ROLE)

    return _complete_login(user, "dev")


def login_federated_user(
    *,
    email: str,
    display_name: str | None,
    provider: str,
    external_id: str | None,
    groups: list[object] | None = None,
    group_source: str | None = None,
    attribute_keys: list[str] | None = None,
) -> tuple[User | None, str | None]:
    normalized_email = email.strip().lower()
    if not normalized_email:
        return None, "email_required"
    if not _domain_allowed(normalized_email):
        return None, "domain_not_allowed"

    user = User.query.filter_by(email=normalized_email).one_or_none()
    if user is None:
        user = User(
            id=uuid.uuid4(),
            email=normalized_email,
            display_name=display_name or normalized_email,
            external_id=external_id,
            auth_provider=provider,
            status="active",
        )
        db.session.add(user)
        db.session.flush()
        _ensure_role(user, USER_ROLE)
        if current_app.config["FIRST_USER_ADMIN"] and User.query.count() == 1:
            _ensure_role(user, ADMIN_ROLE)
    else:
        user.display_name = display_name or user.display_name or normalized_email
        user.external_id = external_id or user.external_id
        user.auth_provider = provider

    synced_groups = _sync_federated_groups(user, groups or [], provider)
    record_audit_event(
        event_type="user.federated_groups_synced",
        outcome="success",
        actor_user_id=user.id,
        target_type="user",
        target_id=user.id,
        metadata={
            "provider": provider,
            "group_source": group_source,
            "group_count": len(synced_groups),
            "groups": synced_groups[:50],
            "attribute_keys": attribute_keys or [],
        },
    )
    return _complete_login(user, provider)


def _complete_login(user: User, provider: str) -> tuple[User | None, str | None]:
    if user.status != "active":
        return None, "user_not_active"

    user.last_login_at = utcnow()
    _ensure_role(user, USER_ROLE)
    record_audit_event(
        event_type="user.login",
        outcome="success",
        actor_user_id=user.id,
        target_type="user",
        target_id=user.id,
        metadata={"provider": provider},
    )
    db.session.commit()
    return user, None


def create_local_user(email: str, password: str, display_name: str | None, roles: list[str]) -> tuple[dict, int]:
    user, error = register_local_user(email, password, display_name)
    if error:
        return {"error": error}, 400
    for role in roles:
        if role:
            _ensure_role(user, role)
    db.session.commit()
    return {"id": str(user.id), "email": user.email, "roles": sorted(_roles_for_user(user))}, 201


def logout_user():
    session.clear()


def load_current_user():
    user_id = session.get("user_id")
    user = db.session.get(User, uuid.UUID(user_id)) if user_id else None
    if user is not None and user.status != "active":
        session.clear()
        user = None
    g.current_user = user
    return None


def current_user():
    return getattr(g, "current_user", None)


def current_user_roles() -> set[str]:
    user = current_user()
    if user is None:
        return set()
    rows = (
        db.session.query(Role.name)
        .join(RoleBinding, RoleBinding.role_id == Role.id)
        .filter(RoleBinding.subject_type == "user", RoleBinding.subject_id == user.id)
        .all()
    )
    return {row[0] for row in rows}


def require_login(view):
    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        if current_user() is None:
            return redirect(url_for("auth.login"))
        return view(*args, **kwargs)

    return wrapped


def require_role(role_name: str):
    def decorator(view):
        @functools.wraps(view)
        def wrapped(*args, **kwargs):
            if current_user() is None:
                return redirect(url_for("auth.login"))
            if role_name not in current_user_roles():
                return redirect(url_for("portal.index"))
            return view(*args, **kwargs)

        return wrapped

    return decorator


def assign_role(user_id: str, role_name: str) -> tuple[dict, int]:
    try:
        parsed_user_id = uuid.UUID(user_id)
    except ValueError:
        return {"error": "invalid_user_id"}, 400

    user = db.session.get(User, parsed_user_id)
    if user is None:
        return {"error": "user_not_found"}, 404
    _ensure_role(user, role_name)
    db.session.commit()
    return {"user_id": str(user.id), "role": role_name}, 200


def remove_role(user_id: str, role_name: str) -> tuple[dict, int]:
    user, error_response = _user_from_id(user_id)
    if error_response:
        return error_response
    if role_name == ADMIN_ROLE and ADMIN_ROLE in _roles_for_user(user) and _active_admin_count() <= 1:
        return {"error": "cannot_remove_last_admin"}, 400
    role = Role.query.filter_by(name=role_name).one_or_none()
    if role is None:
        return {"error": "role_not_found"}, 404
    RoleBinding.query.filter_by(
        subject_type="user",
        subject_id=user.id,
        role_id=role.id,
        scope_type="global",
    ).delete()
    record_audit_event(
        event_type="user.role_removed",
        outcome="success",
        target_type="user",
        target_id=user.id,
        metadata={"role": role_name},
    )
    db.session.commit()
    return {"user_id": str(user.id), "role": role_name}, 200


def set_user_status(user_id: str, status: str) -> tuple[dict, int]:
    user, error_response = _user_from_id(user_id)
    if error_response:
        return error_response
    if status not in {"active", "suspended", "disabled"}:
        return {"error": "invalid_status"}, 400
    if user.status == "active" and status != "active" and ADMIN_ROLE in _roles_for_user(user) and _active_admin_count() <= 1:
        return {"error": "cannot_disable_last_admin"}, 400
    user.status = status
    record_audit_event(
        event_type="user.status_updated",
        outcome="success",
        target_type="user",
        target_id=user.id,
        metadata={"status": status},
    )
    db.session.commit()
    return {"user_id": str(user.id), "status": status}, 200


def update_user_profile(user_id: str, display_name: str | None, external_id: str | None) -> tuple[dict, int]:
    user, error_response = _user_from_id(user_id)
    if error_response:
        return error_response
    user.display_name = display_name or user.email
    user.external_id = external_id or None
    record_audit_event(
        event_type="user.profile_updated",
        outcome="success",
        target_type="user",
        target_id=user.id,
        metadata={"display_name": user.display_name, "external_id": user.external_id},
    )
    db.session.commit()
    return {"user_id": str(user.id)}, 200


def reset_local_password(user_id: str, password: str) -> tuple[dict, int]:
    user, error_response = _user_from_id(user_id)
    if error_response:
        return error_response
    if user.auth_provider != "local":
        return {"error": "not_local_user"}, 400
    if len(password) < 12:
        return {"error": "password_too_short"}, 400
    user.password_hash = generate_password_hash(password)
    user.password_changed_at = utcnow()
    record_audit_event(
        event_type="user.password_reset",
        outcome="success",
        target_type="user",
        target_id=user.id,
        metadata={"provider": user.auth_provider},
    )
    db.session.commit()
    return {"user_id": str(user.id)}, 200


def delete_user(user_id: str) -> tuple[dict, int]:
    user, error_response = _user_from_id(user_id)
    if error_response:
        return error_response
    if ADMIN_ROLE in _roles_for_user(user) and _active_admin_count() <= 1:
        return {"error": "cannot_delete_last_admin"}, 400
    if current_user() is not None and current_user().id == user.id:
        return {"error": "cannot_delete_current_user"}, 400

    original_email = user.email
    for device in Device.query.filter_by(user_id=user.id).all():
        device.status = "revoked"
        device.revoked_at = utcnow()
    RoleBinding.query.filter_by(subject_type="user", subject_id=user.id).delete()
    UserGroup.query.filter_by(user_id=user.id).delete()
    AccessGrant.query.filter_by(subject_type="user", subject_id=user.id).delete()

    user.email = f"deleted-{user.id}@deleted.local"
    user.display_name = "Deleted user"
    user.external_id = None
    user.auth_provider = "deleted"
    user.password_hash = None
    user.status = "deleted"
    record_audit_event(
        event_type="user.deleted",
        outcome="success",
        target_type="user",
        target_id=user.id,
        metadata={"email": original_email},
    )
    db.session.commit()
    return {"user_id": str(user.id), "status": user.status}, 200


def list_users_with_roles() -> list[dict]:
    from app.models.device import Device
    from app.services.portal import accessible_servers_for_user

    users = User.query.filter(User.status != "deleted").order_by(User.email.asc()).all()
    result = []
    for user in users:
        devices = Device.query.filter_by(user_id=user.id).all()
        groups = (
            db.session.query(Group)
            .join(UserGroup, UserGroup.group_id == Group.id)
            .filter(UserGroup.user_id == user.id)
            .order_by(Group.name.asc())
            .all()
        )
        servers = accessible_servers_for_user(user.id)
        result.append(
            {
            "id": str(user.id),
            "email": user.email,
            "display_name": user.display_name,
            "status": user.status,
            "auth_provider": user.auth_provider,
            "external_id": user.external_id,
            "created_at": user.created_at.isoformat() if user.created_at else None,
            "updated_at": user.updated_at.isoformat() if user.updated_at else None,
            "last_login_at": user.last_login_at.isoformat() if user.last_login_at else None,
            "roles": sorted(_roles_for_user(user)),
            "groups": [{"id": str(group.id), "name": group.name, "source": group.source} for group in groups],
            "devices": {
                "total": len(devices),
                "trusted": len([device for device in devices if device.status == "trusted"]),
                "revoked": len([device for device in devices if device.status == "revoked"]),
            },
            "accessible_servers": servers[:8],
            "accessible_server_count": len(servers),
        }
        )
    return result


def _domain_allowed(email: str) -> bool:
    if "@" not in email:
        return False
    domain = email.rsplit("@", 1)[1]
    return "*" in current_app.config["ALLOWED_LOGIN_DOMAINS"] or domain in current_app.config["ALLOWED_LOGIN_DOMAINS"]


def _ensure_role(user: User, role_name: str):
    role = Role.query.filter_by(name=role_name).one_or_none()
    if role is None:
        role = Role(name=role_name, description=f"{role_name} role")
        db.session.add(role)
        db.session.flush()

    existing = RoleBinding.query.filter_by(
        subject_type="user",
        subject_id=user.id,
        role_id=role.id,
        scope_type="global",
    ).one_or_none()
    if existing is None:
        db.session.add(
            RoleBinding(
                subject_type="user",
                subject_id=user.id,
                role_id=role.id,
                scope_type="global",
            )
        )


def _sync_federated_groups(user: User, group_names: list[object], provider: str) -> list[str]:
    cleaned = _normalize_federated_groups(group_names)
    if not cleaned:
        return []
    synced_names = []
    for item in cleaned:
        group_name = item["name"]
        external_id = item.get("external_id")
        group = Group.query.filter_by(external_id=external_id).one_or_none() if external_id else None
        if group is None and external_id:
            group = Group.query.filter_by(name=external_id).one_or_none()
        if group is None:
            group = Group.query.filter_by(name=group_name).one_or_none()
        if group is None:
            group = Group(name=group_name, external_id=external_id, source=provider)
            db.session.add(group)
            db.session.flush()
        else:
            if external_id and not group.external_id:
                group.external_id = external_id
            if group.name == external_id and group_name != external_id:
                group.name = group_name
            if group.source == "local":
                group.source = provider
        existing = UserGroup.query.filter_by(user_id=user.id, group_id=group.id).one_or_none()
        if existing is None:
            db.session.add(UserGroup(user_id=user.id, group_id=group.id))
        synced_names.append(group.name)
    return sorted(set(synced_names))


def _normalize_federated_groups(values: list[object]) -> list[dict]:
    normalized = {}
    for value in values:
        if isinstance(value, dict):
            name = str(value.get("name") or value.get("display_name") or value.get("external_id") or "").strip()
            external_id = str(value.get("external_id") or value.get("id") or "").strip() or None
        else:
            name = str(value or "").strip()
            external_id = name if _looks_uuid(name) else None
        if not name:
            continue
        key = external_id or name.lower()
        normalized[key] = {"name": name, "external_id": external_id}
    return [normalized[key] for key in sorted(normalized)]


def _looks_uuid(value: str) -> bool:
    try:
        uuid.UUID(value)
        return True
    except ValueError:
        return False


def _roles_for_user(user: User) -> set[str]:
    rows = (
        db.session.query(Role.name)
        .join(RoleBinding, RoleBinding.role_id == Role.id)
        .filter(RoleBinding.subject_type == "user", RoleBinding.subject_id == user.id)
        .all()
    )
    return {row[0] for row in rows}


def _active_admin_count() -> int:
    return (
        db.session.query(User.id)
        .join(RoleBinding, RoleBinding.subject_id == User.id)
        .join(Role, RoleBinding.role_id == Role.id)
        .filter(
            User.status == "active",
            RoleBinding.subject_type == "user",
            RoleBinding.scope_type == "global",
            Role.name == ADMIN_ROLE,
        )
        .distinct()
        .count()
    )


def _user_from_id(user_id: str) -> tuple[User | None, tuple[dict, int] | None]:
    try:
        parsed_user_id = uuid.UUID(user_id)
    except ValueError:
        return None, ({"error": "invalid_user_id"}, 400)

    user = db.session.get(User, parsed_user_id)
    if user is None:
        return None, ({"error": "user_not_found"}, 404)
    return user, None
