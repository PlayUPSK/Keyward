from app import db
from app.models.integration import IntegrationSetting
from app.services.audit import record_audit_event


PROVIDER = "device_posture"


DEFAULT_POLICY = {
    "mode": "monitor",
    "require_domain_join": False,
    "allowed_domains": [],
    "allowed_os": [],
    "allowed_directory_services": [],
    "allow_unknown_posture": False,
}


def get_device_posture_policy() -> dict:
    integration = _get_or_create()
    settings = dict(DEFAULT_POLICY)
    settings.update(integration.settings or {})
    settings["mode"] = settings.get("mode") if settings.get("mode") in {"monitor", "enforce"} else "monitor"
    settings["require_domain_join"] = _truthy(settings.get("require_domain_join"))
    settings["allow_unknown_posture"] = _truthy(settings.get("allow_unknown_posture"))
    settings["allowed_domains"] = _domains(settings.get("allowed_domains"))
    settings["allowed_os"] = _values(settings.get("allowed_os"))
    settings["allowed_directory_services"] = _values(settings.get("allowed_directory_services"))
    return settings


def update_device_posture_policy(payload: dict, actor_user_id=None) -> tuple[dict, int]:
    integration = _get_or_create()
    settings = {
        "mode": payload.get("mode") if payload.get("mode") in {"monitor", "enforce"} else "monitor",
        "require_domain_join": payload.get("require_domain_join") == "on",
        "allow_unknown_posture": payload.get("allow_unknown_posture") == "on",
        "allowed_domains": _domains(payload.get("allowed_domains")),
        "allowed_os": _values(payload.get("allowed_os")),
        "allowed_directory_services": _values(payload.get("allowed_directory_services")),
    }
    integration.enabled = settings["mode"] == "enforce"
    integration.status = "enforcing" if integration.enabled else "monitor"
    integration.settings = settings
    record_audit_event(
        event_type="device_posture_policy.updated",
        outcome="success",
        actor_user_id=actor_user_id,
        target_type="device_posture_policy",
        metadata=settings,
    )
    db.session.commit()
    return get_device_posture_policy(), 200


def evaluate_device_enrollment_posture(posture: dict) -> tuple[bool, str | None, dict]:
    policy = get_device_posture_policy()
    enforcement_enabled = policy["mode"] == "enforce"
    if not enforcement_enabled:
        return True, None, {"policy": policy, "enterprise": _enterprise(posture)}

    enterprise = _enterprise(posture)
    posture_os = str((posture or {}).get("os") or "").strip().lower()
    if policy["allowed_os"] and posture_os not in policy["allowed_os"]:
        return False, "device_os_not_allowed", {"policy": policy, "enterprise": enterprise, "os": posture_os}

    if not enterprise:
        if policy["allow_unknown_posture"]:
            return True, None, {"policy": policy, "enterprise": enterprise}
        return False, "device_posture_unknown", {"policy": policy, "enterprise": enterprise}

    domain_joined = bool(enterprise.get("domain_joined"))
    domain = str(enterprise.get("domain") or "").strip().lower()
    directory_service = str(enterprise.get("directory_service") or "").strip().lower()
    allowed_domains = policy["allowed_domains"]
    if policy["require_domain_join"] and not domain_joined:
        return False, "device_not_domain_joined", {"policy": policy, "enterprise": enterprise}
    if allowed_domains and domain not in allowed_domains:
        return False, "device_domain_not_allowed", {"policy": policy, "enterprise": enterprise}
    if policy["allowed_directory_services"] and directory_service not in policy["allowed_directory_services"]:
        return False, "device_directory_service_not_allowed", {"policy": policy, "enterprise": enterprise}
    return True, None, {"policy": policy, "enterprise": enterprise}


def _get_or_create() -> IntegrationSetting:
    integration = IntegrationSetting.query.filter_by(provider=PROVIDER).one_or_none()
    if integration is None:
        integration = IntegrationSetting(provider=PROVIDER, settings=dict(DEFAULT_POLICY), status="disabled")
        db.session.add(integration)
        db.session.flush()
    return integration


def _enterprise(posture: dict) -> dict:
    if not isinstance(posture, dict):
        return {}
    enterprise = posture.get("enterprise")
    return enterprise if isinstance(enterprise, dict) else {}


def _domains(value) -> list[str]:
    return _values(value)


def _values(value) -> list[str]:
    if isinstance(value, str):
        values = value.replace("\n", ",").split(",")
    elif isinstance(value, list):
        values = value
    else:
        values = []
    return sorted({str(item).strip().lower() for item in values if str(item).strip()})


def _truthy(value) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "on"}
