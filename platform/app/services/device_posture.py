import json
import re
import uuid

from app import db
from app.models.identity import UserGroup
from app.models.integration import IntegrationSetting
from app.services.audit import record_audit_event


PROVIDER = "device_posture"


DEFAULT_POLICY = {
    "mode": "monitor",
    "require_domain_join": False,
    "allowed_domains": [],
    "allowed_os": [],
    "allowed_directory_services": [],
    "minimum_os_versions": {},
    "require_hardware_fingerprint": False,
    "require_secure_boot": False,
    "require_disk_encryption": False,
    "require_firewall": False,
    "require_antivirus": False,
    "require_screen_lock": False,
    "require_tpm": False,
    "require_mdm_enrollment": False,
    "allow_unknown_posture": False,
}


def get_device_posture_policy() -> dict:
    integration = _get_or_create()
    settings = _settings_doc(integration.settings or {})
    return {**settings["global"], "rules": settings["rules"]}


def update_device_posture_policy(payload: dict, actor_user_id=None) -> tuple[dict, int]:
    integration = _get_or_create()
    settings = _settings_doc(integration.settings or {})
    settings["global"] = _policy_config_from_payload(payload)
    _save_settings(integration, settings)
    record_audit_event(
        event_type="device_posture_policy.global_updated",
        outcome="success",
        actor_user_id=actor_user_id,
        target_type="device_posture_policy",
        metadata=settings["global"],
    )
    db.session.commit()
    return get_device_posture_policy(), 200


def create_device_posture_rule(payload: dict, actor_user_id=None) -> tuple[dict, int]:
    scope_type = payload.get("scope_type")
    scope_id = str(payload.get("scope_id") or "").strip()
    if scope_type not in {"user", "group"} or not scope_id:
        return {"error": "scope_type and scope_id are required"}, 400
    try:
        uuid.UUID(scope_id)
    except ValueError:
        return {"error": "invalid_scope_id"}, 400

    integration = _get_or_create()
    settings = _settings_doc(integration.settings or {})
    rule = {
        "id": uuid.uuid4().hex,
        "name": str(payload.get("name") or f"{scope_type}:{scope_id}").strip(),
        "scope_type": scope_type,
        "scope_id": scope_id,
        "priority": _bounded_int(payload.get("priority"), default=1000, minimum=1, maximum=999999),
        "policy": _policy_config_from_payload(payload),
    }
    settings["rules"].append(rule)
    settings["rules"] = sorted(settings["rules"], key=lambda item: int(item.get("priority") or 1000))
    _save_settings(integration, settings)
    record_audit_event(
        event_type="device_posture_policy.rule_created",
        outcome="success",
        actor_user_id=actor_user_id,
        target_type="device_posture_policy",
        metadata=rule,
    )
    db.session.commit()
    return rule, 201


def delete_device_posture_rule(rule_id: str, actor_user_id=None) -> tuple[dict, int]:
    integration = _get_or_create()
    settings = _settings_doc(integration.settings or {})
    kept = [rule for rule in settings["rules"] if rule.get("id") != rule_id]
    if len(kept) == len(settings["rules"]):
        return {"error": "rule_not_found"}, 404
    settings["rules"] = kept
    _save_settings(integration, settings)
    record_audit_event(
        event_type="device_posture_policy.rule_deleted",
        outcome="success",
        actor_user_id=actor_user_id,
        target_type="device_posture_policy",
        metadata={"rule_id": rule_id},
    )
    db.session.commit()
    return {"status": "deleted", "rule_id": rule_id}, 200


def evaluate_device_enrollment_posture(posture: dict, user=None) -> tuple[bool, str | None, dict]:
    policies = _applicable_policies(user)
    contexts = []
    for policy in policies:
        ok, reason, context = _evaluate_single_policy(policy["policy"], posture)
        context["scope"] = {
            "type": policy["scope_type"],
            "id": policy.get("scope_id"),
            "name": policy.get("name"),
            "priority": policy.get("priority", 0),
        }
        contexts.append(context)
        if not ok:
            context["evaluated_policies"] = contexts
            return False, reason, context
    return True, None, {"evaluated_policies": contexts, "policy_count": len(contexts)}


def _evaluate_single_policy(policy: dict, posture: dict) -> tuple[bool, str | None, dict]:
    enforcement_enabled = policy["mode"] == "enforce"
    if not enforcement_enabled:
        return True, None, _evaluation_context(policy, posture)

    enterprise = _enterprise(posture)
    posture_os = str((posture or {}).get("os") or "").strip().lower()
    if policy["allowed_os"] and posture_os not in policy["allowed_os"]:
        return False, "device_os_not_allowed", _evaluation_context(policy, posture)
    minimum_version = policy["minimum_os_versions"].get(posture_os)
    if minimum_version and not _version_at_least(str((posture or {}).get("os_version") or ""), minimum_version):
        return False, "device_os_version_too_old", _evaluation_context(policy, posture)

    enterprise_required = (
        policy["require_domain_join"]
        or bool(policy["allowed_domains"])
        or bool(policy["allowed_directory_services"])
    )
    if enterprise_required and not enterprise:
        if policy["allow_unknown_posture"]:
            return True, None, _evaluation_context(policy, posture)
        return False, "device_posture_unknown", _evaluation_context(policy, posture)

    domain_joined = bool(enterprise.get("domain_joined"))
    domain = str(enterprise.get("domain") or "").strip().lower()
    directory_service = str(enterprise.get("directory_service") or "").strip().lower()
    allowed_domains = policy["allowed_domains"]
    if policy["require_domain_join"] and not domain_joined:
        return False, "device_not_domain_joined", _evaluation_context(policy, posture)
    if allowed_domains and domain not in allowed_domains:
        return False, "device_domain_not_allowed", _evaluation_context(policy, posture)
    if policy["allowed_directory_services"] and directory_service not in policy["allowed_directory_services"]:
        return False, "device_directory_service_not_allowed", _evaluation_context(policy, posture)

    hardware = _hardware(posture)
    if policy["require_hardware_fingerprint"] and not (
        hardware.get("serial_hash") or hardware.get("hardware_uuid_hash") or hardware.get("machine_id_hash")
    ):
        return False, "device_hardware_fingerprint_required", _evaluation_context(policy, posture)

    security = _security(posture)
    required_security = {
        "secure_boot": "device_secure_boot_required",
        "disk_encryption": "device_disk_encryption_required",
        "firewall": "device_firewall_required",
        "antivirus": "device_antivirus_required",
        "screen_lock": "device_screen_lock_required",
        "tpm_present": "device_tpm_required",
        "mdm_enrolled": "device_mdm_required",
    }
    policy_key_by_signal = {
        "secure_boot": "require_secure_boot",
        "disk_encryption": "require_disk_encryption",
        "firewall": "require_firewall",
        "antivirus": "require_antivirus",
        "screen_lock": "require_screen_lock",
        "tpm_present": "require_tpm",
        "mdm_enrolled": "require_mdm_enrollment",
    }
    for signal, reason in required_security.items():
        if policy[policy_key_by_signal[signal]] and not _truthy(security.get(signal)):
            return False, reason, _evaluation_context(policy, posture)
    return True, None, _evaluation_context(policy, posture)


def _applicable_policies(user) -> list[dict]:
    settings = _settings_doc((_get_or_create().settings or {}))
    policies = [
        {
            "name": "Global baseline",
            "scope_type": "global",
            "scope_id": None,
            "priority": 0,
            "policy": settings["global"],
        }
    ]
    if user is None:
        return policies

    user_id = str(user.id)
    group_ids = {
        str(group_id)
        for group_id, in db.session.query(UserGroup.group_id).filter(UserGroup.user_id == user.id).all()
    }
    for rule in settings["rules"]:
        if rule.get("scope_type") == "user" and rule.get("scope_id") == user_id:
            policies.append(rule)
        if rule.get("scope_type") == "group" and rule.get("scope_id") in group_ids:
            policies.append(rule)
    return sorted(policies, key=lambda item: int(item.get("priority") or 0))


def _get_or_create() -> IntegrationSetting:
    integration = IntegrationSetting.query.filter_by(provider=PROVIDER).one_or_none()
    if integration is None:
        integration = IntegrationSetting(
            provider=PROVIDER,
            settings={"global": dict(DEFAULT_POLICY), "rules": []},
            status="monitor",
        )
        db.session.add(integration)
        db.session.flush()
    return integration


def _settings_doc(raw_settings: dict) -> dict:
    if isinstance(raw_settings.get("global"), dict):
        global_policy = _normalize_policy_config(raw_settings.get("global") or {})
        rules = [_normalize_rule(rule) for rule in raw_settings.get("rules", []) if isinstance(rule, dict)]
        return {"global": global_policy, "rules": sorted(rules, key=lambda item: int(item.get("priority") or 1000))}

    return {"global": _normalize_policy_config(raw_settings or {}), "rules": []}


def _normalize_rule(rule: dict) -> dict:
    return {
        "id": str(rule.get("id") or uuid.uuid4().hex),
        "name": str(rule.get("name") or "Scoped posture policy").strip(),
        "scope_type": rule.get("scope_type") if rule.get("scope_type") in {"user", "group"} else "user",
        "scope_id": str(rule.get("scope_id") or ""),
        "priority": _bounded_int(rule.get("priority"), default=1000, minimum=1, maximum=999999),
        "policy": _normalize_policy_config(rule.get("policy") or {}),
    }


def _normalize_policy_config(value: dict) -> dict:
    settings = dict(DEFAULT_POLICY)
    settings.update(value or {})
    settings["mode"] = settings.get("mode") if settings.get("mode") in {"monitor", "enforce"} else "monitor"
    settings["require_domain_join"] = _truthy(settings.get("require_domain_join"))
    settings["allow_unknown_posture"] = _truthy(settings.get("allow_unknown_posture"))
    settings["allowed_domains"] = _domains(settings.get("allowed_domains"))
    settings["allowed_os"] = _values(settings.get("allowed_os"))
    settings["allowed_directory_services"] = _values(settings.get("allowed_directory_services"))
    settings["minimum_os_versions"] = _mapping(settings.get("minimum_os_versions"))
    for key in _BOOLEAN_POLICY_KEYS:
        settings[key] = _truthy(settings.get(key))
    return settings


def _policy_config_from_payload(payload: dict) -> dict:
    return _normalize_policy_config(
        {
            "mode": payload.get("mode"),
            "require_domain_join": payload.get("require_domain_join") == "on",
            "allow_unknown_posture": payload.get("allow_unknown_posture") == "on",
            "allowed_domains": payload.get("allowed_domains"),
            "allowed_os": payload.get("allowed_os"),
            "allowed_directory_services": payload.get("allowed_directory_services"),
            "minimum_os_versions": payload.get("minimum_os_versions"),
            "require_hardware_fingerprint": payload.get("require_hardware_fingerprint") == "on",
            "require_secure_boot": payload.get("require_secure_boot") == "on",
            "require_disk_encryption": payload.get("require_disk_encryption") == "on",
            "require_firewall": payload.get("require_firewall") == "on",
            "require_antivirus": payload.get("require_antivirus") == "on",
            "require_screen_lock": payload.get("require_screen_lock") == "on",
            "require_tpm": payload.get("require_tpm") == "on",
            "require_mdm_enrollment": payload.get("require_mdm_enrollment") == "on",
        }
    )


def _save_settings(integration: IntegrationSetting, settings: dict) -> None:
    integration.settings = settings
    enforcing = settings["global"]["mode"] == "enforce" or any(
        rule.get("policy", {}).get("mode") == "enforce" for rule in settings.get("rules", [])
    )
    integration.enabled = enforcing
    integration.status = "enforcing" if enforcing else "monitor"


def _enterprise(posture: dict) -> dict:
    if not isinstance(posture, dict):
        return {}
    enterprise = posture.get("enterprise")
    return enterprise if isinstance(enterprise, dict) else {}


def _hardware(posture: dict) -> dict:
    if not isinstance(posture, dict):
        return {}
    hardware = posture.get("hardware")
    return hardware if isinstance(hardware, dict) else {}


def _security(posture: dict) -> dict:
    if not isinstance(posture, dict):
        return {}
    security = posture.get("security")
    return security if isinstance(security, dict) else {}


def _evaluation_context(policy: dict, posture: dict) -> dict:
    return {
        "policy": policy,
        "os": (posture or {}).get("os") if isinstance(posture, dict) else None,
        "os_version": (posture or {}).get("os_version") if isinstance(posture, dict) else None,
        "enterprise": _enterprise(posture),
        "hardware": _hardware(posture),
        "security": _security(posture),
    }


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


def _bounded_int(value, *, default: int, minimum: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    return max(minimum, min(maximum, parsed))


def _truthy(value) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _mapping(value) -> dict[str, str]:
    if isinstance(value, dict):
        return {str(key).strip().lower(): str(val).strip() for key, val in value.items() if str(key).strip() and str(val).strip()}
    if not isinstance(value, str) or not value.strip():
        return {}
    try:
        parsed = json.loads(value)
    except ValueError:
        parsed = {}
        for item in value.replace("\n", ",").split(","):
            key, sep, val = item.partition("=")
            if sep and key.strip() and val.strip():
                parsed[key.strip()] = val.strip()
    return _mapping(parsed)


def _version_at_least(actual: str, minimum: str) -> bool:
    actual_parts = _version_parts(actual)
    minimum_parts = _version_parts(minimum)
    if not actual_parts or not minimum_parts:
        return False
    max_len = max(len(actual_parts), len(minimum_parts))
    actual_parts += [0] * (max_len - len(actual_parts))
    minimum_parts += [0] * (max_len - len(minimum_parts))
    return actual_parts >= minimum_parts


def _version_parts(value: str) -> list[int]:
    return [int(part) for part in re.findall(r"\d+", value or "")]


_BOOLEAN_POLICY_KEYS = {
    "require_hardware_fingerprint",
    "require_secure_boot",
    "require_disk_encryption",
    "require_firewall",
    "require_antivirus",
    "require_screen_lock",
    "require_tpm",
    "require_mdm_enrollment",
}
