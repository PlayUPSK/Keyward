from app import db
from app.models.integration import IntegrationSetting
from app.models.base import utcnow
from app.services.audit import record_audit_event


PROVIDERS = {
    "oidc": {
        "name": "OpenID Connect",
        "fields": [
            "issuer_url",
            "client_id",
            "client_secret",
            "scopes",
            "email_claim",
            "name_claim",
            "groups_claim",
            "allowed_tenant_id",
        ],
    },
    "saml": {
        "name": "SAML",
        "fields": [
            "idp_metadata_url",
            "idp_entity_id",
            "idp_sso_url",
            "idp_x509_cert",
            "sp_entity_id",
            "nameid_format",
            "email_attribute",
            "display_name_attribute",
            "groups_attribute",
            "sync_groups",
            "resolve_group_names",
            "graph_tenant_id",
            "graph_client_id",
            "graph_client_secret",
            "group_name_map",
            "want_messages_signed",
            "want_assertions_signed",
        ],
    },
    "scim": {
        "name": "SCIM Provisioning",
        "fields": ["base_url", "bearer_token", "sync_groups"],
    },
}


def list_integrations() -> list[dict]:
    return [_integration_to_dict(_get_or_create(provider)) for provider in PROVIDERS]


def update_integration(provider: str, payload: dict) -> tuple[dict, int]:
    if provider not in PROVIDERS:
        return {"error": "unknown_provider"}, 404
    integration = _get_or_create(provider)
    fields = PROVIDERS[provider]["fields"]
    integration.enabled = payload.get("enabled") == "on"
    settings = dict(integration.settings or {})
    for field in fields:
        if payload.get(field) is None:
            continue
        value = payload.get(field, "")
        if _is_secret_field(field) and value == "":
            continue
        settings[field] = value
    integration.settings = settings
    integration.status = "configured" if integration.enabled else "disabled"
    record_audit_event(
        event_type=f"integration.{provider}.updated",
        outcome="success",
        target_type="integration",
        metadata={"provider": provider, "enabled": integration.enabled},
    )
    db.session.commit()
    return _integration_to_dict(integration), 200


def test_integration(provider: str) -> tuple[dict, int]:
    if provider not in PROVIDERS:
        return {"error": "unknown_provider"}, 404
    integration = _get_or_create(provider)
    integration.last_test_at = utcnow()
    if not integration.enabled:
        integration.status = "disabled"
    elif provider == "oidc":
        integration.status = _test_oidc_settings(integration.settings or {})
    elif provider == "saml":
        integration.status = _test_saml_settings(integration.settings or {})
    else:
        integration.status = "test_pending"
    record_audit_event(
        event_type=f"integration.{provider}.test",
        outcome="success",
        target_type="integration",
        metadata={"provider": provider, "status": integration.status},
    )
    db.session.commit()
    return _integration_to_dict(integration), 200


def sync_integration(provider: str) -> tuple[dict, int]:
    if provider not in PROVIDERS:
        return {"error": "unknown_provider"}, 404
    integration = _get_or_create(provider)
    integration.last_sync_at = utcnow()
    integration.status = "sync_pending" if integration.enabled else "disabled"
    record_audit_event(
        event_type=f"integration.{provider}.sync",
        outcome="success",
        target_type="integration",
        metadata={"provider": provider, "status": integration.status},
    )
    db.session.commit()
    return _integration_to_dict(integration), 200


def _get_or_create(provider: str) -> IntegrationSetting:
    integration = IntegrationSetting.query.filter_by(provider=provider).one_or_none()
    if integration is None:
        integration = IntegrationSetting(provider=provider, settings={})
        db.session.add(integration)
        db.session.flush()
    return integration


def _integration_to_dict(integration: IntegrationSetting) -> dict:
    descriptor = PROVIDERS[integration.provider]
    return {
        "id": str(integration.id),
        "provider": integration.provider,
        "name": descriptor["name"],
        "fields": descriptor["fields"],
        "enabled": integration.enabled,
        "status": integration.status,
        "settings": integration.settings or {},
        "secret_fields": [field for field in descriptor["fields"] if _is_secret_field(field)],
        "last_test_at": integration.last_test_at.isoformat() if integration.last_test_at else None,
        "last_sync_at": integration.last_sync_at.isoformat() if integration.last_sync_at else None,
        "updated_at": integration.updated_at.isoformat(),
    }


def _is_secret_field(field: str) -> bool:
    return "secret" in field or "token" in field or field.endswith("_x509_cert")


def _test_oidc_settings(settings: dict) -> str:
    issuer = (settings.get("issuer_url") or "").rstrip("/")
    client_id = settings.get("client_id")
    if not issuer or not client_id:
        return "missing_required_fields"
    try:
        import json
        from urllib.request import urlopen

        with urlopen(f"{issuer}/.well-known/openid-configuration", timeout=5) as response:
            discovery = json.loads(response.read())
        required = {"authorization_endpoint", "token_endpoint", "jwks_uri"}
        if required.issubset(discovery):
            return "healthy"
        return "discovery_incomplete"
    except Exception:
        return "test_failed"


def _test_saml_settings(settings: dict) -> str:
    if settings.get("idp_metadata_url"):
        return "configured"
    required = {"idp_entity_id", "idp_sso_url", "idp_x509_cert"}
    return "configured" if all(settings.get(field) for field in required) else "missing_required_fields"
