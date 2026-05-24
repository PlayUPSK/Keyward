import base64
import hashlib
import json
import re
import secrets
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from flask import request, session, url_for

from app.models.integration import IntegrationSetting


UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


def enabled_sso_providers() -> dict[str, bool]:
    return {
        "oidc": _enabled("oidc"),
        "saml": _enabled("saml"),
    }


def oidc_authorization_url() -> tuple[str | None, str | None]:
    integration = _integration("oidc")
    if not integration or not integration.enabled:
        return None, "oidc_not_configured"
    settings = integration.settings or {}
    discovery, error = _oidc_discovery(settings)
    if error:
        return None, error

    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    session["oidc_state"] = state
    session["oidc_nonce"] = nonce
    session["oidc_code_verifier"] = verifier

    params = {
        "client_id": settings.get("client_id"),
        "response_type": "code",
        "scope": settings.get("scopes") or "openid email profile",
        "redirect_uri": url_for("auth.oidc_callback", _external=True),
        "state": state,
        "nonce": nonce,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    return discovery["authorization_endpoint"] + "?" + urlencode(params), None


def oidc_callback_payload(args) -> tuple[dict | None, str | None]:
    integration = _integration("oidc")
    if not integration or not integration.enabled:
        return None, "oidc_not_configured"
    if args.get("state") != session.pop("oidc_state", None):
        return None, "invalid_state"
    code = args.get("code")
    if not code:
        return None, args.get("error") or "authorization_code_missing"

    settings = integration.settings or {}
    discovery, error = _oidc_discovery(settings)
    if error:
        return None, error

    token_response = _post_form(
        discovery["token_endpoint"],
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": url_for("auth.oidc_callback", _external=True),
            "client_id": settings.get("client_id"),
            "client_secret": settings.get("client_secret"),
            "code_verifier": session.pop("oidc_code_verifier", ""),
        },
    )
    if "error" in token_response:
        return None, token_response.get("error_description") or token_response["error"]

    claims, error = _verify_oidc_id_token(
        id_token=token_response.get("id_token"),
        discovery=discovery,
        settings=settings,
        nonce=session.pop("oidc_nonce", None),
    )
    if error:
        return None, error

    return _claims_to_login_payload(claims, settings, "oidc"), None


def saml_login_url() -> tuple[str | None, str | None]:
    auth, error = _saml_auth()
    if error:
        return None, error
    return auth.login(), None


def saml_acs_payload() -> tuple[dict | None, str | None]:
    auth, error = _saml_auth()
    if error:
        return None, error
    auth.process_response()
    errors = auth.get_errors()
    if errors:
        reason = auth.get_last_error_reason() or ",".join(errors)
        return None, f"{','.join(errors)}: {reason}"
    if not auth.is_authenticated():
        return None, "saml_not_authenticated"
    settings = (_integration("saml").settings or {})
    attributes = auth.get_attributes()
    email_attr = settings.get("email_attribute") or "email"
    display_attr = settings.get("display_name_attribute") or "displayName"
    groups_attr = settings.get("groups_attribute") or "groups"
    email = _first(attributes.get(email_attr)) or auth.get_nameid()
    groups, groups_source = _saml_groups_from_attributes(attributes, groups_attr) if _truthy(settings.get("sync_groups"), default=True) else ([], None)
    resolved_groups = _resolve_saml_groups(groups, settings) if groups else []
    return {
        "email": email,
        "display_name": _first(attributes.get(display_attr)) or email,
        "external_id": auth.get_nameid(),
        "groups": resolved_groups,
        "group_source": groups_source,
        "attribute_keys": sorted(attributes.keys()),
        "provider": "saml",
    }, None


def saml_metadata_xml() -> tuple[str | None, str | None]:
    auth, error = _saml_auth()
    if error:
        return None, error
    from onelogin.saml2.metadata import OneLogin_Saml2_Metadata

    settings = auth.get_settings()
    metadata = settings.get_sp_metadata()
    errors = OneLogin_Saml2_Metadata.validate_metadata(metadata)
    if errors:
        return None, ",".join(errors)
    return metadata, None


def _claims_to_login_payload(claims: dict, settings: dict, provider: str) -> dict:
    email_claim = settings.get("email_claim") or "preferred_username"
    name_claim = settings.get("name_claim") or "name"
    groups_claim = settings.get("groups_claim") or "groups"
    email = claims.get(email_claim) or claims.get("email") or claims.get("upn")
    groups = _list_values(claims.get(groups_claim))
    return {
        "email": email,
        "display_name": claims.get(name_claim) or email,
        "external_id": claims.get("oid") or claims.get("sub"),
        "groups": groups,
        "provider": provider,
    }


def _verify_oidc_id_token(id_token: str | None, discovery: dict, settings: dict, nonce: str | None) -> tuple[dict | None, str | None]:
    if not id_token:
        return None, "id_token_missing"
    try:
        from authlib.jose import JsonWebKey, JsonWebToken
        from authlib.jose.errors import JoseError
    except ImportError:
        return None, "authlib_not_installed"

    try:
        jwks = _get_json(discovery["jwks_uri"])
        jwt = JsonWebToken(["RS256"])
        claims = jwt.decode(id_token, JsonWebKey.import_key_set(jwks), claims_options={
            "iss": {"essential": True, "value": discovery["issuer"]},
            "aud": {"essential": True, "value": settings.get("client_id")},
        })
        claims.validate()
    except JoseError as exc:
        return None, f"id_token_invalid:{exc}"
    except Exception as exc:
        return None, f"id_token_verification_failed:{exc}"

    if nonce and claims.get("nonce") != nonce:
        return None, "invalid_nonce"
    tenant = settings.get("allowed_tenant_id")
    if tenant and claims.get("tid") != tenant:
        return None, "tenant_not_allowed"
    return dict(claims), None


def _oidc_discovery(settings: dict) -> tuple[dict | None, str | None]:
    issuer = (settings.get("issuer_url") or "").rstrip("/")
    if not issuer or not settings.get("client_id"):
        return None, "oidc_missing_required_fields"
    try:
        discovery = _get_json(f"{issuer}/.well-known/openid-configuration")
    except Exception as exc:
        return None, f"oidc_discovery_failed:{exc}"
    return discovery, None


def _post_form(url: str, data: dict) -> dict:
    encoded = urlencode({key: value for key, value in data.items() if value is not None}).encode()
    req = Request(url, data=encoded, headers={"Content-Type": "application/x-www-form-urlencoded"})
    with urlopen(req, timeout=10) as response:
        return json.loads(response.read())


def _get_json(url: str) -> dict:
    with urlopen(url, timeout=10) as response:
        return json.loads(response.read())


def _saml_auth():
    integration = _integration("saml")
    if not integration or not integration.enabled:
        return None, "saml_not_configured"
    try:
        from onelogin.saml2.auth import OneLogin_Saml2_Auth
    except ImportError:
        return None, "python3_saml_not_installed"
    try:
        return OneLogin_Saml2_Auth(_saml_request_data(), _saml_settings(integration.settings or {})), None
    except Exception as exc:
        return None, f"saml_init_failed:{exc}"


def _saml_settings(settings: dict) -> dict:
    base_url = request.url_root.rstrip("/")
    sp_entity_id = settings.get("sp_entity_id") or url_for("auth.saml_metadata", _external=True)
    idp = {}
    if settings.get("idp_metadata_url"):
        try:
            from onelogin.saml2.idp_metadata_parser import OneLogin_Saml2_IdPMetadataParser

            parsed = OneLogin_Saml2_IdPMetadataParser.parse_remote(settings.get("idp_metadata_url"))
            idp.update(parsed.get("idp", {}))
        except Exception:
            idp = {}
    if not idp:
        if settings.get("idp_entity_id"):
            idp["entityId"] = settings.get("idp_entity_id")
        if settings.get("idp_sso_url"):
            idp["singleSignOnService"] = {
                "url": settings.get("idp_sso_url"),
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            }
        if settings.get("idp_x509_cert"):
            idp["x509cert"] = settings.get("idp_x509_cert")
    return {
        "strict": True,
        "debug": False,
        "sp": {
            "entityId": sp_entity_id,
            "assertionConsumerService": {
                "url": url_for("auth.saml_acs", _external=True),
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
            },
            "NameIDFormat": _saml_nameid_format(settings.get("nameid_format")),
        },
        "idp": idp,
        "security": {
            "wantAssertionsSigned": _truthy(settings.get("want_assertions_signed"), default=True),
            "wantMessagesSigned": _truthy(settings.get("want_messages_signed"), default=False),
            "wantNameId": True,
            "authnRequestsSigned": False,
            "logoutRequestSigned": False,
            "logoutResponseSigned": False,
        },
        "contactPerson": {},
        "organization": {"en-US": {"name": "Keyward", "displayname": "Keyward", "url": base_url}},
    }


def _saml_request_data() -> dict:
    return {
        "https": "on" if request.scheme == "https" else "off",
        "http_host": request.host,
        "script_name": request.path,
        "server_port": request.environ.get("SERVER_PORT"),
        "get_data": request.args.copy(),
        "post_data": request.form.copy(),
    }


def _saml_groups_from_attributes(attributes: dict, configured_attr: str) -> tuple[list[str], str | None]:
    candidates = [
        configured_attr,
        "groups",
        "Groups",
        "group",
        "memberOf",
        "roles",
        "Roles",
        "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups",
        "http://schemas.microsoft.com/ws/2008/06/identity/claims/role",
        "http://schemas.xmlsoap.org/claims/Group",
    ]
    for attr in candidates:
        values = _list_values(attributes.get(attr))
        if values:
            return values, attr
    return [], None


def _resolve_saml_groups(groups: list[str], settings: dict) -> list[dict]:
    if not _truthy(settings.get("resolve_group_names"), default=True):
        return [{"name": group, "external_id": group if UUID_RE.match(group) else None} for group in groups]

    manual_map = _group_name_map(settings.get("group_name_map"))
    graph_token = None
    resolved = []
    for group in groups:
        group = str(group).strip()
        if not group:
            continue
        if UUID_RE.match(group):
            display_name = manual_map.get(group.lower())
            if not display_name:
                if graph_token is None:
                    graph_token = _graph_token(settings)
                display_name = _graph_group_display_name(group, graph_token) if graph_token else None
            resolved.append({"name": display_name or group, "external_id": group})
        else:
            resolved.append({"name": group, "external_id": None})
    return resolved


def _group_name_map(value) -> dict[str, str]:
    if not value:
        return {}
    if isinstance(value, dict):
        return {str(key).lower(): str(name) for key, name in value.items() if key and name}
    try:
        parsed = json.loads(value)
    except Exception:
        return {}
    if not isinstance(parsed, dict):
        return {}
    return {str(key).lower(): str(name) for key, name in parsed.items() if key and name}


def _graph_token(settings: dict) -> str | None:
    tenant_id = settings.get("graph_tenant_id") or settings.get("allowed_tenant_id")
    client_id = settings.get("graph_client_id")
    client_secret = settings.get("graph_client_secret")
    if not tenant_id or not client_id or not client_secret:
        return None
    try:
        response = _post_form(
            f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token",
            {
                "client_id": client_id,
                "client_secret": client_secret,
                "grant_type": "client_credentials",
                "scope": "https://graph.microsoft.com/.default",
            },
        )
    except Exception:
        return None
    return response.get("access_token")


def _graph_group_display_name(group_id: str, token: str | None) -> str | None:
    if not token:
        return None
    try:
        req = Request(
            f"https://graph.microsoft.com/v1.0/groups/{group_id}?$select=id,displayName",
            headers={"Authorization": f"Bearer {token}"},
        )
        with urlopen(req, timeout=5) as response:
            payload = json.loads(response.read())
        return payload.get("displayName")
    except Exception:
        return None


def _saml_nameid_format(value: str | None) -> str:
    normalized = (value or "").strip()
    if normalized.startswith(("urn:", "http://", "https://")):
        return normalized
    aliases = {
        "": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        "email": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        "emailaddress": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        "mail": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        "unspecified": "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
        "persistent": "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
        "transient": "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
    }
    key = normalized.lower().replace("-", "").replace("_", "").replace(" ", "")
    return aliases.get(key, "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress")


def _truthy(value, default: bool = False) -> bool:
    if value is None or value == "":
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "on", "y"}


def _integration(provider: str) -> IntegrationSetting | None:
    return IntegrationSetting.query.filter_by(provider=provider).one_or_none()


def _enabled(provider: str) -> bool:
    integration = _integration(provider)
    return bool(integration and integration.enabled)


def _first(value) -> str | None:
    values = _list_values(value)
    return values[0] if values else None


def _list_values(value) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value if item]
    return [str(value)]
