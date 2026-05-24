from dataclasses import dataclass
from datetime import timedelta
from uuid import UUID

from app.models.device import Device
from app.models.identity import User, UserGroup
from app.models.policy import AccessGrant, Policy
from app.models.server import Server, ServerGroupMember
from app.models.base import utcnow
from app.services.timeparse import ensure_aware


@dataclass(frozen=True)
class PolicyDecision:
    decision: str
    reason: str
    ttl_seconds: int = 300
    constraints: dict | None = None
    matched_grant_id: str | None = None
    matched_policy_id: str | None = None

    def as_dict(self) -> dict:
        return {
            "decision": self.decision,
            "reason": self.reason,
            "ttl_seconds": self.ttl_seconds,
            "constraints": self.constraints or default_constraints(),
            "matched_grant_id": self.matched_grant_id,
            "matched_policy_id": self.matched_policy_id,
        }


def default_constraints() -> dict:
    return {
        "permit_pty": True,
        "permit_agent_forwarding": False,
        "permit_x11_forwarding": False,
        "require_user_presence": False,
    }


def evaluate_access(
    *,
    device: Device,
    server: Server,
    ssh_principal: str,
    source_ip: str | None,
    default_ttl_seconds: int,
) -> PolicyDecision:
    user = User.query.filter_by(id=device.user_id).one_or_none()
    if user is None or user.status != "active":
        return PolicyDecision("deny", "user_not_active")
    if device.status != "trusted":
        return PolicyDecision("deny", "device_not_trusted")
    if server.status != "enrolled":
        return PolicyDecision("deny", "server_not_enrolled")

    grant = _find_matching_grant(device= device, server=server, ssh_principal=ssh_principal)
    if grant is None:
        return PolicyDecision("deny", "no_matching_access_grant")

    policy_decision = _evaluate_policies(
        device=device,
        server=server,
        ssh_principal=ssh_principal,
        source_ip=source_ip,
        default_ttl_seconds=default_ttl_seconds,
    )
    if policy_decision.decision == "deny":
        return policy_decision

    return PolicyDecision(
        "allow",
        policy_decision.reason,
        ttl_seconds=policy_decision.ttl_seconds,
        constraints=policy_decision.constraints,
        matched_grant_id=str(grant.id),
        matched_policy_id=policy_decision.matched_policy_id,
    )


def _find_matching_grant(*, device: Device, server: Server, ssh_principal: str) -> AccessGrant | None:
    now = utcnow()
    user_group_ids = {
        row.group_id for row in UserGroup.query.filter_by(user_id=device.user_id).all()
    }
    server_group_ids = {
        row.group_id for row in ServerGroupMember.query.filter_by(server_id=server.id).all()
    }

    grants = AccessGrant.query.all()
    for grant in grants:
        if grant.valid_from and ensure_aware(grant.valid_from) > now:
            continue
        if grant.valid_until and ensure_aware(grant.valid_until) < now:
            continue
        if ssh_principal not in grant.unix_principals and "*" not in grant.unix_principals:
            continue
        if not _subject_matches(grant, device, user_group_ids):
            continue
        if not _server_scope_matches(grant, server, server_group_ids):
            continue
        return grant
    return None


def _subject_matches(grant: AccessGrant, device: Device, user_group_ids: set[UUID]) -> bool:
    if grant.subject_type == "user":
        return grant.subject_id == device.user_id
    if grant.subject_type == "group":
        return grant.subject_id in user_group_ids
    return False


def _server_scope_matches(grant: AccessGrant, server: Server, server_group_ids: set[UUID]) -> bool:
    if grant.server_scope_type == "server":
        return grant.server_scope_id == server.id
    if grant.server_scope_type == "server_group":
        return grant.server_scope_id in server_group_ids
    if grant.server_scope_type == "all":
        return True
    return False


def _evaluate_policies(
    *,
    device: Device,
    server: Server,
    ssh_principal: str,
    source_ip: str | None,
    default_ttl_seconds: int,
) -> PolicyDecision:
    constraints = default_constraints()
    ttl_seconds = default_ttl_seconds

    policies = Policy.query.filter_by(enabled=True).order_by(Policy.priority.asc()).all()
    for policy in policies:
        if not _conditions_match(policy.conditions, device, server, ssh_principal, source_ip):
            continue

        if policy.effect == "deny":
            return PolicyDecision(
                "deny",
                policy.actions.get("reason", "policy_denied"),
                matched_policy_id=str(policy.id),
            )

        if policy.effect == "allow":
            ttl_seconds = int(policy.actions.get("ttl_seconds", ttl_seconds))
            constraints.update(policy.actions.get("constraints", {}))
            return PolicyDecision(
                "allow",
                "policy_allowed",
                ttl_seconds=ttl_seconds,
                constraints=constraints,
                matched_policy_id=str(policy.id),
            )

    return PolicyDecision(
        "allow",
        "access_grant_allowed",
        ttl_seconds=ttl_seconds,
        constraints=constraints,
    )


def _conditions_match(
    conditions: dict,
    device: Device,
    server: Server,
    ssh_principal: str,
    source_ip: str | None,
) -> bool:
    if not conditions:
        return True

    if "device_status" in conditions and conditions["device_status"] != device.status:
        return False
    if "server_environment" in conditions and conditions["server_environment"] != server.environment:
        return False
    if "ssh_principal" in conditions and conditions["ssh_principal"] != ssh_principal:
        return False
    if "source_ip" in conditions and conditions["source_ip"] != source_ip:
        return False
    if "user_id" in conditions and conditions["user_id"] != str(device.user_id):
        return False
    if "group_id" in conditions:
        group_ids = {str(row.group_id) for row in UserGroup.query.filter_by(user_id=device.user_id).all()}
        if conditions["group_id"] not in group_ids:
            return False
    if "server_tags" in conditions:
        for key, value in conditions["server_tags"].items():
            if server.tags.get(key) != value:
                return False
    return True


def simulate_policy(payload: dict, default_ttl_seconds: int = 300) -> dict:
    try:
        device_id = UUID(payload.get("device_id", ""))
        server_id = UUID(payload.get("server_id", ""))
    except ValueError:
        return PolicyDecision("deny", "invalid_device_or_server_id").as_dict()

    device = Device.query.filter_by(id=device_id).one_or_none()
    server = Server.query.filter_by(id=server_id).one_or_none()
    if device is None:
        return PolicyDecision("deny", "device_not_found").as_dict()
    if server is None:
        return PolicyDecision("deny", "server_not_found").as_dict()
    return evaluate_access(
        device=device,
        server=server,
        ssh_principal=payload.get("ssh_principal", ""),
        source_ip=payload.get("source_ip"),
        default_ttl_seconds=default_ttl_seconds,
    ).as_dict()
