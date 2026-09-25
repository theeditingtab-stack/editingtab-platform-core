"""Explicit trusted provisioning, never a bypass in tenant role-management services."""

from datetime import UTC, datetime

from sqlalchemy import select

from editingtab_core.authorization import repository as repo
from editingtab_core.authorization.models import MembershipRole, Role
from editingtab_core.authorization.policy import (
    BOOKING_INVENTORY_PERMISSIONS,
    ROLE_ASSIGN,
    Conflict,
    Inaccessible,
)
from editingtab_core.authorization.services import authorize, transaction
from editingtab_core.identity.models import Membership, User
from editingtab_core.platform.services import (
    _audit,
    _organization,
    _require_platform,
    require_entitlement,
)

ROLE_NAME = "Booking inventory administrator"
KIND = "booking_inventory"


def provision(session, *, actor_id, organization_id, membership_id):
    with transaction(session):
        _require_platform(session, actor_id)
        _organization(session, organization_id, lock=True)
        require_entitlement(session, organization_id=organization_id, module_code="booking")
        member = session.scalar(
            select(Membership)
            .join(User)
            .where(
                Membership.id == membership_id,
                Membership.organization_id == organization_id,
                Membership.deleted_at.is_(None),
                User.deleted_at.is_(None),
                User.is_active.is_(True),
            )
        )
        if member is None:
            raise Inaccessible()
        authorize(session, organization_id, member.user_id, ROLE_ASSIGN)
        designated = session.scalar(
            select(Role)
            .where(
                Role.organization_id == organization_id,
                Role.provisioning_kind == KIND,
            )
            .execution_options(populate_existing=True)
        )
        named = session.scalar(
            select(Role.id).where(
                Role.organization_id == organization_id,
                Role.normalized_name == ROLE_NAME.lower(),
            )
        )
        if designated is None:
            if named is not None:
                raise Conflict()
            designated = Role(
                organization_id=organization_id,
                name=ROLE_NAME,
                normalized_name=ROLE_NAME.lower(),
                provisioning_kind=KIND,
            )
            session.add(designated)
            session.flush()
        elif (
            designated.deleted_at is not None
            or designated.name != ROLE_NAME
            or named != designated.id
        ):
            raise Conflict()
        before = repo.role_permission_grants(session, organization_id, designated.id)
        # Never remove unrelated privileges or take over a tenant-repurposed role.
        if not before.keys() <= BOOKING_INVENTORY_PERMISSIONS:
            raise Conflict()
        assignment = session.get(MembershipRole, (organization_id, membership_id, designated.id))
        was_assigned = assignment is not None
        after = dict.fromkeys(BOOKING_INVENTORY_PERMISSIONS, False)
        if before != after:
            designated.updated_at = datetime.now(UTC)
            repo.replace_permissions(session, organization_id, designated.id, after)
            repo.audit(
                session,
                organization_id,
                actor_id,
                "booking.role.provisioned",
                designated.id,
                before,
                after,
            )
        if not was_assigned:
            session.add(
                MembershipRole(
                    organization_id=organization_id,
                    membership_id=membership_id,
                    role_id=designated.id,
                )
            )
            repo.audit(
                session,
                organization_id,
                actor_id,
                "assignment.added",
                designated.id,
                {},
                after,
                membership_id,
            )
        if before != after or not was_assigned:
            _audit(
                session,
                actor_id=actor_id,
                organization_id=organization_id,
                action="booking.permissions.provisioned",
                target_id=membership_id,
                before={"permissions": repo.permission_state(before), "assigned": was_assigned},
                after={
                    "role_id": str(designated.id),
                    "permissions": repo.permission_state(after),
                    "assigned": True,
                },
            )
        return {
            "organization_id": organization_id,
            "membership_id": membership_id,
            "role_id": designated.id,
            "permissions": sorted(BOOKING_INVENTORY_PERMISSIONS),
        }
