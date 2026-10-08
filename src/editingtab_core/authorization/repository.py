"""Scoped queries and mutations only; callers own transactions and organization locks."""

from sqlalchemy import and_, delete, select

from editingtab_core.authorization.models import (
    BookingPermissionManagerDesignation,
    BookingPermissionManagerScope,
    MembershipRole,
    PermissionDefinition,
    Role,
    RoleAudit,
    RolePermission,
)
from editingtab_core.authorization.policy import ADMINISTRATOR_PERMISSIONS
from editingtab_core.identity.models import Membership, Organization, User
from editingtab_core.platform.models import ModuleEntitlement


def active_members(organization_id):
    return (
        select(Membership, User)
        .join(User, User.id == Membership.user_id)
        .join(Organization, Organization.id == Membership.organization_id)
        .where(
            Membership.organization_id == organization_id,
            Membership.deleted_at.is_(None),
            Organization.deleted_at.is_(None),
            User.deleted_at.is_(None),
            User.is_active.is_(True),
        )
    )


def members(organization_id):
    return (
        select(Membership, User)
        .join(User, User.id == Membership.user_id)
        .join(Organization, Organization.id == Membership.organization_id)
        .where(
            Membership.organization_id == organization_id,
            Organization.deleted_at.is_(None),
            User.deleted_at.is_(None),
        )
    )


def permission_query(organization_id):
    return (
        select(RolePermission.code)
        .select_from(RolePermission)
        .join(
            Role,
            and_(
                Role.id == RolePermission.role_id,
                Role.organization_id == RolePermission.organization_id,
            ),
        )
        .join(
            MembershipRole,
            and_(
                MembershipRole.role_id == Role.id,
                MembershipRole.organization_id == Role.organization_id,
            ),
        )
        .join(
            Membership,
            and_(
                Membership.id == MembershipRole.membership_id,
                Membership.organization_id == MembershipRole.organization_id,
            ),
        )
        .join(User, User.id == Membership.user_id)
        .join(Organization, Organization.id == Membership.organization_id)
        .where(
            RolePermission.organization_id == organization_id,
            Role.deleted_at.is_(None),
            Membership.deleted_at.is_(None),
            User.deleted_at.is_(None),
            User.is_active.is_(True),
            Organization.deleted_at.is_(None),
        )
    )


def effective_permissions(session, organization_id, actor_id):
    return frozenset(session.scalars(permission_query(organization_id).where(User.id == actor_id)))


def effective_grant_authority(session, organization_id, actor_id):
    return frozenset(
        session.scalars(
            permission_query(organization_id).where(
                User.id == actor_id, RolePermission.can_grant.is_(True)
            )
        )
    )


def grant_only_permission_management_query(organization_id):
    """Active membership-scoped authority, gated by assignment and entitlement."""
    return (
        select(BookingPermissionManagerScope.code)
        .select_from(BookingPermissionManagerScope)
        .join(
            BookingPermissionManagerDesignation,
            and_(
                BookingPermissionManagerDesignation.organization_id
                == BookingPermissionManagerScope.organization_id,
                BookingPermissionManagerDesignation.membership_id
                == BookingPermissionManagerScope.membership_id,
            ),
        )
        .join(
            Role,
            and_(
                Role.id == BookingPermissionManagerDesignation.role_id,
                Role.organization_id == BookingPermissionManagerDesignation.organization_id,
            ),
        )
        .join(
            MembershipRole,
            and_(
                MembershipRole.role_id == Role.id,
                MembershipRole.organization_id == Role.organization_id,
                MembershipRole.membership_id == BookingPermissionManagerDesignation.membership_id,
            ),
        )
        .join(
            Membership,
            and_(
                Membership.id == MembershipRole.membership_id,
                Membership.organization_id == MembershipRole.organization_id,
            ),
        )
        .join(User, User.id == Membership.user_id)
        .join(Organization, Organization.id == Membership.organization_id)
        .join(
            PermissionDefinition,
            PermissionDefinition.code == BookingPermissionManagerScope.code,
        )
        .join(
            ModuleEntitlement,
            and_(
                ModuleEntitlement.organization_id == BookingPermissionManagerScope.organization_id,
                ModuleEntitlement.module_code == PermissionDefinition.module,
            ),
        )
        .where(
            BookingPermissionManagerScope.organization_id == organization_id,
            BookingPermissionManagerDesignation.revoked_at.is_(None),
            Role.provisioning_kind == "booking_permission_manager",
            Role.deleted_at.is_(None),
            Membership.deleted_at.is_(None),
            User.deleted_at.is_(None),
            User.is_active.is_(True),
            Organization.deleted_at.is_(None),
            ModuleEntitlement.enabled.is_(True),
        )
    )


def effective_grant_only_permission_management_authority(session, organization_id, actor_id):
    return frozenset(
        session.scalars(
            grant_only_permission_management_query(organization_id).where(User.id == actor_id)
        )
    )


def effective_permission_management_authority(session, organization_id, actor_id):
    return effective_grant_authority(
        session, organization_id, actor_id
    ) | effective_grant_only_permission_management_authority(session, organization_id, actor_id)


def assignable_permission_codes(session, codes):
    requested = frozenset(codes)
    if not requested:
        return requested
    found = frozenset(
        session.scalars(
            select(PermissionDefinition.code).where(
                PermissionDefinition.code.in_(requested),
                PermissionDefinition.organization_assignable.is_(True),
                PermissionDefinition.lifecycle == "active",
            )
        )
    )
    return found


def permission_catalog(session):
    return session.scalars(
        select(PermissionDefinition)
        .where(
            PermissionDefinition.organization_assignable.is_(True),
            PermissionDefinition.lifecycle == "active",
        )
        .order_by(PermissionDefinition.module, PermissionDefinition.code)
    )


def has_administrator(session, organization_id):
    user_ids = session.scalars(active_members(organization_id).with_only_columns(User.id)).all()
    for user_id in user_ids:
        if ADMINISTRATOR_PERMISSIONS <= effective_permissions(
            session, organization_id, user_id
        ) and ADMINISTRATOR_PERMISSIONS <= effective_grant_authority(
            session, organization_id, user_id
        ):
            return True
    return False


def role_permissions(session, organization_id, role_id):
    return frozenset(
        session.scalars(
            select(RolePermission.code).where(
                RolePermission.organization_id == organization_id, RolePermission.role_id == role_id
            )
        )
    )


def role_permission_grants(session, organization_id, role_id):
    return {
        code: can_grant
        for code, can_grant in session.execute(
            select(RolePermission.code, RolePermission.can_grant).where(
                RolePermission.organization_id == organization_id,
                RolePermission.role_id == role_id,
            )
        )
    }


def booking_permission_manager_scopes(session, organization_id, membership_id):
    return frozenset(
        session.scalars(
            select(BookingPermissionManagerScope.code).where(
                BookingPermissionManagerScope.organization_id == organization_id,
                BookingPermissionManagerScope.membership_id == membership_id,
            )
        )
    )


def membership_roles(session, organization_id, membership_id):
    return list(
        session.scalars(
            select(Role)
            .join(
                MembershipRole,
                and_(
                    MembershipRole.role_id == Role.id,
                    MembershipRole.organization_id == Role.organization_id,
                ),
            )
            .where(
                MembershipRole.organization_id == organization_id,
                MembershipRole.membership_id == membership_id,
                Role.deleted_at.is_(None),
            )
            .order_by(Role.name, Role.id)
        )
    )


def role_assignments(session, organization_id, role_id):
    return list(
        session.scalars(
            select(MembershipRole).where(
                MembershipRole.organization_id == organization_id,
                MembershipRole.role_id == role_id,
            )
        )
    )


def replace_permissions(session, organization_id, role_id, permissions):
    session.execute(
        delete(RolePermission).where(
            RolePermission.organization_id == organization_id, RolePermission.role_id == role_id
        )
    )
    session.add_all(
        RolePermission(
            organization_id=organization_id,
            role_id=role_id,
            code=code,
            can_grant=permissions[code],
        )
        for code in sorted(permissions)
    )
    session.flush()


def permission_state(permissions):
    return [
        {"code": code, "can_grant": can_grant} for code, can_grant in sorted(permissions.items())
    ]


def audit(session, organization_id, actor_id, action, role_id, before, after, membership_id=None):
    session.add(
        RoleAudit(
            organization_id=organization_id,
            actor_id=actor_id,
            action=action,
            target_id=role_id,
            membership_id=membership_id,
            permissions_before=permission_state(before),
            permissions_after=permission_state(after),
        )
    )
    session.flush()


def member_audit(session, organization_id, actor_id, action, membership_id, user_id):
    # RoleAudit is the existing organization authorization audit ledger. For member
    # lifecycle events target_id identifies the global user and membership_id the
    # organization relationship; no account-security data is recorded.
    audit(session, organization_id, actor_id, action, user_id, {}, {}, membership_id)
