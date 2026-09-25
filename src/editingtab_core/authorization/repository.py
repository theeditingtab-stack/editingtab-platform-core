"""Scoped queries and mutations only; callers own transactions and organization locks."""

from sqlalchemy import and_, delete, select

from editingtab_core.authorization.models import (
    MembershipRole,
    PermissionDefinition,
    Role,
    RoleAudit,
    RolePermission,
)
from editingtab_core.authorization.policy import MANAGE
from editingtab_core.identity.models import Membership, Organization, User


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
    return (
        session.scalar(
            permission_query(organization_id).where(RolePermission.code == MANAGE).limit(1)
        )
        is not None
    )


def role_permissions(session, organization_id, role_id):
    return frozenset(
        session.scalars(
            select(RolePermission.code).where(
                RolePermission.organization_id == organization_id, RolePermission.role_id == role_id
            )
        )
    )


def replace_permissions(session, organization_id, role_id, codes):
    session.execute(
        delete(RolePermission).where(
            RolePermission.organization_id == organization_id, RolePermission.role_id == role_id
        )
    )
    session.add_all(
        RolePermission(organization_id=organization_id, role_id=role_id, code=code)
        for code in sorted(codes)
    )
    session.flush()


def audit(session, organization_id, actor_id, action, role_id, before, after, membership_id=None):
    session.add(
        RoleAudit(
            organization_id=organization_id,
            actor_id=actor_id,
            action=action,
            target_id=role_id,
            membership_id=membership_id,
            permissions_before=sorted(before),
            permissions_after=sorted(after),
        )
    )
    session.flush()
