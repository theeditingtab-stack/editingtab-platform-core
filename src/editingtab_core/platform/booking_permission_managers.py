"""Trusted platform lifecycle for independently scoped Booking permission managers."""

from datetime import UTC, datetime

from sqlalchemy import select

from editingtab_core.authorization import repository as repo
from editingtab_core.authorization.models import (
    BookingPermissionManagerDesignation,
    MembershipRole,
    PermissionDefinition,
    Role,
)
from editingtab_core.authorization.policy import (
    COMPANY_ADMINISTRATOR_PERMISSIONS,
    AccessError,
    Conflict,
    Inaccessible,
    InvalidPermission,
)
from editingtab_core.authorization.services import transaction
from editingtab_core.identity.models import Membership, User
from editingtab_core.platform.services import (
    _audit,
    _organization,
    _require_platform,
    require_entitlement,
)

ROLE_NAME = "Booking permission manager"
KIND = "booking_permission_manager"
MODULE = "booking"


def _scope_state(scopes):
    return sorted(scopes)


def _info(session, designation, user_id):
    return {
        "organization_id": designation.organization_id,
        "membership_id": designation.membership_id,
        "user_id": user_id,
        "role_id": designation.role_id,
        "state": "revoked" if designation.revoked_at is not None else "active",
        "scopes": _scope_state(
            repo.booking_permission_manager_scopes(
                session, designation.organization_id, designation.membership_id
            )
        ),
    }


def _member(session, organization_id, membership_id, *, lock=False):
    query = (
        select(Membership, User)
        .join(User, User.id == Membership.user_id)
        .where(
            Membership.id == membership_id,
            Membership.organization_id == organization_id,
            Membership.deleted_at.is_(None),
            Membership.is_active.is_(True),
            User.deleted_at.is_(None),
            User.is_active.is_(True),
        )
    )
    if lock:
        query = query.with_for_update(of=(Membership, User))
    row = session.execute(query.execution_options(populate_existing=True)).first()
    if row is None:
        raise Inaccessible()
    return row


def _validated_scopes(session, scopes):
    try:
        requested = list(scopes)
    except TypeError:
        raise InvalidPermission() from None
    if len(requested) > 100 or any(not isinstance(code, str) for code in requested):
        raise InvalidPermission()
    if len(requested) != len(set(requested)):
        raise InvalidPermission()
    selected = frozenset(requested)
    if not selected:
        return selected
    found = frozenset(
        session.scalars(
            select(PermissionDefinition.code).where(
                PermissionDefinition.code.in_(selected),
                PermissionDefinition.module == MODULE,
                PermissionDefinition.organization_assignable.is_(True),
                PermissionDefinition.lifecycle == "active",
            )
        )
    )
    if found != selected:
        raise InvalidPermission()
    return found


def _protected_role(session, organization_id, *, create):
    role = session.scalar(
        select(Role)
        .where(Role.organization_id == organization_id, Role.provisioning_kind == KIND)
        .execution_options(populate_existing=True)
    )
    named = session.scalar(
        select(Role.id).where(
            Role.organization_id == organization_id,
            Role.normalized_name == ROLE_NAME.lower(),
        )
    )
    if role is None:
        if not create:
            return None
        if named is not None:
            raise Conflict()
        role = Role(
            organization_id=organization_id,
            name=ROLE_NAME,
            normalized_name=ROLE_NAME.lower(),
            provisioning_kind=KIND,
        )
        session.add(role)
        session.flush()
    elif (
        role.deleted_at is not None
        or role.name != ROLE_NAME
        or role.normalized_name != ROLE_NAME.lower()
        or named != role.id
    ):
        raise Conflict()
    if repo.role_permission_grants(session, organization_id, role.id):
        raise Conflict()
    return role


def _audit_state(state, role_id, scopes):
    return {"state": state, "role_id": str(role_id), "scopes": _scope_state(scopes)}


def list_managers(session, *, actor_id, organization_id):
    with transaction(session):
        _require_platform(session, actor_id)
        _organization(session, organization_id)
        rows = session.execute(
            select(BookingPermissionManagerDesignation, Membership.user_id)
            .join(
                Membership,
                (Membership.id == BookingPermissionManagerDesignation.membership_id)
                & (
                    Membership.organization_id
                    == BookingPermissionManagerDesignation.organization_id
                ),
            )
            .where(BookingPermissionManagerDesignation.organization_id == organization_id)
            .order_by(BookingPermissionManagerDesignation.membership_id)
        )
        return [_info(session, designation, user_id) for designation, user_id in rows]


def designate(session, *, actor_id, organization_id, membership_id, scopes):
    with transaction(session):
        _require_platform(session, actor_id)
        _organization(session, organization_id, lock=True)
        require_entitlement(session, organization_id=organization_id, module_code=MODULE)
        membership, user = _member(session, organization_id, membership_id, lock=True)
        if not COMPANY_ADMINISTRATOR_PERMISSIONS <= repo.effective_permissions(
            session, organization_id, user.id
        ):
            raise AccessError()
        selected = _validated_scopes(session, scopes)
        role = _protected_role(session, organization_id, create=True)
        designation = session.get(
            BookingPermissionManagerDesignation,
            (organization_id, membership_id),
            with_for_update=True,
            populate_existing=True,
        )
        before_state = "absent"
        before_scopes = frozenset()
        if designation is None:
            designation = BookingPermissionManagerDesignation(
                organization_id=organization_id,
                membership_id=membership_id,
                role_id=role.id,
            )
            session.add(designation)
            session.flush()
        else:
            before_state = "revoked" if designation.revoked_at is not None else "active"
            before_scopes = repo.booking_permission_manager_scopes(
                session, organization_id, membership_id
            )
            designation.role_id = role.id
            designation.revoked_at = None

        assignment = session.get(MembershipRole, (organization_id, membership_id, role.id))
        was_assigned = assignment is not None
        if not was_assigned:
            session.add(
                MembershipRole(
                    organization_id=organization_id,
                    membership_id=membership_id,
                    role_id=role.id,
                )
            )
        if before_scopes != selected:
            repo.replace_booking_permission_manager_scopes(
                session, organization_id, membership_id, selected
            )

        changed_designation = before_state != "active" or not was_assigned
        changed_scopes = before_scopes != selected
        if changed_designation or changed_scopes:
            designation.updated_at = datetime.now(UTC)
            _audit(
                session,
                actor_id=actor_id,
                organization_id=organization_id,
                action=(
                    "booking.manager.designated"
                    if changed_designation
                    else "booking.manager.scopes_replaced"
                ),
                target_id=membership_id,
                before=_audit_state(before_state, role.id, before_scopes),
                after=_audit_state("active", role.id, selected),
            )
        return _info(session, designation, membership.user_id)


def revoke(session, *, actor_id, organization_id, membership_id):
    with transaction(session):
        _require_platform(session, actor_id)
        _organization(session, organization_id, lock=True)
        designation = session.get(
            BookingPermissionManagerDesignation,
            (organization_id, membership_id),
            with_for_update=True,
            populate_existing=True,
        )
        role = session.scalar(
            select(Role).where(
                Role.organization_id == organization_id,
                Role.provisioning_kind == KIND,
            )
        )
        assignment = None
        if role is not None:
            assignment = session.get(MembershipRole, (organization_id, membership_id, role.id))
        if designation is None and assignment is None:
            return

        scopes = (
            repo.booking_permission_manager_scopes(session, organization_id, membership_id)
            if designation is not None
            else frozenset()
        )
        was_active = designation is not None and designation.revoked_at is None
        if designation is not None and was_active:
            now = datetime.now(UTC)
            designation.revoked_at = now
            designation.updated_at = now
        if assignment is not None:
            session.delete(assignment)
        if was_active or assignment is not None:
            role_id = role.id if role is not None else designation.role_id
            if was_active:
                before_state = "active"
            elif designation is not None:
                before_state = "revoked"
            else:
                before_state = "assignment_only"
            after_state = "revoked" if designation is not None else "absent"
            _audit(
                session,
                actor_id=actor_id,
                organization_id=organization_id,
                action="booking.manager.revoked",
                target_id=membership_id,
                before=_audit_state(before_state, role_id, scopes),
                after=_audit_state(after_state, role_id, scopes),
            )
