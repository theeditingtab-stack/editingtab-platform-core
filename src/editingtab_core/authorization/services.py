"""Authorization is enforced here, including for callers outside HTTP routes."""

from contextlib import contextmanager
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from editingtab_core.authorization import repository as repo
from editingtab_core.authorization.models import MembershipRole, Role
from editingtab_core.authorization.policy import (
    MANAGE,
    AccessError,
    Conflict,
    Inaccessible,
    InvalidPermission,
    LastAdministrator,
    StorageUnavailable,
    role_name,
)
from editingtab_core.identity.models import Membership, Organization, User


@contextmanager
def transaction(session):
    if session.in_transaction():
        raise StorageUnavailable()
    try:
        with session.begin():
            yield
    except IntegrityError as error:
        constraint = getattr(getattr(error.orig, "diag", None), "constraint_name", None)
        if constraint in {
            "uq_core_roles_name",
            "core_membership_roles_pkey",
            "uq_core_organizations_slug",
        }:
            raise Conflict() from None
        raise StorageUnavailable() from None
    except SQLAlchemyError:
        raise StorageUnavailable() from None


def authorize(session, organization_id, actor_id, code, *, lock=False):
    if repo.assignable_permission_codes(session, [code]) != {code}:
        raise InvalidPermission()
    query = select(Organization).where(
        Organization.id == organization_id, Organization.deleted_at.is_(None)
    )
    if lock:
        query = query.with_for_update()
    organization = session.scalar(query.execution_options(populate_existing=True))
    if (
        organization is None
        or session.execute(repo.active_members(organization_id).where(User.id == actor_id)).first()
        is None
    ):
        raise Inaccessible()
    held = repo.effective_permissions(session, organization_id, actor_id)
    if code not in held:
        raise AccessError()
    return organization, held


def _role(session, organization_id, role_id, *, archived=False):
    query = select(Role).where(Role.organization_id == organization_id, Role.id == role_id)
    if not archived:
        query = query.where(Role.deleted_at.is_(None))
    role = session.scalar(query.execution_options(populate_existing=True))
    if role is None:
        raise Inaccessible()
    return role


def _grantable(held, codes):
    if not codes <= held:
        raise AccessError()


def _permissions(session, values):
    result = frozenset(values)
    if repo.assignable_permission_codes(session, result) != result:
        raise InvalidPermission()
    return result


def ensure_administrator(session, organization_id):
    session.flush()
    if not repo.has_administrator(session, organization_id):
        raise LastAdministrator()


def _role_info(session, role):
    return {
        "id": role.id,
        "name": role.name,
        "permissions": sorted(repo.role_permissions(session, role.organization_id, role.id)),
    }


def _page(limit, offset):
    if not 1 <= limit <= 100 or not 0 <= offset <= 100000:
        raise InvalidPermission()


def list_organizations(session, *, actor_id, limit=50, offset=0):
    _page(limit, offset)
    with transaction(session):
        rows = session.scalars(
            select(Organization)
            .join(Membership)
            .join(User)
            .where(
                User.id == actor_id,
                User.is_active.is_(True),
                User.deleted_at.is_(None),
                Organization.deleted_at.is_(None),
                Membership.deleted_at.is_(None),
            )
            .order_by(Organization.id)
            .limit(limit)
            .offset(offset)
        )
        return [{"id": row.id, "name": row.name, "slug": row.slug} for row in rows]


def read_organization(session, *, organization_id, actor_id):
    with transaction(session):
        org, _ = authorize(session, organization_id, actor_id, "core.organization.read")
        return {"id": org.id, "name": org.name, "slug": org.slug}


def list_members(session, *, organization_id, actor_id, limit=50, offset=0):
    _page(limit, offset)
    with transaction(session):
        authorize(session, organization_id, actor_id, "core.members.read")
        rows = session.execute(
            repo.active_members(organization_id).order_by(Membership.id).limit(limit).offset(offset)
        )
        return [
            {"id": member.id, "user_id": user.id, "display_name": user.display_name}
            for member, user in rows
        ]


def list_roles(session, *, organization_id, actor_id, limit=50, offset=0):
    _page(limit, offset)
    with transaction(session):
        authorize(session, organization_id, actor_id, "core.roles.read")
        roles = session.scalars(
            select(Role)
            .where(Role.organization_id == organization_id, Role.deleted_at.is_(None))
            .order_by(Role.id)
            .limit(limit)
            .offset(offset)
        )
        return [_role_info(session, role) for role in roles]


def list_permission_catalog(session, *, organization_id, actor_id):
    with transaction(session):
        authorize(session, organization_id, actor_id, "core.roles.read")
        return [
            {
                "code": definition.code,
                "module": definition.module,
                "description": definition.description,
                "lifecycle": definition.lifecycle,
            }
            for definition in repo.permission_catalog(session)
        ]


def create_role(session, *, organization_id, actor_id, name, codes):
    with transaction(session):
        _, held = authorize(session, organization_id, actor_id, MANAGE, lock=True)
        selected = _permissions(session, codes)
        _grantable(held, selected)
        display, normalized = role_name(name)
        role = Role(organization_id=organization_id, name=display, normalized_name=normalized)
        session.add(role)
        session.flush()
        repo.replace_permissions(session, organization_id, role.id, selected)
        repo.audit(session, organization_id, actor_id, "role.created", role.id, [], selected)
        return _role_info(session, role)


def update_role(session, *, organization_id, actor_id, role_id, name, codes):
    with transaction(session):
        _, held = authorize(session, organization_id, actor_id, MANAGE, lock=True)
        role = _role(session, organization_id, role_id)
        before = repo.role_permissions(session, organization_id, role_id)
        after = _permissions(session, codes)
        _grantable(held, before | after)
        role.name, role.normalized_name = role_name(name)
        role.updated_at = datetime.now(UTC)
        repo.replace_permissions(session, organization_id, role_id, after)
        ensure_administrator(session, organization_id)
        repo.audit(session, organization_id, actor_id, "role.updated", role_id, before, after)
        return _role_info(session, role)


def archive_role(session, *, organization_id, actor_id, role_id):
    with transaction(session):
        _, held = authorize(session, organization_id, actor_id, MANAGE, lock=True)
        role = _role(session, organization_id, role_id)
        before = repo.role_permissions(session, organization_id, role_id)
        _grantable(held, before)
        role.deleted_at = datetime.now(UTC)
        ensure_administrator(session, organization_id)
        repo.audit(session, organization_id, actor_id, "role.archived", role_id, before, [])


def change_assignment(session, *, organization_id, actor_id, membership_id, role_id, remove=False):
    with transaction(session):
        _, held = authorize(session, organization_id, actor_id, MANAGE, lock=True)
        _role(session, organization_id, role_id, archived=remove)
        if (
            session.execute(
                repo.active_members(organization_id).where(Membership.id == membership_id)
            ).first()
            is None
        ):
            raise Inaccessible()
        codes = repo.role_permissions(session, organization_id, role_id)
        _grantable(held, codes)
        assignment = session.get(MembershipRole, (organization_id, membership_id, role_id))
        if remove:
            if assignment is None:
                raise Inaccessible()
            session.delete(assignment)
        else:
            if assignment is not None:
                return  # Idempotent addition, no fabricated change audit.
            session.add(
                MembershipRole(
                    organization_id=organization_id, membership_id=membership_id, role_id=role_id
                )
            )
        ensure_administrator(session, organization_id)
        repo.audit(
            session,
            organization_id,
            actor_id,
            "assignment.removed" if remove else "assignment.added",
            role_id,
            codes if remove else [],
            [] if remove else codes,
            membership_id,
        )


def before_membership_archive(session, organization, membership, actor_id):
    # Internal lifecycle hook: identity service already holds the organization lock.
    assignments = list(
        session.scalars(
            select(MembershipRole).where(
                MembershipRole.organization_id == organization.id,
                MembershipRole.membership_id == membership.id,
            )
        )
    )
    if not assignments:
        return
    if actor_id is None:
        raise AccessError()
    # Archived organization lifecycle may remove assignments only with an explicit actor;
    # ordinary role authority requires an active organization, so deny that path here.
    _, held = authorize(session, organization.id, actor_id, MANAGE)
    for assignment in assignments:
        codes = repo.role_permissions(session, organization.id, assignment.role_id)
        _grantable(held, codes)
        session.delete(assignment)
        repo.audit(
            session,
            organization.id,
            actor_id,
            "assignment.removed",
            assignment.role_id,
            codes,
            [],
            membership.id,
        )
    ensure_administrator(session, organization.id)


def before_membership_restore(session, organization_id, membership_id):
    if (
        session.scalar(
            select(MembershipRole.role_id)
            .where(
                MembershipRole.organization_id == organization_id,
                MembershipRole.membership_id == membership_id,
            )
            .limit(1)
        )
        is not None
    ):
        # Normally archive already removed these. Never revive historical/raw-SQL grants.
        raise AccessError()
