"""Company operations with current authority checks and atomic writes."""

from datetime import UTC, datetime

from sqlalchemy import select

from editingtab_core.auth.models import PasswordCredential
from editingtab_core.authorization.onboarding import _create_owned_organization
from editingtab_core.authorization.policy import (
    AccessError,
    Conflict,
    Inaccessible,
    StorageUnavailable,
)
from editingtab_core.authorization.services import authorize, transaction
from editingtab_core.identity.errors import InvalidIdentity
from editingtab_core.identity.models import Organization, User
from editingtab_core.identity.normalization import clean_name, normalize_email, normalize_slug
from editingtab_core.platform.models import (
    BootstrapState,
    ModuleEntitlement,
    PlatformAdminGrant,
    PlatformAudit,
)

MODULE_CATALOG = frozenset({"booking", "pos", "unified_inbox", "chatbot"})
SUPPORTED_MODULES = frozenset({"booking"})


class OrganizationConflict(Conflict):
    message = "Organization slug is already reserved; existing records were not changed."


class InvalidModule(AccessError):
    status = 422
    message = "Unknown module or activation not yet supported."


class InvalidOnboarding(AccessError):
    status = 422
    message = "Invalid organization details or eligible owner unavailable."


class BootstrapClosed(AccessError):
    status = 409
    message = "Initial bootstrap is closed; use a separate controlled recovery process."


def _module(code, enabled=False):
    if code not in MODULE_CATALOG or (enabled and code not in SUPPORTED_MODULES):
        raise InvalidModule()


def _audit(session, *, actor_id, organization_id, action, target_id, before, after):
    session.add(
        PlatformAudit(
            actor_id=actor_id,
            actor_kind="operator_bootstrap" if actor_id is None else "authenticated_user",
            organization_id=organization_id,
            action=action,
            target_id=target_id,
            before=before,
            after=after,
        )
    )
    session.flush()


def _require_platform(session, actor_id):
    # Check scalars in PostgreSQL each time, not cached ORM attributes/session claims.
    grant = session.scalar(
        select(PlatformAdminGrant.id)
        .join(User)
        .where(
            User.id == actor_id,
            User.is_active.is_(True),
            User.deleted_at.is_(None),
            PlatformAdminGrant.revoked_at.is_(None),
        )
    )
    if grant is None:
        raise AccessError()


def bootstrap_initial(session, *, email):
    """Operator-only entry point. CLI requires confirmation; never exposed over HTTP."""
    try:
        _, normalized = normalize_email(email)
    except InvalidIdentity:
        raise InvalidOnboarding() from None
    with transaction(session):
        state = session.scalar(
            select(BootstrapState)
            .where(BootstrapState.id == 1)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        if state is None:
            raise StorageUnavailable()
        if state.completed_at is not None or session.scalar(select(PlatformAdminGrant.id).limit(1)):
            raise BootstrapClosed()
        user_id = session.scalar(
            select(User.id)
            .where(
                User.normalized_email == normalized,
                User.is_active.is_(True),
                User.deleted_at.is_(None),
            )
            .with_for_update()
        )
        if user_id is None:
            raise InvalidOnboarding()
        grant = PlatformAdminGrant(user_id=user_id)
        session.add(grant)
        session.flush()
        state.completed_at = datetime.now(UTC)
        _audit(
            session,
            actor_id=None,
            organization_id=None,
            action="operator.bootstrap",
            target_id=grant.id,
            before={},
            after={"user_id": str(user_id), "active": True},
        )
        return grant.id


def _organization(session, organization_id, *, lock=False):
    query = select(Organization).where(
        Organization.id == organization_id, Organization.deleted_at.is_(None)
    )
    if lock:
        query = query.with_for_update()
    org = session.scalar(query.execution_options(populate_existing=True))
    if org is None:
        raise Inaccessible()
    return org


def _info(org):
    return {"id": org.id, "name": org.name, "slug": org.slug}


def list_organizations(session, *, actor_id, limit=50, offset=0):
    with transaction(session):
        _require_platform(session, actor_id)
        if not 1 <= limit <= 100 or not 0 <= offset <= 100000:
            raise InvalidOnboarding()
        return [
            _info(org)
            for org in session.scalars(
                select(Organization)
                .where(Organization.deleted_at.is_(None))
                .order_by(Organization.id)
                .limit(limit)
                .offset(offset)
            )
        ]


def onboard(session, *, actor_id, name, slug, owner_email, enabled_modules=()):
    try:
        with transaction(session):
            _require_platform(session, actor_id)
            try:
                name, slug = clean_name(name), normalize_slug(slug)
                _, normalized = normalize_email(owner_email)
            except InvalidIdentity:
                raise InvalidOnboarding() from None
            modules = frozenset(enabled_modules)
            for code in modules:
                _module(code, True)
            if session.scalar(select(Organization.id).where(Organization.slug == slug)) is not None:
                raise Conflict()
            owner_id = session.scalar(
                select(User.id)
                .join(PasswordCredential)
                .where(
                    User.normalized_email == normalized,
                    User.is_active.is_(True),
                    User.deleted_at.is_(None),
                )
                .with_for_update(of=User)
            )
            if owner_id is None:
                raise InvalidOnboarding()
            org = _create_owned_organization(
                session, name=name, slug=slug, owner_id=owner_id, actor_id=actor_id
            )
            for code in sorted(modules):
                session.add(
                    ModuleEntitlement(organization_id=org.id, module_code=code, enabled=True)
                )
            _audit(
                session,
                actor_id=actor_id,
                organization_id=org.id,
                action="organization.onboarded",
                target_id=org.id,
                before={},
                after={"owner_id": str(owner_id), "enabled_modules": sorted(modules)},
            )
            return {**_info(org), "enabled_modules": sorted(modules)}
    except Conflict:
        raise OrganizationConflict() from None


def _enabled(session, organization_id):
    return list(
        session.scalars(
            select(ModuleEntitlement.module_code)
            .where(
                ModuleEntitlement.organization_id == organization_id,
                ModuleEntitlement.enabled.is_(True),
                ModuleEntitlement.module_code.in_(SUPPORTED_MODULES),
            )
            .order_by(ModuleEntitlement.module_code)
        )
    )


def read_entitlements(session, *, actor_id, organization_id):
    with transaction(session):
        _require_platform(session, actor_id)
        _organization(session, organization_id)
        return {
            "organization_id": organization_id,
            "enabled_modules": _enabled(session, organization_id),
        }


def tenant_entitlements(session, *, actor_id, organization_id):
    with transaction(session):
        authorize(session, organization_id, actor_id, "core.organization.read")
        return {
            "organization_id": organization_id,
            "enabled_modules": _enabled(session, organization_id),
        }


def set_entitlement(session, *, actor_id, organization_id, module_code, enabled):
    with transaction(session):
        _require_platform(session, actor_id)
        _module(module_code, enabled)
        if type(enabled) is not bool:
            raise InvalidModule()
        _organization(session, organization_id, lock=True)
        row = session.get(ModuleEntitlement, (organization_id, module_code), populate_existing=True)
        previous = row.enabled if row is not None else False
        if previous != enabled:
            if row is None:
                row = ModuleEntitlement(
                    organization_id=organization_id, module_code=module_code, enabled=enabled
                )
                session.add(row)
            else:
                row.enabled = enabled
            _audit(
                session,
                actor_id=actor_id,
                organization_id=organization_id,
                action="entitlement.changed",
                target_id=organization_id,
                before={"module": module_code, "enabled": previous},
                after={"module": module_code, "enabled": enabled},
            )
        return {
            "organization_id": organization_id,
            "enabled_modules": _enabled(session, organization_id),
        }


def require_entitlement(session, *, organization_id, module_code):
    """Inside a caller-owned transaction, AFTER tenant permission authorization.

    Entitlements are product access only. Future module services must separately
    authenticate and authorize their operation; platform grants do not bypass that.
    """
    _module(module_code, True)
    _organization(session, organization_id)
    if module_code not in _enabled(session, organization_id):
        raise AccessError()
