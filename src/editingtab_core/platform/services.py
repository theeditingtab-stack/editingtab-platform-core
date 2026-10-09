"""Company operations with current authority checks and atomic writes."""

from datetime import UTC, datetime

from sqlalchemy import select

from editingtab_core.auth import repository as auth_repository
from editingtab_core.auth.models import PasswordCredential
from editingtab_core.auth.security import Passwords, validate_password
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
PLATFORM_ADMIN_EMAIL = "editingtab.dev@gmail.com"


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


def bootstrap_initial(session, *, passwords: Passwords, password: str, display_name: str):
    """Create the designated administrator once; repeat calls never change credentials."""
    email = PLATFORM_ADMIN_EMAIL
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
        existing_user = session.scalar(
            select(User)
            .where(User.normalized_email == normalized)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        existing_grant = session.scalar(
            select(PlatformAdminGrant)
            .join(User)
            .where(User.normalized_email == normalized)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        any_grant = session.scalar(select(PlatformAdminGrant.id).limit(1))
        if state.completed_at is not None:
            if (
                existing_user is not None
                and existing_user.is_active
                and existing_user.deleted_at is None
                and existing_grant is not None
                and existing_grant.revoked_at is None
            ):
                return existing_grant.id
            raise BootstrapClosed()
        if any_grant is not None:
            raise BootstrapClosed()
        if existing_user is not None and (
            not existing_user.is_active or existing_user.deleted_at is not None
        ):
            raise InvalidOnboarding()
        if existing_user is None:
            validate_password(password)
            try:
                name = clean_name(display_name)
            except InvalidIdentity:
                raise InvalidOnboarding() from None
            existing_user = User(
                email=normalized,
                normalized_email=normalized,
                display_name=name,
            )
            session.add(existing_user)
            session.flush()
        credential = session.get(PasswordCredential, existing_user.id, with_for_update=True)
        if credential is None:
            validate_password(password)
            session.add(
                PasswordCredential(
                    user_id=existing_user.id,
                    password_hash=passwords.hash(password),
                )
            )
        grant = PlatformAdminGrant(user_id=existing_user.id)
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
            after={"user_id": str(existing_user.id), "active": True},
        )
        return grant.id


def recover_platform_admin(session, *, passwords: Passwords, password: str):
    """Explicit operator recovery; never used by startup or tenant-facing HTTP."""
    validate_password(password)
    _, normalized = normalize_email(PLATFORM_ADMIN_EMAIL)
    with transaction(session):
        state = session.scalar(
            select(BootstrapState)
            .where(BootstrapState.id == 1)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        if state is None or state.completed_at is None:
            raise BootstrapClosed()
        user = session.scalar(
            select(User)
            .where(User.normalized_email == normalized)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        if user is None or not user.is_active or user.deleted_at is not None:
            raise InvalidOnboarding()
        credential = session.get(PasswordCredential, user.id, with_for_update=True)
        if credential is None:
            credential = PasswordCredential(user_id=user.id, password_hash=passwords.hash(password))
            session.add(credential)
        else:
            credential.password_hash = passwords.hash(password)
        grant = session.scalar(
            select(PlatformAdminGrant)
            .where(PlatformAdminGrant.user_id == user.id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        before = {"active": grant is not None and grant.revoked_at is None}
        if grant is None:
            grant = PlatformAdminGrant(user_id=user.id)
            session.add(grant)
            session.flush()
        else:
            grant.revoked_at = None
        revoked_sessions = auth_repository.revoke_user_sessions(session, user.id)
        _audit(
            session,
            actor_id=None,
            organization_id=None,
            action="operator.recovery",
            target_id=grant.id,
            before=before,
            after={"active": True, "sessions_revoked": revoked_sessions},
        )
        auth_repository.audit(
            session,
            action="password.recovered",
            target_id=user.id,
            details={"method": "operator_recovery", "sessions_revoked": revoked_sessions},
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


def read_organization(session, *, actor_id, organization_id):
    with transaction(session):
        _require_platform(session, actor_id)
        org = _organization(session, organization_id)
        return {**_info(org), "enabled_modules": _enabled(session, organization_id)}


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
