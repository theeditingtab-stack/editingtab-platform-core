"""Global platform administration with current authority checks and atomic writes."""

import secrets
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, or_, select, update
from sqlalchemy.exc import SQLAlchemyError

from editingtab_core.auth import repository as auth_repository
from editingtab_core.auth.models import InvitationRole, OrganizationInvitation, PasswordCredential
from editingtab_core.auth.security import Passwords, SetupThrottled, token_digest, validate_password
from editingtab_core.authorization import repository as authorization_repository
from editingtab_core.authorization.models import (
    MembershipRole,
    PermissionDefinition,
    Role,
)
from editingtab_core.authorization.onboarding import _create_owned_organization
from editingtab_core.authorization.policy import (
    OWNER_PERMISSIONS,
    AccessError,
    Conflict,
    Inaccessible,
    LastAdministrator,
    StorageUnavailable,
)
from editingtab_core.authorization.services import authorize, transaction
from editingtab_core.config import Settings
from editingtab_core.identity import repository as identity_repository
from editingtab_core.identity.errors import InvalidIdentity
from editingtab_core.identity.models import Membership, Organization, User
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


class InvalidSetup(AccessError):
    status = 422
    message = "Invalid setup request."


class SetupAuthenticationFailed(AccessError):
    status = 401
    message = "Setup authentication failed."


class SetupUnavailable(StorageUnavailable):
    message = "Initial setup unavailable."


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


def _page(limit, offset):
    if not 1 <= limit <= 100 or not 0 <= offset <= 100000:
        raise InvalidOnboarding()


def _account_status(user):
    if user.deleted_at is not None:
        return "archived"
    return "active" if user.is_active else "inactive"


def _membership_status(membership, organization, user):
    if membership.deleted_at is not None:
        return "archived"
    if organization.deleted_at is not None:
        return "organization_archived"
    if not user.is_active or user.deleted_at is not None:
        return "account_inactive"
    return "active" if membership.is_active else "inactive"


def _role_system_managed(role):
    return role.normalized_name == "organization owner" or role.provisioning_kind is not None


def _platform_role_info(session, role, organization):
    permissions = authorization_repository.role_permission_grants(
        session, role.organization_id, role.id
    )
    assignments = session.scalar(
        select(func.count())
        .select_from(MembershipRole)
        .where(
            MembershipRole.organization_id == role.organization_id,
            MembershipRole.role_id == role.id,
        )
    )
    return {
        "id": role.id,
        "organization_id": organization.id,
        "organization_name": organization.name,
        "name": role.name,
        "scope": "organization",
        "state": "archived" if role.deleted_at is not None else "active",
        "system_managed": _role_system_managed(role),
        "permissions": [
            {"code": code, "can_grant": can_grant}
            for code, can_grant in sorted(permissions.items())
        ],
        "assignment_count": assignments,
    }


def list_users(session, *, actor_id, limit=50, offset=0, search=None):
    """Return a stable, bounded global identity directory without credential data."""
    _page(limit, offset)
    with transaction(session):
        _require_platform(session, actor_id)
        filters = []
        if search and (term := search.strip().lower()):
            filters.append(
                or_(
                    func.lower(User.display_name).contains(term),
                    User.normalized_email.contains(term),
                )
            )
        base = select(User).where(*filters)
        total = session.scalar(select(func.count()).select_from(base.subquery()))
        users = session.scalars(
            base.order_by(User.normalized_email, User.id).limit(limit).offset(offset)
        )
        return {
            "items": [
                {
                    "id": user.id,
                    "email": user.email,
                    "display_name": user.display_name,
                    "account_status": _account_status(user),
                    "created_at": user.created_at,
                }
                for user in users
            ],
            "total": total,
            "limit": limit,
            "offset": offset,
        }


def read_user(session, *, actor_id, user_id):
    with transaction(session):
        _require_platform(session, actor_id)
        user = session.get(User, user_id)
        if user is None:
            raise Inaccessible()
        membership_rows = session.execute(
            select(Membership, Organization)
            .join(Organization, Organization.id == Membership.organization_id)
            .where(Membership.user_id == user.id)
            .order_by(Organization.name, Organization.id, Membership.id)
        ).all()
        memberships = []
        for membership, organization in membership_rows:
            roles = list(
                session.scalars(
                    select(Role)
                    .join(
                        MembershipRole,
                        (MembershipRole.role_id == Role.id)
                        & (MembershipRole.organization_id == Role.organization_id),
                    )
                    .where(
                        MembershipRole.organization_id == membership.organization_id,
                        MembershipRole.membership_id == membership.id,
                    )
                    .order_by(Role.normalized_name, Role.id)
                )
            )
            active = _membership_status(membership, organization, user) == "active"
            memberships.append(
                {
                    "id": membership.id,
                    "organization_id": organization.id,
                    "organization_name": organization.name,
                    "organization_archived": organization.deleted_at is not None,
                    "state": _membership_status(membership, organization, user),
                    "is_owner": any(role.normalized_name == "organization owner" for role in roles),
                    "roles": [
                        {
                            "id": role.id,
                            "name": role.name,
                            "system_managed": _role_system_managed(role),
                        }
                        for role in roles
                    ],
                    "effective_permissions": (
                        sorted(
                            authorization_repository.effective_permissions(
                                session, organization.id, user.id
                            )
                        )
                        if active
                        else []
                    ),
                }
            )
        invitations = list(
            session.scalars(
                select(OrganizationInvitation)
                .where(OrganizationInvitation.normalized_email == user.normalized_email)
                .order_by(OrganizationInvitation.created_at.desc(), OrganizationInvitation.id)
            )
        )
        now = session.scalar(select(func.clock_timestamp()))
        return {
            "id": user.id,
            "email": user.email,
            "display_name": user.display_name,
            "account_status": _account_status(user),
            "activation_state": "activated"
            if session.get(PasswordCredential, user.id)
            else "pending",
            "created_at": user.created_at,
            "memberships": memberships,
            "invitations": [
                {
                    "id": invitation.id,
                    "organization_id": invitation.organization_id,
                    "kind": invitation.kind,
                    "status": (
                        "accepted"
                        if invitation.accepted_at is not None
                        else "revoked"
                        if invitation.revoked_at is not None
                        else "expired"
                        if invitation.expires_at <= now
                        else "pending"
                    ),
                    "created_at": invitation.created_at,
                    "expires_at": invitation.expires_at,
                    "accepted_at": invitation.accepted_at,
                    "revoked_at": invitation.revoked_at,
                    "delivery_status": "adapter_required",
                }
                for invitation in invitations
            ],
        }


def list_owner_onboarding(session, *, actor_id, limit=50, offset=0):
    _page(limit, offset)
    with transaction(session):
        _require_platform(session, actor_id)
        organizations = list(
            session.scalars(
                select(Organization)
                .order_by(Organization.name, Organization.id)
                .limit(limit)
                .offset(offset)
            )
        )
        total = session.scalar(select(func.count()).select_from(Organization))
        now = session.scalar(select(func.clock_timestamp()))
        items = []
        for organization in organizations:
            invitation = _owner_invitation(session, organization.id)
            owner_exists = (
                session.scalar(
                    select(Membership.id)
                    .join(
                        MembershipRole,
                        (MembershipRole.membership_id == Membership.id)
                        & (MembershipRole.organization_id == Membership.organization_id),
                    )
                    .join(
                        Role,
                        (Role.id == MembershipRole.role_id)
                        & (Role.organization_id == MembershipRole.organization_id),
                    )
                    .join(User, User.id == Membership.user_id)
                    .where(
                        Membership.organization_id == organization.id,
                        Membership.deleted_at.is_(None),
                        Membership.is_active.is_(True),
                        User.deleted_at.is_(None),
                        User.is_active.is_(True),
                        Role.deleted_at.is_(None),
                        Role.normalized_name == "organization owner",
                    )
                    .limit(1)
                )
                is not None
            )
            status = "unrecorded"
            if invitation is not None:
                status = (
                    "accepted"
                    if invitation.accepted_at is not None
                    else "revoked"
                    if invitation.revoked_at is not None
                    else "expired"
                    if invitation.expires_at <= now
                    else "pending"
                )
            items.append(
                {
                    "organization_id": organization.id,
                    "organization_name": organization.name,
                    "organization_archived": organization.deleted_at is not None,
                    "has_active_owner": owner_exists,
                    "invitation_id": invitation.id if invitation else None,
                    "owner_name": invitation.intended_display_name if invitation else None,
                    "owner_email": invitation.normalized_email if invitation else None,
                    "invitation_status": status,
                    "expires_at": invitation.expires_at if invitation else None,
                    "delivery_status": "adapter_required" if invitation else None,
                }
            )
        return {"items": items, "total": total, "limit": limit, "offset": offset}


def list_platform_roles(session, *, actor_id, limit=50, offset=0, organization_id=None):
    _page(limit, offset)
    with transaction(session):
        _require_platform(session, actor_id)
        filters = [Role.organization_id == organization_id] if organization_id else []
        base = select(Role, Organization).join(Organization).where(*filters)
        total = session.scalar(select(func.count()).select_from(base.subquery()))
        rows = session.execute(
            base.order_by(Organization.name, Role.normalized_name, Role.id)
            .limit(limit)
            .offset(offset)
        )
        return {
            "items": [
                _platform_role_info(session, role, organization) for role, organization in rows
            ],
            "total": total,
            "limit": limit,
            "offset": offset,
        }


def list_platform_permissions(session, *, actor_id):
    with transaction(session):
        _require_platform(session, actor_id)
        definitions = session.scalars(
            select(PermissionDefinition).order_by(
                PermissionDefinition.module, PermissionDefinition.code
            )
        )
        return [
            {
                "code": definition.code,
                "module": definition.module,
                "description": definition.description,
                "lifecycle": definition.lifecycle,
                "organization_assignable": definition.organization_assignable,
            }
            for definition in definitions
        ]


def archive_platform_membership(session, *, actor_id, organization_id, membership_id):
    with transaction(session):
        _require_platform(session, actor_id)
        organization = _organization(session, organization_id, lock=True)
        row = session.execute(
            select(Membership, User)
            .join(User, User.id == Membership.user_id)
            .where(Membership.organization_id == organization.id, Membership.id == membership_id)
            .with_for_update()
        ).first()
        if row is None:
            raise Inaccessible()
        membership, user = row
        if membership.deleted_at is not None:
            return {"membership_id": membership.id, "state": "archived"}
        assignments = list(
            session.scalars(
                select(MembershipRole).where(
                    MembershipRole.organization_id == organization.id,
                    MembershipRole.membership_id == membership.id,
                )
            )
        )
        owner_role_ids = list(
            session.scalars(
                select(Role.id).where(
                    Role.organization_id == organization.id,
                    Role.normalized_name == "organization owner",
                )
            )
        )
        removes_owner = any(assignment.role_id in owner_role_ids for assignment in assignments)
        if removes_owner:
            another_owner = session.scalar(
                select(Membership.id)
                .join(
                    MembershipRole,
                    (MembershipRole.membership_id == Membership.id)
                    & (MembershipRole.organization_id == Membership.organization_id),
                )
                .join(User, User.id == Membership.user_id)
                .where(
                    Membership.organization_id == organization.id,
                    Membership.id != membership.id,
                    Membership.deleted_at.is_(None),
                    Membership.is_active.is_(True),
                    User.deleted_at.is_(None),
                    User.is_active.is_(True),
                    MembershipRole.role_id.in_(owner_role_ids),
                )
                .limit(1)
            )
            if another_owner is None:
                raise LastAdministrator()
        for assignment in assignments:
            permissions = authorization_repository.role_permission_grants(
                session, organization.id, assignment.role_id
            )
            session.delete(assignment)
            authorization_repository.audit(
                session,
                organization.id,
                actor_id,
                "assignment.removed",
                assignment.role_id,
                permissions,
                {},
                membership.id,
            )
        membership.deleted_at = datetime.now(UTC)
        membership.updated_at = datetime.now(UTC)
        session.flush()
        from editingtab_core.authorization.services import ensure_administrator

        ensure_administrator(session, organization.id)
        authorization_repository.member_audit(
            session, organization.id, actor_id, "member.archived", membership.id, user.id
        )
        _audit(
            session,
            actor_id=actor_id,
            organization_id=organization.id,
            action="membership.archived",
            target_id=membership.id,
            before={"state": "active" if membership.is_active else "inactive"},
            after={"state": "archived"},
        )
        return {"membership_id": membership.id, "state": "archived"}


def restore_platform_membership(session, *, actor_id, organization_id, membership_id):
    with transaction(session):
        _require_platform(session, actor_id)
        organization = _organization(session, organization_id, lock=True)
        membership = session.scalar(
            select(Membership)
            .join(User, User.id == Membership.user_id)
            .where(
                Membership.organization_id == organization.id,
                Membership.id == membership_id,
                User.deleted_at.is_(None),
                User.is_active.is_(True),
            )
            .with_for_update()
        )
        if membership is None:
            raise Inaccessible()
        if membership.deleted_at is not None:
            if (
                session.scalar(
                    select(MembershipRole.role_id)
                    .where(
                        MembershipRole.organization_id == organization.id,
                        MembershipRole.membership_id == membership.id,
                    )
                    .limit(1)
                )
                is not None
            ):
                raise AccessError()
            membership.deleted_at = None
            membership.is_active = True
            membership.updated_at = datetime.now(UTC)
            authorization_repository.member_audit(
                session,
                organization.id,
                actor_id,
                "member.restored",
                membership.id,
                membership.user_id,
            )
            _audit(
                session,
                actor_id=actor_id,
                organization_id=organization.id,
                action="membership.restored",
                target_id=membership.id,
                before={"state": "archived"},
                after={"state": "active", "roles_restored": False},
            )
        return {"membership_id": membership.id, "state": "active"}


def setup_status(session):
    """Expose only whether the one-time setup operation remains eligible."""
    with transaction(session):
        state = session.get(BootstrapState, 1)
        if state is None:
            raise SetupUnavailable()
        any_grant = session.scalar(select(PlatformAdminGrant.id).limit(1))
        required = not any((state.completed_at, state.administrator_user_id, any_grant))
        return {"setup_required": required}


def _consume_setup_attempt(session, *, settings: Settings, source: str):
    """Persist setup throttles independently so rejected attempts still count."""
    if session.in_transaction():
        raise SetupUnavailable()
    try:
        with session.begin():
            auth_repository.purge_expired_throttles(session)
            allowed = auth_repository.consume_bucket(
                session,
                kind="w",
                value=source,
                limit=settings.setup_source_limit,
                window=settings.setup_window_seconds,
            )
    except SQLAlchemyError:
        raise SetupUnavailable() from None
    if not allowed:
        raise SetupThrottled("Try again later.")


def _require_setup_token(settings: Settings, supplied_token: str):
    configured = settings.setup_token_digest
    if configured is None:
        raise SetupUnavailable()
    supplied_digest = token_digest(supplied_token)
    # Always perform one fixed-length comparison, including malformed input.
    candidate = supplied_digest if supplied_digest is not None else "0" * 64
    if not secrets.compare_digest(candidate, configured.get_secret_value()):
        raise SetupAuthenticationFailed()


def web_setup_initial(
    session,
    *,
    settings: Settings,
    passwords: Passwords,
    email: str,
    password: str,
    password_confirmation: str,
    setup_token: str,
    source: str,
):
    """Authenticate and perform strict one-time browser setup."""
    _consume_setup_attempt(session, settings=settings, source=source)
    _require_setup_token(settings, setup_token)
    if password != password_confirmation:
        raise InvalidSetup()
    try:
        validate_password(password)
    except ValueError:
        raise InvalidSetup() from None
    _bootstrap_initial(
        session,
        passwords=passwords,
        email=email,
        password=password,
        display_name="The Editing Tab Platform Administrator",
        strict=True,
        allow_existing_user=False,
        action="operator.web_setup",
    )
    return {"initialized": True}


def bootstrap_initial(session, *, passwords: Passwords, password: str, display_name: str):
    """Create the legacy designated administrator once without changing repeat credentials."""
    return _bootstrap_initial(
        session,
        passwords=passwords,
        email=PLATFORM_ADMIN_EMAIL,
        password=password,
        display_name=display_name,
        strict=False,
        allow_existing_user=True,
        action="operator.bootstrap",
    )


def _bootstrap_initial(
    session,
    *,
    passwords: Passwords,
    email: str,
    password: str,
    display_name: str,
    strict: bool,
    allow_existing_user: bool,
    action: str,
):
    """Create one administrator and close setup in the same locked transaction."""
    try:
        display_email, normalized = normalize_email(email)
    except InvalidIdentity:
        raise InvalidSetup() from None
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
                not strict
                and existing_user is not None
                and existing_user.is_active
                and existing_user.deleted_at is None
                and existing_grant is not None
                and existing_grant.revoked_at is None
                and state.administrator_user_id in {None, existing_user.id}
            ):
                return existing_grant.id
            raise BootstrapClosed()
        if any_grant is not None or state.administrator_user_id is not None:
            raise BootstrapClosed()
        if existing_user is not None and not allow_existing_user:
            raise BootstrapClosed()
        if existing_user is not None and (
            not existing_user.is_active or existing_user.deleted_at is not None
        ):
            if allow_existing_user:
                raise InvalidOnboarding()
            raise InvalidSetup()
        if existing_user is None:
            validate_password(password)
            try:
                name = clean_name(display_name)
            except InvalidIdentity:
                raise InvalidSetup() from None
            existing_user = User(
                email=display_email,
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
        state.administrator_user_id = existing_user.id
        _audit(
            session,
            actor_id=None,
            organization_id=None,
            action=action,
            target_id=grant.id,
            before={},
            after={"user_id": str(existing_user.id), "active": True},
        )
        return grant.id


def recover_platform_admin(session, *, passwords: Passwords, password: str):
    """Explicit operator recovery; never used by startup or tenant-facing HTTP."""
    validate_password(password)
    with transaction(session):
        state = session.scalar(
            select(BootstrapState)
            .where(BootstrapState.id == 1)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        if state is None or state.completed_at is None:
            raise BootstrapClosed()
        if state.administrator_user_id is not None:
            user = session.get(
                User,
                state.administrator_user_id,
                with_for_update=True,
                populate_existing=True,
            )
        else:
            # Backward-compatible fallback for an inconsistent pre-0016 installation.
            _, normalized = normalize_email(PLATFORM_ADMIN_EMAIL)
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


def _organization_any_state(session, organization_id, *, lock=False):
    query = select(Organization).where(Organization.id == organization_id)
    if lock:
        query = query.with_for_update()
    org = session.scalar(query.execution_options(populate_existing=True))
    if org is None:
        raise Inaccessible()
    return org


def _info(org):
    return {
        "id": org.id,
        "name": org.name,
        "slug": org.slug,
        "archived_at": org.deleted_at,
    }


def _owner_invitation(session, organization_id):
    return session.scalar(
        select(OrganizationInvitation)
        .where(
            OrganizationInvitation.organization_id == organization_id,
            OrganizationInvitation.kind == "organization_owner",
        )
        .order_by(OrganizationInvitation.created_at.desc(), OrganizationInvitation.id.desc())
        .limit(1)
    )


def _owner_info(session, organization_id):
    invitation = _owner_invitation(session, organization_id)
    if invitation is None:
        return None
    now = session.scalar(select(func.clock_timestamp()))
    if invitation.accepted_at is not None:
        status = "active"
    elif invitation.revoked_at is not None:
        status = "revoked"
    elif invitation.expires_at <= now:
        status = "expired"
    else:
        status = "pending"
    return {
        "invitation_id": invitation.id,
        "full_name": invitation.intended_display_name,
        "email": invitation.normalized_email,
        "status": status,
        "created_at": invitation.created_at,
        "expires_at": invitation.expires_at,
        "accepted_at": invitation.accepted_at,
        "revoked_at": invitation.revoked_at,
        "delivery_status": "adapter_required",
    }


def _detail(session, org):
    return {
        **_info(org),
        "enabled_modules": _enabled(session, org.id),
        "owner": _owner_info(session, org.id),
    }


def list_organizations(
    session, *, actor_id, limit=50, offset=0, search=None, include_archived=False
):
    with transaction(session):
        _require_platform(session, actor_id)
        if not 1 <= limit <= 100 or not 0 <= offset <= 100000:
            raise InvalidOnboarding()
        query = select(Organization)
        if not include_archived:
            query = query.where(Organization.deleted_at.is_(None))
        if search:
            term = f"%{search.strip()}%"
            query = query.where(Organization.name.ilike(term) | Organization.slug.ilike(term))
        return [
            _info(org)
            for org in session.scalars(
                query.order_by(Organization.name, Organization.id).limit(limit).offset(offset)
            )
        ]


def read_organization(session, *, actor_id, organization_id):
    with transaction(session):
        _require_platform(session, actor_id)
        org = _organization_any_state(session, organization_id)
        return _detail(session, org)


def _issue_owner_invitation(session, *, settings, org, actor_id, owner_name, owner_email, role_ids):
    role_ids = tuple(role_ids)
    token = secrets.token_urlsafe(32)
    now = session.scalar(select(func.clock_timestamp()))
    invitation = OrganizationInvitation(
        organization_id=org.id,
        normalized_email=owner_email,
        inviter_id=actor_id,
        token_digest=token_digest(token),
        created_at=now,
        expires_at=now + timedelta(seconds=settings.auth_invitation_seconds),
        kind="organization_owner",
        intended_display_name=owner_name,
    )
    session.add(invitation)
    session.flush()
    session.add_all(
        InvitationRole(
            organization_id=org.id,
            invitation_id=invitation.id,
            role_id=role_id,
        )
        for role_id in role_ids
    )
    auth_repository.audit(
        session,
        action="invitation.created",
        actor_id=actor_id,
        organization_id=org.id,
        target_id=invitation.id,
        details={
            "purpose": "organization_owner",
            "role_ids": [str(role_id) for role_id in role_ids],
        },
    )
    return invitation, token


def onboard(
    session,
    *,
    actor_id,
    name,
    slug,
    owner_email,
    enabled_modules=(),
    owner_name=None,
    settings=None,
):
    try:
        with transaction(session):
            _require_platform(session, actor_id)
            try:
                name, slug = clean_name(name), normalize_slug(slug)
                if owner_name is not None:
                    owner_name = clean_name(owner_name)
                _, normalized = normalize_email(owner_email)
            except InvalidIdentity:
                raise InvalidOnboarding() from None
            modules = frozenset(enabled_modules)
            for code in modules:
                _module(code, True)
            if session.scalar(select(Organization.id).where(Organization.slug == slug)) is not None:
                raise Conflict()
            existing_user = session.scalar(
                select(User).where(User.normalized_email == normalized).with_for_update()
            )
            if existing_user is not None and existing_user.deleted_at is not None:
                raise InvalidOnboarding()
            if owner_name is None:
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
                if "booking" in modules:
                    from editingtab_core.platform.booking_permissions import (
                        assign_booking_administrator_role,
                    )

                    membership_id = session.scalar(
                        select(Membership.id).where(
                            Membership.organization_id == org.id,
                            Membership.user_id == owner_id,
                        )
                    )
                    if membership_id is None:
                        raise StorageUnavailable()
                    assign_booking_administrator_role(
                        session,
                        actor_id=actor_id,
                        organization_id=org.id,
                        membership_id=membership_id,
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
            if settings is None:
                raise InvalidOnboarding()
            org = identity_repository.create_organization(session, name=name, slug=slug)
            role = Role(
                organization_id=org.id,
                name="Organization owner",
                normalized_name="organization owner",
            )
            session.add(role)
            session.flush()
            permissions = dict.fromkeys(OWNER_PERMISSIONS, True)
            authorization_repository.replace_permissions(session, org.id, role.id, permissions)
            authorization_repository.audit(
                session, org.id, actor_id, "role.bootstrapped", role.id, {}, permissions
            )
            invitation_role_ids = [role.id]
            for code in sorted(modules):
                session.add(
                    ModuleEntitlement(organization_id=org.id, module_code=code, enabled=True)
                )
            if "booking" in modules:
                from editingtab_core.platform.booking_permissions import (
                    ensure_booking_administrator_role,
                )

                booking_role, _, _, _ = ensure_booking_administrator_role(
                    session,
                    actor_id=actor_id,
                    organization_id=org.id,
                )
                invitation_role_ids.append(booking_role.id)
            invitation, token = _issue_owner_invitation(
                session,
                settings=settings,
                org=org,
                actor_id=actor_id,
                owner_name=owner_name,
                owner_email=normalized,
                role_ids=invitation_role_ids,
            )
            _audit(
                session,
                actor_id=actor_id,
                organization_id=org.id,
                action="organization.onboarded",
                target_id=org.id,
                before={},
                after={
                    "owner_email": normalized,
                    "owner_invitation_id": str(invitation.id),
                    "enabled_modules": sorted(modules),
                },
            )
            return _detail(session, org), token
    except Conflict:
        raise OrganizationConflict() from None


def resend_owner_invitation(session, *, settings, actor_id, organization_id):
    with transaction(session):
        _require_platform(session, actor_id)
        org = _organization(session, organization_id, lock=True)
        previous = _owner_invitation(session, organization_id)
        if previous is None or previous.accepted_at is not None:
            raise Conflict()
        previous.revoked_at = session.scalar(select(func.clock_timestamp()))
        role_ids = list(
            session.scalars(
                select(InvitationRole.role_id)
                .where(InvitationRole.invitation_id == previous.id)
                .order_by(InvitationRole.role_id)
            )
        )
        if not role_ids:
            raise StorageUnavailable()
        auth_repository.audit(
            session,
            action="invitation.revoked",
            actor_id=actor_id,
            organization_id=organization_id,
            target_id=previous.id,
            details={"reason": "reissued"},
        )
        invitation, token = _issue_owner_invitation(
            session,
            settings=settings,
            org=org,
            actor_id=actor_id,
            owner_name=previous.intended_display_name,
            owner_email=previous.normalized_email,
            role_ids=role_ids,
        )
        _audit(
            session,
            actor_id=actor_id,
            organization_id=organization_id,
            action="owner.invitation.reissued",
            target_id=invitation.id,
            before={"invitation_id": str(previous.id)},
            after={"invitation_id": str(invitation.id)},
        )
        return _owner_info(session, organization_id), token


def revoke_owner_invitation(session, *, actor_id, organization_id, invitation_id):
    with transaction(session):
        _require_platform(session, actor_id)
        _organization(session, organization_id, lock=True)
        invitation = session.scalar(
            select(OrganizationInvitation)
            .where(
                OrganizationInvitation.id == invitation_id,
                OrganizationInvitation.organization_id == organization_id,
                OrganizationInvitation.kind == "organization_owner",
            )
            .with_for_update()
        )
        if invitation is None:
            raise Inaccessible()
        if invitation.accepted_at is not None:
            raise Conflict()
        if invitation.revoked_at is None:
            invitation.revoked_at = session.scalar(select(func.clock_timestamp()))
            auth_repository.audit(
                session,
                action="invitation.revoked",
                actor_id=actor_id,
                organization_id=organization_id,
                target_id=invitation.id,
                details={"reason": "platform_administrator"},
            )
            _audit(
                session,
                actor_id=actor_id,
                organization_id=organization_id,
                action="owner.invitation.revoked",
                target_id=invitation.id,
                before={"status": "pending"},
                after={"status": "revoked"},
            )


def archive_organization(session, *, actor_id, organization_id):
    with transaction(session):
        _require_platform(session, actor_id)
        org = _organization_any_state(session, organization_id, lock=True)
        if org.deleted_at is None:
            org.deleted_at = session.scalar(select(func.clock_timestamp()))
            session.execute(
                update(OrganizationInvitation)
                .where(
                    OrganizationInvitation.organization_id == organization_id,
                    OrganizationInvitation.accepted_at.is_(None),
                    OrganizationInvitation.revoked_at.is_(None),
                )
                .values(revoked_at=func.clock_timestamp())
            )
            _audit(
                session,
                actor_id=actor_id,
                organization_id=organization_id,
                action="organization.archived",
                target_id=organization_id,
                before={"archived": False},
                after={"archived": True},
            )
        return _detail(session, org)


def restore_organization(session, *, actor_id, organization_id):
    with transaction(session):
        _require_platform(session, actor_id)
        org = _organization_any_state(session, organization_id, lock=True)
        if org.deleted_at is not None:
            org.deleted_at = None
            _audit(
                session,
                actor_id=actor_id,
                organization_id=organization_id,
                action="organization.restored",
                target_id=organization_id,
                before={"archived": True},
                after={"archived": False},
            )
        return _detail(session, org)


def list_audit(session, *, actor_id, organization_id, limit=100, offset=0):
    with transaction(session):
        _require_platform(session, actor_id)
        _organization_any_state(session, organization_id)
        if not 1 <= limit <= 100 or not 0 <= offset <= 100000:
            raise InvalidOnboarding()
        rows = session.scalars(
            select(PlatformAudit)
            .where(PlatformAudit.organization_id == organization_id)
            .order_by(PlatformAudit.created_at.desc(), PlatformAudit.id.desc())
            .limit(limit)
            .offset(offset)
        )
        return [
            {
                "id": row.id,
                "action": row.action,
                "actor_id": row.actor_id,
                "target_id": row.target_id,
                "created_at": row.created_at,
                "before": row.before,
                "after": row.after,
            }
            for row in rows
        ]


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
