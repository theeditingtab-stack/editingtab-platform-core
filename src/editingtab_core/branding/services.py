"""Current-state authorization and transactional organization branding operations."""

import re
from datetime import UTC, datetime

from sqlalchemy import select

from editingtab_core.authorization import repository as authorization_repository
from editingtab_core.authorization.policy import (
    BRANDING_MANAGE,
    AccessError,
    Inaccessible,
    InvalidPermission,
    StorageUnavailable,
)
from editingtab_core.authorization.services import authorize, transaction
from editingtab_core.branding.models import (
    OrganizationBrandAsset,
    OrganizationBranding,
    OrganizationBrandingAudit,
)
from editingtab_core.branding.storage import InvalidLogo, LocalBrandingStorage, validate_logo
from editingtab_core.identity.errors import InvalidIdentity
from editingtab_core.identity.models import Organization, User
from editingtab_core.identity.normalization import clean_name
from editingtab_core.platform.services import _require_platform

DEFAULT_PRIMARY_COLOR = "#183C2B"
DEFAULT_ACCENT_COLOR = "#D4A853"


class InvalidBranding(InvalidPermission):
    message = "Invalid organization branding."


class StaleBranding(AccessError):
    status = 409
    code = "stale_branding"
    message = "Organization branding changed; reload before saving."


class BrandingUnavailable(StorageUnavailable):
    message = "Organization branding unavailable."


def normalize_color(value: str) -> str:
    if not isinstance(value, str) or re.fullmatch(r"#[0-9A-F]{6}", value) is None:
        raise InvalidBranding()
    return value


def _branding(session, organization_id, *, lock=False) -> OrganizationBranding:
    query = select(OrganizationBranding).where(
        OrganizationBranding.organization_id == organization_id
    )
    if lock:
        query = query.with_for_update()
    row = session.scalar(query.execution_options(populate_existing=True))
    if row is None:
        row = OrganizationBranding(organization_id=organization_id)
        session.add(row)
        session.flush()
    return row


def _active_tenant_organization(session, organization_id, actor_id, *, lock=False):
    query = (
        authorization_repository.active_members(organization_id)
        .where(User.id == actor_id)
        .with_only_columns(Organization)
    )
    if lock:
        query = query.with_for_update(of=Organization)
    organization = session.scalar(query.execution_options(populate_existing=True))
    if organization is None:
        raise Inaccessible()
    return organization


def _asset(session, organization_id, asset_id):
    if asset_id is None:
        return None
    return session.scalar(
        select(OrganizationBrandAsset).where(
            OrganizationBrandAsset.organization_id == organization_id,
            OrganizationBrandAsset.id == asset_id,
            OrganizationBrandAsset.retired_at.is_(None),
        )
    )


def _state(organization, branding, asset):
    return {
        "organization_id": organization.id,
        "name": organization.name,
        "slug": organization.slug,
        "primary_color": branding.primary_color,
        "accent_color": branding.accent_color,
        "version": branding.version,
        "created_at": branding.created_at,
        "updated_at": branding.updated_at,
        "logo": (
            None
            if asset is None
            else {
                "asset_id": asset.id,
                "media_type": asset.media_type,
                "byte_size": asset.byte_size,
                "width": asset.width,
                "height": asset.height,
            }
        ),
    }


def _audit(session, organization_id, actor_id, action, before, after):
    session.add(
        OrganizationBrandingAudit(
            organization_id=organization_id,
            actor_id=actor_id,
            action=action,
            before=before,
            after=after,
        )
    )
    session.flush()


def _audit_state(organization, branding):
    return {
        "name": organization.name,
        "primary_color": branding.primary_color,
        "accent_color": branding.accent_color,
        "logo_asset_id": str(branding.logo_asset_id) if branding.logo_asset_id else None,
        "version": branding.version,
    }


def read_tenant(session, *, organization_id, actor_id):
    # Workspace branding is baseline active-membership context. This intentionally
    # grants no mutation or permission-management authority to ordinary staff.
    with transaction(session):
        organization = _active_tenant_organization(session, organization_id, actor_id)
        branding = _branding(session, organization_id)
        return _state(
            organization, branding, _asset(session, organization_id, branding.logo_asset_id)
        )


def read_platform(session, *, organization_id, actor_id):
    with transaction(session):
        _require_platform(session, actor_id)
        organization = session.get(Organization, organization_id)
        if organization is None:
            raise Inaccessible()
        branding = _branding(session, organization_id)
        return _state(
            organization, branding, _asset(session, organization_id, branding.logo_asset_id)
        )


def update_tenant(session, *, organization_id, actor_id, version, **changes):
    return _update(
        session,
        organization_id=organization_id,
        actor_id=actor_id,
        version=version,
        platform=False,
        changes=changes,
    )


def update_platform(session, *, organization_id, actor_id, version, **changes):
    return _update(
        session,
        organization_id=organization_id,
        actor_id=actor_id,
        version=version,
        platform=True,
        changes=changes,
    )


def _update(session, *, organization_id, actor_id, version, platform, changes):
    try:
        name = clean_name(changes["name"]) if changes.get("name") is not None else None
    except InvalidIdentity:
        raise InvalidBranding() from None
    primary = (
        normalize_color(changes["primary_color"])
        if changes.get("primary_color") is not None
        else None
    )
    accent = (
        normalize_color(changes["accent_color"])
        if changes.get("accent_color") is not None
        else None
    )
    with transaction(session):
        if platform:
            _require_platform(session, actor_id)
            organization = session.scalar(
                select(Organization)
                .where(Organization.id == organization_id)
                .with_for_update()
                .execution_options(populate_existing=True)
            )
            if organization is None:
                raise Inaccessible()
        else:
            organization, _ = authorize(
                session, organization_id, actor_id, BRANDING_MANAGE, lock=True
            )
        branding = _branding(session, organization_id, lock=True)
        if branding.version != version:
            raise StaleBranding()
        before = _audit_state(organization, branding)
        changed = False
        for target, attribute, value in (
            (organization, "name", name),
            (branding, "primary_color", primary),
            (branding, "accent_color", accent),
        ):
            if value is None:
                continue
            if getattr(target, attribute) != value:
                setattr(target, attribute, value)
                changed = True
        if changed:
            branding.version += 1
            branding.updated_at = datetime.now(UTC)
            session.flush()
            _audit(
                session,
                organization_id,
                actor_id,
                "branding.updated",
                before,
                _audit_state(organization, branding),
            )
        return _state(
            organization, branding, _asset(session, organization_id, branding.logo_asset_id)
        )


def replace_logo(
    session,
    storage: LocalBrandingStorage,
    *,
    organization_id,
    actor_id,
    version,
    content,
    media_type,
    platform=False,
):
    try:
        logo = validate_logo(content, media_type)
    except InvalidLogo:
        raise InvalidBranding() from None
    # Reject unauthorized uploads before performing filesystem I/O. Authorization
    # is repeated under the branding row lock below to close the race window.
    with transaction(session):
        if platform:
            _require_platform(session, actor_id)
            if session.get(Organization, organization_id) is None:
                raise Inaccessible()
        else:
            authorize(session, organization_id, actor_id, BRANDING_MANAGE)
    try:
        stored = storage.save(organization_id=organization_id, logo=logo)
    except (InvalidLogo, OSError):
        raise BrandingUnavailable() from None
    old_key = None
    try:
        with transaction(session):
            if platform:
                _require_platform(session, actor_id)
                organization = session.scalar(
                    select(Organization)
                    .where(Organization.id == organization_id)
                    .with_for_update()
                    .execution_options(populate_existing=True)
                )
                if organization is None:
                    raise Inaccessible()
            else:
                organization, _ = authorize(
                    session, organization_id, actor_id, BRANDING_MANAGE, lock=True
                )
            branding = _branding(session, organization_id, lock=True)
            if branding.version != version:
                raise StaleBranding()
            before = _audit_state(organization, branding)
            old = _asset(session, organization_id, branding.logo_asset_id)
            asset = OrganizationBrandAsset(
                organization_id=organization_id,
                storage_key=stored.key,
                media_type=logo.media_type,
                byte_size=len(logo.content),
                width=logo.width,
                height=logo.height,
                content_sha256=logo.content_sha256,
                created_by=actor_id,
            )
            session.add(asset)
            session.flush()
            branding.logo_asset_id = asset.id
            branding.version += 1
            branding.updated_at = datetime.now(UTC)
            if old is not None:
                old.retired_at = datetime.now(UTC)
                old_key = old.storage_key
            session.flush()
            _audit(
                session,
                organization_id,
                actor_id,
                "branding.logo.replaced" if old else "branding.logo.added",
                before,
                _audit_state(organization, branding),
            )
            result = _state(organization, branding, asset)
    except Exception:
        storage.delete(stored.key)
        raise
    if old_key:
        storage.delete(old_key)
    return result


def delete_logo(
    session,
    storage: LocalBrandingStorage,
    *,
    organization_id,
    actor_id,
    version,
    platform=False,
):
    old_key = None
    with transaction(session):
        if platform:
            _require_platform(session, actor_id)
            organization = session.scalar(
                select(Organization)
                .where(Organization.id == organization_id)
                .with_for_update()
                .execution_options(populate_existing=True)
            )
            if organization is None:
                raise Inaccessible()
        else:
            organization, _ = authorize(
                session, organization_id, actor_id, BRANDING_MANAGE, lock=True
            )
        branding = _branding(session, organization_id, lock=True)
        if branding.version != version:
            raise StaleBranding()
        before = _audit_state(organization, branding)
        old = _asset(session, organization_id, branding.logo_asset_id)
        if old is not None:
            old_key = old.storage_key
            old.retired_at = datetime.now(UTC)
            branding.logo_asset_id = None
            branding.version += 1
            branding.updated_at = datetime.now(UTC)
            session.flush()
            _audit(
                session,
                organization_id,
                actor_id,
                "branding.logo.deleted",
                before,
                _audit_state(organization, branding),
            )
        result = _state(organization, branding, None)
    if old_key:
        storage.delete(old_key)
    return result


def read_logo_tenant(session, *, organization_id, actor_id):
    with transaction(session):
        _active_tenant_organization(session, organization_id, actor_id)
        branding = _branding(session, organization_id)
        asset = _asset(session, organization_id, branding.logo_asset_id)
        if asset is None:
            raise Inaccessible()
        return asset.storage_key, asset.media_type, asset.content_sha256


def read_logo_platform(session, *, organization_id, actor_id):
    with transaction(session):
        _require_platform(session, actor_id)
        if session.get(Organization, organization_id) is None:
            raise Inaccessible()
        branding = _branding(session, organization_id)
        asset = _asset(session, organization_id, branding.logo_asset_id)
        if asset is None:
            raise Inaccessible()
        return asset.storage_key, asset.media_type, asset.content_sha256
