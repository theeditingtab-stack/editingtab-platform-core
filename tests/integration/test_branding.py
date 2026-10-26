from contextlib import contextmanager
from io import BytesIO
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from PIL import Image
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker

from editingtab_core.app import create_app
from editingtab_core.auth.provision import provision_user
from editingtab_core.auth.security import Passwords
from editingtab_core.authorization import services as authorization
from editingtab_core.authorization.bootstrap import bootstrap
from editingtab_core.authorization.models import PermissionDefinition, Role
from editingtab_core.authorization.policy import (
    BRANDING_MANAGE,
    BRANDING_READ,
    COMPANY_ADMINISTRATOR_PERMISSIONS,
)
from editingtab_core.branding.models import (
    OrganizationBrandAsset,
    OrganizationBranding,
    OrganizationBrandingAudit,
)
from editingtab_core.identity import services as identity
from editingtab_core.identity.models import Organization
from editingtab_core.platform.models import ModuleEntitlement, PlatformAdminGrant

pytestmark = pytest.mark.integration
ORIGIN = "http://127.0.0.1:18080"
PASSWORD = "synthetic branding test password"


def png(color=(20, 80, 40)):
    output = BytesIO()
    Image.new("RGB", (48, 32), color=color).save(output, format="PNG")
    return output.getvalue()


@pytest.fixture
def branding_env(identity_session, integration_settings):
    passwords = Passwords()
    users = {}
    for name in ("owner", "other-owner", "admin", "staff", "booking", "platform"):
        users[name] = provision_user(
            identity_session,
            settings=integration_settings,
            passwords=passwords,
            email=f"{name}@example.test",
            display_name=name.title(),
            password=PASSWORD,
        )
    organization = bootstrap(
        identity_session,
        settings=integration_settings,
        email="owner@example.test",
        slug="brand-a",
        name="Brand A",
    )
    other_organization = bootstrap(
        identity_session,
        settings=integration_settings,
        email="other-owner@example.test",
        slug="brand-b",
        name="Brand B",
    )
    memberships = {
        name: identity.add_membership(
            identity_session, organization_id=organization, user_id=users[name]
        )
        for name in ("admin", "staff", "booking")
    }
    with identity_session.begin():
        identity_session.add(
            ModuleEntitlement(organization_id=organization, module_code="booking", enabled=True)
        )
        identity_session.add(PlatformAdminGrant(user_id=users["platform"]))

    admin_role = authorization.create_role(
        identity_session,
        organization_id=organization,
        actor_id=users["owner"],
        name="Brand administrator",
        permissions={
            **dict.fromkeys(COMPANY_ADMINISTRATOR_PERMISSIONS, False),
            BRANDING_READ: False,
            BRANDING_MANAGE: False,
        },
    )["id"]
    authorization.change_assignment(
        identity_session,
        organization_id=organization,
        actor_id=users["owner"],
        membership_id=memberships["admin"],
        role_id=admin_role,
    )
    booking_role = authorization.create_role(
        identity_session,
        organization_id=organization,
        actor_id=users["owner"],
        name="Booking-only administrator",
        permissions={"booking.settings.read": False, "booking.settings.manage": False},
    )["id"]
    authorization.change_assignment(
        identity_session,
        organization_id=organization,
        actor_id=users["owner"],
        membership_id=memberships["booking"],
        role_id=booking_role,
    )
    return SimpleNamespace(
        users=users,
        organization=organization,
        other_organization=other_organization,
        memberships=memberships,
        admin_role=admin_role,
        booking_role=booking_role,
    )


@pytest.fixture
def clients(migration_connection, integration_settings, tmp_path):
    @contextmanager
    def make(email):
        settings = integration_settings.model_copy(
            update={
                "auth_allowed_origins": (ORIGIN,),
                "branding_storage_path": tmp_path / "branding",
            }
        )
        app = create_app(settings)
        with TestClient(app, base_url=ORIGIN) as client:
            app.state.session_factory = sessionmaker(
                bind=migration_connection,
                join_transaction_mode="create_savepoint",
                expire_on_commit=False,
            )
            assert (
                client.post(
                    "/auth/login",
                    json={"email": email, "password": PASSWORD},
                    headers={"Origin": ORIGIN},
                ).status_code
                == 204
            )
            yield client

    return make


def test_permission_registry_owner_grants_and_explicit_administrator_assignment(
    identity_session, branding_env
):
    with identity_session.begin():
        definitions = set(
            identity_session.scalars(
                select(PermissionDefinition.code).where(
                    PermissionDefinition.code.in_([BRANDING_READ, BRANDING_MANAGE])
                )
            )
        )
        owner_role = identity_session.scalar(
            select(Role).where(
                Role.organization_id == branding_env.organization,
                Role.normalized_name == "organization owner",
            )
        )
        booking_role = identity_session.get(Role, branding_env.booking_role)
        assert definitions == {BRANDING_READ, BRANDING_MANAGE}
        owner_permissions = authorization.repo.role_permission_grants(
            identity_session, branding_env.organization, owner_role.id
        )
        assert owner_permissions[BRANDING_READ] is True
        assert owner_permissions[BRANDING_MANAGE] is True
        assert BRANDING_MANAGE not in authorization.repo.role_permissions(
            identity_session, branding_env.organization, booking_role.id
        )


def test_tenant_branding_isolation_roles_rename_colors_stale_write_and_audit(
    clients, identity_session, branding_env
):
    path = f"/organizations/{branding_env.organization}/branding"
    other_path = f"/organizations/{branding_env.other_organization}/branding"

    with clients("staff@example.test") as staff:
        read = staff.get(path)
        assert read.status_code == 200
        assert read.json()["name"] == "Brand A"
        assert staff.get(other_path).status_code == 404
        assert (
            staff.patch(
                path,
                headers={"Origin": ORIGIN, "If-Match": '"1"'},
                json={"name": "Not allowed"},
            ).status_code
            == 403
        )

    with clients("booking@example.test") as booking:
        assert (
            booking.patch(
                path,
                headers={"Origin": ORIGIN, "If-Match": '"1"'},
                json={"primary_color": "#112233"},
            ).status_code
            == 403
        )

    with clients("admin@example.test") as admin:
        updated = admin.patch(
            path,
            headers={"Origin": ORIGIN, "If-Match": '"1"'},
            json={
                "name": "Renamed Company",
                "primary_color": "#112233",
                "accent_color": "#AABBCC",
            },
        )
        assert updated.status_code == 200
        assert updated.headers["etag"] == '"2"'
        assert updated.json()["slug"] == "brand-a"
        assert updated.json()["name"] == "Renamed Company"
        stale = admin.patch(
            path,
            headers={"Origin": ORIGIN, "If-Match": '"1"'},
            json={"name": "Stale rename"},
        )
        assert stale.status_code == 409
        assert stale.json()["code"] == "stale_branding"
        assert (
            admin.patch(
                path,
                headers={"Origin": ORIGIN, "If-Match": '"2"'},
                json={"primary_color": "#aabbcc"},
            ).status_code
            == 422
        )

    with identity_session.begin():
        organization = identity_session.get(Organization, branding_env.organization)
        audit = identity_session.scalars(
            select(OrganizationBrandingAudit).where(
                OrganizationBrandingAudit.organization_id == branding_env.organization
            )
        ).all()
        assert organization.name == "Renamed Company"
        assert organization.slug == "brand-a"
        assert len(audit) == 1
        assert audit[0].actor_id == branding_env.users["admin"]
        assert audit[0].action == "branding.updated"


def test_platform_administrator_must_use_platform_route(clients, branding_env):
    tenant_path = f"/organizations/{branding_env.organization}/branding"
    platform_path = f"/platform/organizations/{branding_env.organization}/branding"
    with clients("platform@example.test") as client:
        assert client.get(tenant_path).status_code == 404
        read = client.get(platform_path)
        assert read.status_code == 200
        updated = client.patch(
            platform_path,
            headers={"Origin": ORIGIN, "If-Match": read.headers["etag"]},
            json={"accent_color": "#334455"},
        )
        assert updated.status_code == 200
        assert updated.json()["accent_color"] == "#334455"


def test_logo_validation_replacement_deletion_and_private_paths(
    clients, identity_session, branding_env, tmp_path
):
    path = f"/organizations/{branding_env.organization}/branding"
    logo_path = f"{path}/logo"
    with clients("owner@example.test") as owner:
        invalid = owner.put(
            logo_path,
            content=b"<svg/>",
            headers={
                "Origin": ORIGIN,
                "If-Match": '"1"',
                "Content-Type": "image/svg+xml",
            },
        )
        assert invalid.status_code == 422

        first = owner.put(
            logo_path,
            content=png(),
            headers={
                "Origin": ORIGIN,
                "If-Match": '"1"',
                "Content-Type": "image/png",
            },
        )
        assert first.status_code == 200
        assert first.json()["version"] == 2
        assert "storage" not in first.text.lower()
        first_asset = first.json()["logo"]["asset_id"]
        downloaded = owner.get(logo_path)
        assert downloaded.status_code == 200
        assert downloaded.content == png()
        assert downloaded.headers["x-content-type-options"] == "nosniff"

        replacement = owner.put(
            logo_path,
            content=png((90, 20, 120)),
            headers={
                "Origin": ORIGIN,
                "If-Match": '"2"',
                "Content-Type": "image/png",
            },
        )
        assert replacement.status_code == 200
        assert replacement.json()["logo"]["asset_id"] != first_asset
        deleted = owner.delete(
            logo_path,
            headers={"Origin": ORIGIN, "If-Match": '"3"'},
        )
        assert deleted.status_code == 200
        assert deleted.json()["logo"] is None
        assert owner.get(logo_path).status_code == 404

    with identity_session.begin():
        assets = identity_session.scalars(
            select(OrganizationBrandAsset).where(
                OrganizationBrandAsset.organization_id == branding_env.organization
            )
        ).all()
        assert len(assets) == 2
        assert all(asset.retired_at is not None for asset in assets)
        assert all(str(tmp_path) not in asset.storage_key for asset in assets)
        actions = set(
            identity_session.scalars(
                select(OrganizationBrandingAudit.action).where(
                    OrganizationBrandingAudit.organization_id == branding_env.organization
                )
            )
        )
        assert actions == {
            "branding.logo.added",
            "branding.logo.replaced",
            "branding.logo.deleted",
        }


def test_database_rejects_cross_tenant_logo_reference(identity_session, branding_env):
    with pytest.raises(IntegrityError):
        with identity_session.begin():
            asset = OrganizationBrandAsset(
                organization_id=branding_env.organization,
                storage_key="test/cross-tenant.png",
                media_type="image/png",
                byte_size=8,
                width=1,
                height=1,
                content_sha256="a" * 64,
                created_by=branding_env.users["owner"],
            )
            identity_session.add(asset)
            identity_session.flush()
            other_branding = identity_session.get(
                OrganizationBranding, branding_env.other_organization
            )
            if other_branding is None:
                other_branding = OrganizationBranding(
                    organization_id=branding_env.other_organization
                )
                identity_session.add(other_branding)
                identity_session.flush()
            other_branding.logo_asset_id = asset.id
            identity_session.flush()
