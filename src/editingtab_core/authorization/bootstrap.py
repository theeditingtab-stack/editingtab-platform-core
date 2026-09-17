"""Explicit local organization bootstrap; existing slugs are never reconfigured."""

import sys

from sqlalchemy import select
from sqlalchemy.orm import Session

from editingtab_core.auth.provision import SafeParser, require_local
from editingtab_core.authorization import repository as repo
from editingtab_core.authorization.models import MembershipRole, Role
from editingtab_core.authorization.policy import (
    OWNER_PERMISSIONS,
    AccessError,
    Conflict,
    Inaccessible,
)
from editingtab_core.authorization.services import transaction
from editingtab_core.config import load_settings
from editingtab_core.database import build_engine
from editingtab_core.identity import repository as identity
from editingtab_core.identity.errors import IdentityError
from editingtab_core.identity.models import Organization, User
from editingtab_core.identity.normalization import clean_name, normalize_email, normalize_slug


def bootstrap(session, *, settings, email, slug, name):
    require_local(settings)
    _, normalized = normalize_email(email)
    slug = normalize_slug(slug)
    name = clean_name(name)
    with transaction(session):
        # Unique slug is the final concurrency arbiter. Never repair/regrant on rerun.
        if session.scalar(select(Organization.id).where(Organization.slug == slug)) is not None:
            raise Conflict()
        user = session.scalar(
            select(User)
            .where(
                User.normalized_email == normalized,
                User.deleted_at.is_(None),
                User.is_active.is_(True),
            )
            .with_for_update()
        )
        if user is None:
            raise Inaccessible()
        org = identity.create_organization(session, name=name, slug=slug)
        member = identity.create_membership(session, organization_id=org.id, user_id=user.id)
        role = Role(
            organization_id=org.id, name="Organization owner", normalized_name="organization owner"
        )
        session.add(role)
        session.flush()
        repo.replace_permissions(session, org.id, role.id, OWNER_PERMISSIONS)
        session.add(
            MembershipRole(organization_id=org.id, membership_id=member.id, role_id=role.id)
        )
        repo.audit(session, org.id, user.id, "role.bootstrapped", role.id, [], OWNER_PERMISSIONS)
        repo.audit(
            session, org.id, user.id, "assignment.added", role.id, [], OWNER_PERMISSIONS, member.id
        )
        return org.id


def main():
    parser = SafeParser(
        description="Create one local demo organization for an existing active user."
    )
    parser.add_argument("--email", required=True)
    parser.add_argument("--slug", required=True)
    parser.add_argument("--name", required=True)
    args = parser.parse_args()
    engine = None
    try:
        settings = load_settings()
        require_local(settings)
        engine = build_engine(settings)
        with Session(engine, expire_on_commit=False) as session:
            bootstrap(session, settings=settings, email=args.email, slug=args.slug, name=args.name)
        print(
            "Demo organization created with its explicit owner role; no platform privilege granted."
        )
        return 0
    except Conflict:
        print(
            "Organization slug already reserved; "
            "inspect existing administration. Nothing regranted.",
            file=sys.stderr,
        )
        return 1
    except (ValueError, IdentityError, AccessError):
        print(
            "Bootstrap unavailable; check local mode, active user, configuration, and migrations.",
            file=sys.stderr,
        )
        return 1
    finally:
        if engine is not None:
            engine.dispose()


if __name__ == "__main__":
    raise SystemExit(main())
