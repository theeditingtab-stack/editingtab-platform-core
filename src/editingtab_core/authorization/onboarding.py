"""Trusted owner construction inside a caller-owned transaction.

Internal only: callers must establish operator/platform authority or explicit local
bootstrap policy first. This is not an authorization bypass on tenant services.
"""

from editingtab_core.authorization import repository as repo
from editingtab_core.authorization.models import MembershipRole, Role
from editingtab_core.authorization.policy import OWNER_PERMISSIONS
from editingtab_core.identity import repository as identity


def _create_owned_organization(session, *, name, slug, owner_id, actor_id):
    org = identity.create_organization(session, name=name, slug=slug)
    member = identity.create_membership(session, organization_id=org.id, user_id=owner_id)
    role = Role(
        organization_id=org.id, name="Organization owner", normalized_name="organization owner"
    )
    session.add(role)
    session.flush()
    permissions = dict.fromkeys(OWNER_PERMISSIONS, True)
    repo.replace_permissions(session, org.id, role.id, permissions)
    session.add(MembershipRole(organization_id=org.id, membership_id=member.id, role_id=role.id))
    repo.audit(session, org.id, actor_id, "role.bootstrapped", role.id, {}, permissions)
    repo.audit(session, org.id, actor_id, "assignment.added", role.id, {}, permissions, member.id)
    return org
