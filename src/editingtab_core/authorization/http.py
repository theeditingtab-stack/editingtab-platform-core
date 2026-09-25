"""Small organization API backed by authenticated, authorized services."""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request, Response
from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy.orm import Session

from editingtab_core.auth.security import COOKIE_NAME
from editingtab_core.auth.services import current_user
from editingtab_core.authorization import services
from editingtab_core.database import get_session

router = APIRouter(prefix="/organizations")
Database = Annotated[Session, Depends(get_session)]
Limit = Annotated[int, Query(ge=1, le=100)]
Offset = Annotated[int, Query(ge=0, le=100000)]


def actor(request: Request, session: Database) -> UUID:
    return current_user(session, request.cookies.get(COOKIE_NAME)).id


Actor = Annotated[UUID, Depends(actor)]


class RolePermissionInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    code: str = Field(min_length=1, max_length=64)
    can_grant: bool


class RoleInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=100)
    permissions: list[RolePermissionInput] = Field(max_length=100)

    @model_validator(mode="after")
    def unique_permissions(self):
        codes = [permission.code for permission in self.permissions]
        if len(codes) != len(set(codes)):
            raise ValueError("duplicate permission code")
        return self


class MemberInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    user_id: UUID
    role_ids: list[UUID] = Field(default_factory=list, max_length=100)

    @model_validator(mode="after")
    def unique_roles(self):
        if len(self.role_ids) != len(set(self.role_ids)):
            raise ValueError("duplicate role id")
        return self


class MemberRestoreInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    role_ids: list[UUID] = Field(default_factory=list, max_length=100)

    @model_validator(mode="after")
    def unique_roles(self):
        if len(self.role_ids) != len(set(self.role_ids)):
            raise ValueError("duplicate role id")
        return self


@router.get("")
def organizations(session: Database, actor_id: Actor, limit: Limit = 50, offset: Offset = 0):
    return services.list_organizations(session, actor_id=actor_id, limit=limit, offset=offset)


@router.get("/{organization_id}")
def organization(organization_id: UUID, session: Database, actor_id: Actor):
    return services.read_organization(session, organization_id=organization_id, actor_id=actor_id)


@router.get("/{organization_id}/members")
def members(
    organization_id: UUID, session: Database, actor_id: Actor, limit: Limit = 50, offset: Offset = 0
):
    return services.list_members(
        session, organization_id=organization_id, actor_id=actor_id, limit=limit, offset=offset
    )


@router.get("/{organization_id}/members/{membership_id}")
def member(organization_id: UUID, membership_id: UUID, session: Database, actor_id: Actor):
    return services.read_member(
        session,
        organization_id=organization_id,
        actor_id=actor_id,
        membership_id=membership_id,
    )


@router.post("/{organization_id}/members")
def add_member(organization_id: UUID, body: MemberInput, session: Database, actor_id: Actor):
    return services.add_member(
        session,
        organization_id=organization_id,
        actor_id=actor_id,
        user_id=body.user_id,
        role_ids=body.role_ids,
    )


@router.delete("/{organization_id}/members/{membership_id}", status_code=204)
def archive_member(organization_id: UUID, membership_id: UUID, session: Database, actor_id: Actor):
    services.archive_member(
        session,
        organization_id=organization_id,
        actor_id=actor_id,
        membership_id=membership_id,
    )
    return Response(status_code=204)


@router.post("/{organization_id}/members/{membership_id}/restore")
def restore_member(
    organization_id: UUID,
    membership_id: UUID,
    body: MemberRestoreInput,
    session: Database,
    actor_id: Actor,
):
    return services.restore_member(
        session,
        organization_id=organization_id,
        actor_id=actor_id,
        membership_id=membership_id,
        role_ids=body.role_ids,
    )


@router.get("/{organization_id}/roles")
def roles(
    organization_id: UUID, session: Database, actor_id: Actor, limit: Limit = 50, offset: Offset = 0
):
    return services.list_roles(
        session, organization_id=organization_id, actor_id=actor_id, limit=limit, offset=offset
    )


@router.get("/{organization_id}/permissions")
def permissions(organization_id: UUID, session: Database, actor_id: Actor):
    return services.list_permission_catalog(
        session, organization_id=organization_id, actor_id=actor_id
    )


@router.post("/{organization_id}/roles", status_code=201)
def create_role(organization_id: UUID, body: RoleInput, session: Database, actor_id: Actor):
    return services.create_role(
        session,
        organization_id=organization_id,
        actor_id=actor_id,
        name=body.name,
        permissions={item.code: item.can_grant for item in body.permissions},
    )


@router.put("/{organization_id}/roles/{role_id}")
def update_role(
    organization_id: UUID, role_id: UUID, body: RoleInput, session: Database, actor_id: Actor
):
    return services.update_role(
        session,
        organization_id=organization_id,
        actor_id=actor_id,
        role_id=role_id,
        name=body.name,
        permissions={item.code: item.can_grant for item in body.permissions},
    )


@router.delete("/{organization_id}/roles/{role_id}", status_code=204)
def archive_role(organization_id: UUID, role_id: UUID, session: Database, actor_id: Actor):
    services.archive_role(
        session, organization_id=organization_id, actor_id=actor_id, role_id=role_id
    )
    return Response(status_code=204)


@router.put("/{organization_id}/members/{membership_id}/roles/{role_id}", status_code=204)
def assign(
    organization_id: UUID, membership_id: UUID, role_id: UUID, session: Database, actor_id: Actor
):
    services.change_assignment(
        session,
        organization_id=organization_id,
        actor_id=actor_id,
        membership_id=membership_id,
        role_id=role_id,
    )
    return Response(status_code=204)


@router.delete("/{organization_id}/members/{membership_id}/roles/{role_id}", status_code=204)
def unassign(
    organization_id: UUID, membership_id: UUID, role_id: UUID, session: Database, actor_id: Actor
):
    services.change_assignment(
        session,
        organization_id=organization_id,
        actor_id=actor_id,
        membership_id=membership_id,
        role_id=role_id,
        remove=True,
    )
    return Response(status_code=204)
