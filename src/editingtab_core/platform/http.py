"""Explicit platform routes; tenant module reads retain tenant authorization."""

from uuid import UUID

from fastapi import APIRouter
from pydantic import BaseModel, ConfigDict, Field, StrictBool

from editingtab_core.authorization.http import Actor, Database, Limit, Offset
from editingtab_core.platform import services

router = APIRouter(prefix="/platform")
tenant_router = APIRouter(prefix="/organizations")


class OnboardingInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=200)
    slug: str = Field(min_length=1, max_length=63)
    owner_email: str = Field(min_length=1, max_length=254)
    enabled_modules: list[str] = Field(default_factory=list, max_length=4)


class EntitlementInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: StrictBool


@router.get("/organizations")
def organizations(session: Database, actor_id: Actor, limit: Limit = 50, offset: Offset = 0):
    return services.list_organizations(session, actor_id=actor_id, limit=limit, offset=offset)


@router.post("/organizations", status_code=201)
def onboard(body: OnboardingInput, session: Database, actor_id: Actor):
    return services.onboard(session, actor_id=actor_id, **body.model_dump())


@router.get("/organizations/{organization_id}/modules")
def modules(organization_id: UUID, session: Database, actor_id: Actor):
    return services.read_entitlements(session, actor_id=actor_id, organization_id=organization_id)


@router.put("/organizations/{organization_id}/modules/{module_code}")
def update_module(
    organization_id: UUID,
    module_code: str,
    body: EntitlementInput,
    session: Database,
    actor_id: Actor,
):
    return services.set_entitlement(
        session,
        actor_id=actor_id,
        organization_id=organization_id,
        module_code=module_code,
        enabled=body.enabled,
    )


@tenant_router.get("/{organization_id}/modules")
def tenant_modules(organization_id: UUID, session: Database, actor_id: Actor):
    return services.tenant_entitlements(session, actor_id=actor_id, organization_id=organization_id)


class BookingProvisionInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    membership_id: UUID


@router.post("/organizations/{organization_id}/booking-inventory-administrator")
def booking_administrator(
    organization_id: UUID, body: BookingProvisionInput, session: Database, actor_id: Actor
):
    from editingtab_core.platform.booking_permissions import provision

    return provision(
        session,
        actor_id=actor_id,
        organization_id=organization_id,
        membership_id=body.membership_id,
    )
