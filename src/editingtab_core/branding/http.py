"""Tenant and explicit platform-super-administrator branding HTTP contracts."""

import re
from datetime import datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Body, Depends, Header, Request, Response
from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy.orm import Session

from editingtab_core.auth.security import COOKIE_NAME
from editingtab_core.auth.services import current_user
from editingtab_core.authorization.policy import Inaccessible
from editingtab_core.branding import services
from editingtab_core.branding.storage import MAX_LOGO_BYTES, InvalidLogo
from editingtab_core.database import get_session

tenant_router = APIRouter(prefix="/organizations")
platform_router = APIRouter(prefix="/platform/organizations")
Database = Annotated[Session, Depends(get_session)]


def actor(request: Request, session: Database) -> UUID:
    return current_user(session, request.cookies.get(COOKIE_NAME)).id


Actor = Annotated[UUID, Depends(actor)]


class LogoOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    asset_id: UUID
    media_type: str
    byte_size: int
    width: int
    height: int


class BrandingOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    organization_id: UUID
    name: str
    slug: str
    primary_color: str
    accent_color: str
    version: int
    created_at: datetime | None
    updated_at: datetime | None
    logo: LogoOutput | None


class BrandingUpdateInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str | None = Field(default=None, min_length=1, max_length=200)
    primary_color: str | None = Field(default=None, pattern=r"^#[0-9A-F]{6}$")
    accent_color: str | None = Field(default=None, pattern=r"^#[0-9A-F]{6}$")

    @model_validator(mode="after")
    def at_least_one_change(self):
        if self.name is None and self.primary_color is None and self.accent_color is None:
            raise ValueError("at least one branding field is required")
        return self


def expected_version(if_match: Annotated[str, Header(alias="If-Match")]) -> int:
    match = re.fullmatch(r'"([1-9][0-9]{0,9})"', if_match)
    if match is None:
        raise services.InvalidBranding()
    return int(match.group(1))


Version = Annotated[int, Depends(expected_version)]


def _etag(response: Response, version: int) -> None:
    response.headers["ETag"] = f'"{version}"'


@tenant_router.get("/{organization_id}/branding", response_model=BrandingOutput)
def get_tenant_branding(
    organization_id: UUID, response: Response, session: Database, actor_id: Actor
):
    result = services.read_tenant(session, organization_id=organization_id, actor_id=actor_id)
    _etag(response, result["version"])
    return result


@tenant_router.patch("/{organization_id}/branding", response_model=BrandingOutput)
def update_tenant_branding(
    organization_id: UUID,
    body: BrandingUpdateInput,
    response: Response,
    session: Database,
    actor_id: Actor,
    version: Version,
):
    result = services.update_tenant(
        session,
        organization_id=organization_id,
        actor_id=actor_id,
        version=version,
        **body.model_dump(exclude_none=True),
    )
    _etag(response, result["version"])
    return result


@tenant_router.put("/{organization_id}/branding/logo", response_model=BrandingOutput)
def put_tenant_logo(
    organization_id: UUID,
    request: Request,
    response: Response,
    session: Database,
    actor_id: Actor,
    version: Version,
    content: Annotated[bytes, Body(max_length=MAX_LOGO_BYTES)],
):
    result = services.replace_logo(
        session,
        request.app.state.branding_storage,
        organization_id=organization_id,
        actor_id=actor_id,
        version=version,
        content=content,
        media_type=request.headers.get("content-type", ""),
    )
    _etag(response, result["version"])
    return result


@tenant_router.get("/{organization_id}/branding/logo")
def get_tenant_logo(organization_id: UUID, request: Request, session: Database, actor_id: Actor):
    key, media_type, digest = services.read_logo_tenant(
        session, organization_id=organization_id, actor_id=actor_id
    )
    try:
        content = request.app.state.branding_storage.read(key)
    except (InvalidLogo, FileNotFoundError, OSError):
        raise Inaccessible() from None
    return Response(
        content=content,
        media_type=media_type,
        headers={
            "Cache-Control": "private, no-cache",
            "Content-Disposition": "inline",
            "ETag": f'"{digest}"',
            "X-Content-Type-Options": "nosniff",
        },
    )


@tenant_router.delete("/{organization_id}/branding/logo", response_model=BrandingOutput)
def delete_tenant_logo(
    organization_id: UUID,
    request: Request,
    response: Response,
    session: Database,
    actor_id: Actor,
    version: Version,
):
    result = services.delete_logo(
        session,
        request.app.state.branding_storage,
        organization_id=organization_id,
        actor_id=actor_id,
        version=version,
    )
    _etag(response, result["version"])
    return result


@platform_router.get("/{organization_id}/branding", response_model=BrandingOutput)
def get_platform_branding(
    organization_id: UUID, response: Response, session: Database, actor_id: Actor
):
    result = services.read_platform(session, organization_id=organization_id, actor_id=actor_id)
    _etag(response, result["version"])
    return result


@platform_router.patch("/{organization_id}/branding", response_model=BrandingOutput)
def update_platform_branding(
    organization_id: UUID,
    body: BrandingUpdateInput,
    response: Response,
    session: Database,
    actor_id: Actor,
    version: Version,
):
    result = services.update_platform(
        session,
        organization_id=organization_id,
        actor_id=actor_id,
        version=version,
        **body.model_dump(exclude_none=True),
    )
    _etag(response, result["version"])
    return result


@platform_router.put("/{organization_id}/branding/logo", response_model=BrandingOutput)
def put_platform_logo(
    organization_id: UUID,
    request: Request,
    response: Response,
    session: Database,
    actor_id: Actor,
    version: Version,
    content: Annotated[bytes, Body(max_length=MAX_LOGO_BYTES)],
):
    result = services.replace_logo(
        session,
        request.app.state.branding_storage,
        organization_id=organization_id,
        actor_id=actor_id,
        version=version,
        content=content,
        media_type=request.headers.get("content-type", ""),
        platform=True,
    )
    _etag(response, result["version"])
    return result


@platform_router.get("/{organization_id}/branding/logo")
def get_platform_logo(organization_id: UUID, request: Request, session: Database, actor_id: Actor):
    key, media_type, digest = services.read_logo_platform(
        session, organization_id=organization_id, actor_id=actor_id
    )
    try:
        content = request.app.state.branding_storage.read(key)
    except (InvalidLogo, FileNotFoundError, OSError):
        raise Inaccessible() from None
    return Response(
        content=content,
        media_type=media_type,
        headers={
            "Cache-Control": "private, no-cache",
            "Content-Disposition": "inline",
            "ETag": f'"{digest}"',
            "X-Content-Type-Options": "nosniff",
        },
    )


@platform_router.delete("/{organization_id}/branding/logo", response_model=BrandingOutput)
def delete_platform_logo(
    organization_id: UUID,
    request: Request,
    response: Response,
    session: Database,
    actor_id: Actor,
    version: Version,
):
    result = services.delete_logo(
        session,
        request.app.state.branding_storage,
        organization_id=organization_id,
        actor_id=actor_id,
        version=version,
        platform=True,
    )
    _etag(response, result["version"])
    return result
