"""Cookie endpoints and fail-closed Origin protection for the same-origin demo."""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Request, Response
from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator, model_validator
from sqlalchemy.orm import Session
from starlette.responses import JSONResponse

from editingtab_core.auth import services
from editingtab_core.auth.security import COOKIE_NAME
from editingtab_core.database import get_session
from editingtab_core.identity.errors import InvalidIdentity
from editingtab_core.identity.normalization import clean_name, normalize_email

router = APIRouter(prefix="/auth")
invitation_router = APIRouter(prefix="/organizations")


class LoginInput(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)
    email: str = Field(max_length=254)
    password: SecretStr = Field(repr=False, exclude=True)


@router.post("/login", status_code=204)
def login(body: LoginInput, request: Request, session: Annotated[Session, Depends(get_session)]):
    settings = request.app.state.settings
    token = services.login(
        session,
        settings=settings,
        passwords=request.app.state.passwords,
        email=body.email,
        password=body.password.get_secret_value(),
        source=request.client.host if request.client else "unknown",
    )
    response = Response(status_code=204)
    response.set_cookie(
        COOKIE_NAME,
        token,
        max_age=settings.auth_session_seconds,
        secure=settings.auth_secure_cookie,
        httponly=True,
        samesite="lax",
        path="/",
    )
    return response


@router.get("/me")
def me(request: Request, session: Annotated[Session, Depends(get_session)]) -> services.Profile:
    return services.current_user(session, request.cookies.get(COOKIE_NAME))


@router.post("/logout", status_code=204)
def logout(request: Request, session: Annotated[Session, Depends(get_session)]):
    services.logout(session, request.cookies.get(COOKIE_NAME))
    response = Response(status_code=204)
    response.delete_cookie(
        COOKIE_NAME,
        path="/",
        secure=request.app.state.settings.auth_secure_cookie,
        httponly=True,
        samesite="lax",
    )
    return response


class InvitationInput(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)
    email: str = Field(max_length=254)
    role_ids: list[UUID] = Field(default_factory=list, max_length=100)

    @field_validator("email")
    @classmethod
    def supported_email(cls, value):
        try:
            normalize_email(value)
        except InvalidIdentity:
            raise ValueError("unsupported email") from None
        return value

    @model_validator(mode="after")
    def unique_roles(self):
        if len(self.role_ids) != len(set(self.role_ids)):
            raise ValueError("duplicate role id")
        return self


def actor(request: Request, session: Annotated[Session, Depends(get_session)]) -> UUID:
    return services.current_user(session, request.cookies.get(COOKIE_NAME)).id


@invitation_router.post("/{organization_id}/invitations", status_code=201)
def create_invitation(
    organization_id: UUID,
    body: InvitationInput,
    request: Request,
    session: Annotated[Session, Depends(get_session)],
    actor_id: Annotated[UUID, Depends(actor)],
):
    return services.create_invitation(
        session,
        settings=request.app.state.settings,
        organization_id=organization_id,
        actor_id=actor_id,
        email=body.email,
        role_ids=body.role_ids,
    )


@invitation_router.get("/{organization_id}/invitations")
def invitations(
    organization_id: UUID,
    session: Annotated[Session, Depends(get_session)],
    actor_id: Annotated[UUID, Depends(actor)],
):
    return services.list_invitations(session, organization_id=organization_id, actor_id=actor_id)


@invitation_router.delete("/{organization_id}/invitations/{invitation_id}", status_code=204)
def revoke_invitation(
    organization_id: UUID,
    invitation_id: UUID,
    session: Annotated[Session, Depends(get_session)],
    actor_id: Annotated[UUID, Depends(actor)],
):
    services.revoke_invitation(
        session,
        organization_id=organization_id,
        actor_id=actor_id,
        invitation_id=invitation_id,
    )
    return Response(status_code=204)


class InvitationAcceptanceInput(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)
    token: SecretStr = Field(max_length=256, repr=False, exclude=True)
    email: str = Field(max_length=254)
    display_name: str | None = Field(default=None, max_length=200)
    password: SecretStr | None = Field(
        default=None, min_length=15, max_length=1024, repr=False, exclude=True
    )

    @field_validator("email")
    @classmethod
    def supported_email(cls, value):
        try:
            normalize_email(value)
        except InvalidIdentity:
            raise ValueError("unsupported email") from None
        return value

    @field_validator("display_name")
    @classmethod
    def supported_name(cls, value):
        if value is not None:
            try:
                clean_name(value)
            except InvalidIdentity:
                raise ValueError("unsupported display name") from None
        return value


@router.post("/invitations/accept")
def accept_invitation(
    body: InvitationAcceptanceInput,
    request: Request,
    session: Annotated[Session, Depends(get_session)],
):
    return services.accept_invitation(
        session,
        passwords=request.app.state.passwords,
        token=body.token.get_secret_value(),
        email=body.email,
        display_name=body.display_name,
        password=body.password.get_secret_value() if body.password else None,
    )


class PasswordChangeInput(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)
    current_password: SecretStr = Field(min_length=15, max_length=1024, repr=False, exclude=True)
    new_password: SecretStr = Field(min_length=15, max_length=1024, repr=False, exclude=True)


@router.post("/password/change", status_code=204)
def change_password(
    body: PasswordChangeInput,
    request: Request,
    session: Annotated[Session, Depends(get_session)],
):
    services.change_password(
        session,
        passwords=request.app.state.passwords,
        token=request.cookies.get(COOKIE_NAME),
        current_password=body.current_password.get_secret_value(),
        new_password=body.new_password.get_secret_value(),
    )
    return Response(status_code=204)


class PasswordResetRequestInput(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)
    email: str = Field(max_length=254)


@router.post("/password/reset/request", status_code=202)
def request_password_reset(
    body: PasswordResetRequestInput,
    request: Request,
    session: Annotated[Session, Depends(get_session)],
):
    token = services.request_password_reset(
        session,
        settings=request.app.state.settings,
        email=body.email,
        source=request.client.host if request.client else "unknown",
    )
    result: dict[str, object] = {"accepted": True}
    if token is not None:
        result["development_token"] = token
    return result


class PasswordResetConfirmInput(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)
    token: SecretStr = Field(max_length=256, repr=False, exclude=True)
    new_password: SecretStr = Field(min_length=15, max_length=1024, repr=False, exclude=True)


@router.post("/password/reset/confirm", status_code=204)
def confirm_password_reset(
    body: PasswordResetConfirmInput,
    request: Request,
    session: Annotated[Session, Depends(get_session)],
):
    services.reset_password(
        session,
        passwords=request.app.state.passwords,
        token=body.token.get_secret_value(),
        password=body.new_password.get_secret_value(),
    )
    return Response(status_code=204)


@router.get("/sessions")
def sessions(request: Request, session: Annotated[Session, Depends(get_session)]):
    return services.list_sessions(session, request.cookies.get(COOKIE_NAME))


@router.post("/sessions/revoke-all", status_code=204)
def revoke_all_sessions(request: Request, session: Annotated[Session, Depends(get_session)]):
    services.revoke_all_sessions(session, request.cookies.get(COOKIE_NAME))
    response = Response(status_code=204)
    response.delete_cookie(
        COOKIE_NAME,
        path="/",
        secure=request.app.state.settings.auth_secure_cookie,
        httponly=True,
        samesite="lax",
    )
    return response


@router.delete("/sessions/{session_id}", status_code=204)
def revoke_session(
    session_id: UUID,
    request: Request,
    session: Annotated[Session, Depends(get_session)],
):
    current = services.revoke_selected_session(
        session, request.cookies.get(COOKIE_NAME), session_id
    )
    response = Response(status_code=204)
    if current:
        response.delete_cookie(
            COOKIE_NAME,
            path="/",
            secure=request.app.state.settings.auth_secure_cookie,
            httponly=True,
            samesite="lax",
        )
    return response


class AuthRequestGuard:
    """Reject missing/duplicate origins and oversized auth bodies before JSON parsing."""

    def __init__(self, app, origins):
        self.app = app
        self.origins = frozenset(origins)

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or not (
            scope["path"].startswith("/auth/")
            or scope["path"] == "/platform"
            or scope["path"].startswith("/platform/")
            or scope["path"] == "/organizations"
            or scope["path"].startswith("/organizations/")
        ):
            return await self.app(scope, receive, send)

        async def no_cache(message):
            if message["type"] == "http.response.start":
                message["headers"] = list(message["headers"]) + [(b"cache-control", b"no-store")]
            await send(message)

        if scope["method"] not in {"GET", "HEAD", "OPTIONS"}:
            origins = [v.decode("latin-1") for k, v in scope["headers"] if k.lower() == b"origin"]
            if len(origins) != 1 or origins[0] not in self.origins:
                return await JSONResponse({"detail": "Origin not allowed."}, status_code=403)(
                    scope, receive, no_cache
                )
            body = bytearray()
            while True:
                message = await receive()
                if message["type"] == "http.disconnect":
                    return
                body.extend(message.get("body", b""))
                if len(body) > 16384:
                    return await JSONResponse({"detail": "Request too large."}, status_code=413)(
                        scope, receive, no_cache
                    )
                if not message.get("more_body", False):
                    break
            original_receive = receive
            delivered = False

            async def buffered_receive():
                nonlocal delivered
                if delivered:
                    return await original_receive()
                delivered = True
                return {"type": "http.request", "body": bytes(body), "more_body": False}

            receive = buffered_receive
        await self.app(scope, receive, no_cache)
