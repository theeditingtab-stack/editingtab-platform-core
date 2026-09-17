"""Cookie endpoints and fail-closed Origin protection for the same-origin demo."""

from typing import Annotated

from fastapi import APIRouter, Depends, Request, Response
from pydantic import BaseModel, ConfigDict, Field, SecretStr
from sqlalchemy.orm import Session
from starlette.responses import JSONResponse

from editingtab_core.auth import services
from editingtab_core.auth.security import COOKIE_NAME
from editingtab_core.database import get_session

router = APIRouter(prefix="/auth")


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
