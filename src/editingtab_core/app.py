"""Application factory. Importing this module never connects to PostgreSQL."""

from contextlib import asynccontextmanager
from typing import Annotated

from fastapi import Depends, FastAPI
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker
from starlette.concurrency import run_in_threadpool

from editingtab_core.auth.http import AuthRequestGuard, router
from editingtab_core.auth.security import (
    AuthenticationError,
    AuthenticationUnavailable,
    LoginThrottled,
    Passwords,
)
from editingtab_core.authorization.http import router as organization_router
from editingtab_core.authorization.policy import AccessError
from editingtab_core.config import Settings, load_settings
from editingtab_core.database import build_engine, get_session
from editingtab_core.internal.booking import (
    PATH,
    AuthorizationFailure,
    BookingRequestGuard,
    failure,
)
from editingtab_core.internal.booking import router as internal_router
from editingtab_core.platform.http import router as platform_router
from editingtab_core.platform.http import tenant_router


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings if settings is not None else load_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        app.state.passwords = await run_in_threadpool(Passwords)
        engine = build_engine(settings)
        app.state.session_factory = sessionmaker(bind=engine, expire_on_commit=False)
        try:
            yield
        finally:
            await run_in_threadpool(engine.dispose)

    app = FastAPI(title=settings.service_name, debug=False, lifespan=lifespan)

    app.state.settings = settings
    app.add_middleware(AuthRequestGuard, origins=settings.auth_allowed_origins)
    app.include_router(router)
    app.include_router(organization_router)
    app.include_router(platform_router)
    app.include_router(tenant_router)
    app.include_router(internal_router)
    app.add_middleware(BookingRequestGuard, settings=settings)

    @app.exception_handler(AuthorizationFailure)
    async def internal_failure(request, error):
        return failure(error.status, error.code)

    @app.exception_handler(AccessError)
    async def organization_error(request, error):
        return JSONResponse(status_code=error.status, content={"detail": error.message})

    @app.exception_handler(AuthenticationError)
    async def authentication_error(request, error):
        return JSONResponse(status_code=401, content={"detail": "Authentication failed."})

    @app.exception_handler(AuthenticationUnavailable)
    async def authentication_unavailable(request, error):
        return JSONResponse(status_code=503, content={"detail": "Authentication unavailable."})

    @app.exception_handler(LoginThrottled)
    async def login_throttled(request, error):
        return JSONResponse(
            status_code=429,
            content={"detail": "Try again later."},
            headers={"Retry-After": str(settings.auth_window_seconds)},
        )

    @app.exception_handler(RequestValidationError)
    async def invalid_request(request, error):
        if request.url.path == PATH:
            return failure(422, "invalid_authorization_request")
        # Never serialize input/errors: validation can contain submitted passwords.
        return JSONResponse(status_code=422, content={"detail": "Invalid request."})

    @app.get("/health/live")
    def live() -> dict[str, str]:
        return {"status": "alive"}

    @app.get("/health/ready", response_model=None)
    def ready(session: Annotated[Session, Depends(get_session)]) -> dict[str, str] | JSONResponse:
        try:
            session.execute(text("SELECT 1")).scalar_one()
        except SQLAlchemyError:
            # Never log the driver exception: it may contain connection details.
            return JSONResponse(status_code=503, content={"status": "unavailable"})
        return {"status": "ready"}

    return app
