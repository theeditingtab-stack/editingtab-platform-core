"""Application factory. Importing this module never connects to PostgreSQL."""

from contextlib import asynccontextmanager
from typing import Annotated

from fastapi import Depends, FastAPI
from fastapi.responses import JSONResponse
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker
from starlette.concurrency import run_in_threadpool

from editingtab_core.config import Settings, load_settings
from editingtab_core.database import build_engine, get_session


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings if settings is not None else load_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        engine = build_engine(settings)
        app.state.session_factory = sessionmaker(bind=engine, expire_on_commit=False)
        try:
            yield
        finally:
            await run_in_threadpool(engine.dispose)

    app = FastAPI(title=settings.service_name, debug=False, lifespan=lifespan)

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
