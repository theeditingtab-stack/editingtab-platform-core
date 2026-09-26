"""Booking-only authentication and fresh authorization; no outgoing requests."""

import hashlib
import hmac
import ipaddress
import re
from uuid import UUID

from fastapi import APIRouter, Request
from pydantic import BaseModel, ConfigDict
from starlette.responses import JSONResponse

from editingtab_core.auth import repository as auth_repo
from editingtab_core.auth.security import token_digest
from editingtab_core.authorization.http import Database
from editingtab_core.authorization.policy import (
    BOOKING_PERMISSIONS,
    AccessError,
    Inaccessible,
    StorageUnavailable,
)
from editingtab_core.authorization.services import authorization_context, transaction
from editingtab_core.platform.services import require_entitlement

PATH = "/internal/v1/booking/authorize"
router = APIRouter()


class AuthorizationFailure(Exception):
    def __init__(self, status, code):
        self.status = status
        self.code = code


def failure(status, code):
    return JSONResponse(
        status_code=status, content={"error": code}, headers={"Cache-Control": "no-store"}
    )


def valid_service(settings, header):
    if not isinstance(header, str) or len(header) > 140:
        return False
    scheme, separator, secret = header.partition(" ")
    if (
        scheme.lower() != "bearer"
        or not separator
        or re.fullmatch(r"[A-Za-z0-9_-]{43,128}", secret) is None
    ):
        return False
    digest = hashlib.sha256(secret.encode("ascii")).hexdigest()
    # Compare both slots without a short-circuit. Previous alone never enables access.
    current = settings.booking_service_current_digest
    previous = settings.booking_service_previous_digest
    current_match = hmac.compare_digest(digest, current.get_secret_value() if current else "0" * 64)
    previous_match = hmac.compare_digest(
        digest, previous.get_secret_value() if previous else "0" * 64
    )
    return current is not None and (current_match | (previous is not None and previous_match))


def trusted_transport(scope, settings):
    if scope.get("scheme") == "https":
        return True
    if settings.auth_secure_cookie or scope.get("scheme") != "http":
        return False
    try:
        return ipaddress.ip_address(scope["client"][0]).is_loopback
    except (KeyError, TypeError, ValueError):
        return False


class BookingRequestGuard:
    """Exact endpoint only. Authenticate service BEFORE body parsing or any DB query."""

    def __init__(self, app, settings):
        self.app, self.settings = app, settings

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope["path"] != PATH:
            return await self.app(scope, receive, send)

        async def no_store(message):
            if message["type"] == "http.response.start":
                message["headers"] = [
                    (k, v) for k, v in message["headers"] if k.lower() != b"cache-control"
                ] + [(b"cache-control", b"no-store")]
            await send(message)

        headers = [
            v.decode("latin-1") for k, v in scope["headers"] if k.lower() == b"authorization"
        ]
        if (
            not trusted_transport(scope, self.settings)
            or len(headers) != 1
            or not valid_service(self.settings, headers[0])
        ):
            return await failure(401, "invalid_service_credentials")(scope, receive, no_store)
        tokens = [
            v.decode("latin-1") for k, v in scope["headers"] if k.lower() == b"x-core-session"
        ]
        if len(tokens) != 1 or token_digest(tokens[0]) is None:
            return await failure(401, "invalid_user_session")(scope, receive, no_store)
        if scope["method"] != "POST":
            return await failure(422, "invalid_authorization_request")(scope, receive, no_store)
        body = bytearray()
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            body.extend(message.get("body", b""))
            if len(body) > 4096:
                return await failure(422, "invalid_authorization_request")(scope, receive, no_store)
            if not message.get("more_body", False):
                break
        delivered = False
        original_receive = receive

        async def buffered_receive():
            nonlocal delivered
            if not delivered:
                delivered = True
                return {"type": "http.request", "body": bytes(body), "more_body": False}
            return await original_receive()

        return await self.app(scope, buffered_receive, no_store)


class AuthorizationInput(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)
    organization_id: UUID
    permission: str


def authorize_booking(session, *, token, organization_id, permission):
    if permission not in BOOKING_PERMISSIONS:
        raise AuthorizationFailure(422, "invalid_authorization_request")
    digest = token_digest(token)
    if digest is None:
        raise AuthorizationFailure(401, "invalid_user_session")
    try:
        with transaction(session):
            user = auth_repo.authenticated_user(session, digest)
            if user is None:
                raise AuthorizationFailure(401, "invalid_user_session")
            try:
                _, membership, _ = authorization_context(
                    session, organization_id, user.id, permission
                )
            except Inaccessible:
                raise AuthorizationFailure(404, "organization_not_accessible") from None
            except AccessError:
                raise AuthorizationFailure(403, "permission_denied") from None
            try:
                require_entitlement(session, organization_id=organization_id, module_code="booking")
            except Inaccessible:
                raise AuthorizationFailure(404, "organization_not_accessible") from None
            except AccessError:
                raise AuthorizationFailure(403, "module_disabled") from None
            return {
                "allowed": True,
                "user_id": user.id,
                "membership_id": membership.id,
                "organization_id": organization_id,
                "permission": permission,
            }
    except StorageUnavailable:
        raise AuthorizationFailure(503, "authorization_unavailable") from None


@router.post(PATH)
def booking_authorize(body: AuthorizationInput, request: Request, session: Database):
    return authorize_booking(
        session,
        token=request.headers.get("x-core-session"),
        organization_id=body.organization_id,
        permission=body.permission,
    )
