from types import SimpleNamespace
from uuid import uuid4

import pytest
from pydantic import ValidationError

from editingtab_core.auth.http import InvitationOutput
from editingtab_core.authorization.http import PermissionGrantInput, RoleInput
from editingtab_core.authorization.services import _system_managed


def test_system_role_classification_uses_existing_role_identities():
    assert _system_managed(
        SimpleNamespace(normalized_name="organization owner", provisioning_kind=None)
    )
    assert _system_managed(
        SimpleNamespace(
            normalized_name="booking administrator", provisioning_kind="booking_inventory"
        )
    )
    assert not _system_managed(SimpleNamespace(normalized_name="custom", provisioning_kind=None))


def test_admin_inputs_are_strict_and_reject_ambiguous_permissions():
    with pytest.raises(ValidationError):
        RoleInput.model_validate(
            {
                "name": "Duplicate",
                "permissions": [
                    {"code": "core.organization.read", "can_grant": False},
                    {"code": "core.organization.read", "can_grant": True},
                ],
            }
        )
    with pytest.raises(ValidationError):
        PermissionGrantInput.model_validate({"can_grant": 1})


def test_invitation_response_schema_rejects_secret_tokens():
    with pytest.raises(ValidationError):
        InvitationOutput.model_validate(
            {
                "id": uuid4(),
                "email": "employee@example.test",
                "created_at": "2026-01-01T00:00:00Z",
                "expires_at": "2026-01-02T00:00:00Z",
                "role_ids": [],
                "token": "must-not-serialize",
            }
        )
