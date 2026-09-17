"""Safety checks run as unit tests, without the integration marker."""

import pytest
from conftest import explicit_test_settings


def valid_values():
    return {
        "CORE_TEST_DB_HOST": "127.0.0.1",
        "CORE_TEST_DB_PORT": "15433",
        "CORE_TEST_DB_NAME": "editingtab_core_test",
        "CORE_TEST_DB_USERNAME": "editingtab_test",
        "CORE_TEST_DB_PASSWORD": "public-test-only",
    }


def test_missing_configuration_never_defaults():
    with pytest.raises(ValueError, match="every explicit"):
        explicit_test_settings({})


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("CORE_TEST_DB_NAME", "editingtab_core"),
        ("CORE_TEST_DB_USERNAME", "editingtab_dev"),
        ("CORE_TEST_DB_HOST", "production.example.com"),
        ("CORE_TEST_DB_PORT", "15432"),
    ],
)
def test_refuses_unsafe_database(field, value):
    values = valid_values()
    values[field] = value
    with pytest.raises(ValueError, match="non-isolated"):
        explicit_test_settings(values)
