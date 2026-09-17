"""Tests discard CORE_ environment values and never load the developer's .env."""

import os

import pytest

from editingtab_core.config import Settings


def pytest_addoption(parser):
    parser.addoption("--integration", action="store_true", help="Enable isolated PostgreSQL tests")


def pytest_configure(config):
    # Snapshot only explicitly named test configuration, before fixture isolation.
    config.core_test_environment = {
        name: value for name, value in os.environ.items() if name.startswith("CORE_TEST_")
    }


def pytest_collection_modifyitems(config, items):
    if not config.getoption("--integration"):
        for item in items:
            if item.get_closest_marker("integration") is not None:
                item.add_marker(
                    pytest.mark.skip(reason="Use --integration and explicit CORE_TEST_ settings")
                )


@pytest.fixture(autouse=True)
def isolated_environment(monkeypatch, tmp_path):
    for name in list(os.environ):
        if name.startswith("CORE_"):
            monkeypatch.delenv(name)
    monkeypatch.chdir(tmp_path)


@pytest.fixture
def settings():
    return Settings(
        _env_file=None,
        environment="test",
        db_name="editingtab_core_test",
        db_username="editingtab_test",
        db_password="unit-only-P@ss:/%#'secret",
        db_port=15433,
    )
