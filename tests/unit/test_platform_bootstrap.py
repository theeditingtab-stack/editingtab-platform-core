"""CLI guard tests do not touch any database or developer configuration."""

from unittest.mock import MagicMock

import pytest

from editingtab_core.platform import bootstrap


@pytest.mark.parametrize("interactive,confirmation", [(False, None), (True, "no")])
def test_operator_cli_requires_interactive_exact_confirmation(
    monkeypatch, interactive, confirmation
):
    monkeypatch.setattr("sys.argv", ["bootstrap", "--email", "operator@example.test"])
    monkeypatch.setattr("sys.stdin.isatty", lambda: interactive)
    monkeypatch.setattr(bootstrap, "load_settings", lambda: object())
    monkeypatch.setattr("builtins.input", lambda _: confirmation)
    engine = MagicMock()
    monkeypatch.setattr(bootstrap, "build_engine", engine)
    assert bootstrap.main() == 1
    engine.assert_not_called()


def test_cli_delegates_only_after_confirmation_and_does_not_claim_target_as_actor(monkeypatch):
    monkeypatch.setattr("sys.argv", ["bootstrap", "--email", "operator@example.test"])
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda _: bootstrap.CONFIRMATION)
    monkeypatch.setattr(bootstrap, "load_settings", lambda: object())
    engine = MagicMock()
    monkeypatch.setattr(bootstrap, "build_engine", lambda _: engine)
    session_context = MagicMock()
    monkeypatch.setattr(bootstrap, "Session", lambda *args, **kwargs: session_context)
    grant = MagicMock()
    monkeypatch.setattr(bootstrap, "bootstrap_initial", grant)
    assert bootstrap.main() == 0
    grant.assert_called_once_with(
        session_context.__enter__.return_value, email="operator@example.test"
    )
    engine.dispose.assert_called_once()
