from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from editingtab_core.auth import diagnose
from editingtab_core.auth.security import Passwords


@pytest.mark.parametrize(
    "active,archived,correct",
    [(True, False, True), (True, False, False), (False, False, True), (True, True, True)],
)
def test_diagnostic_uses_real_verification_without_mutations(active, archived, correct):
    passwords = Passwords()
    synthetic = "synthetic diagnostic password"
    encoded = passwords.hash(synthetic)
    row = SimpleNamespace(is_active=active, archived=archived, password_hash=encoded)
    engine = MagicMock()
    connection = engine.connect.return_value.__enter__.return_value
    connection.execute.return_value.one_or_none.return_value = row
    result = diagnose.inspect_password(
        engine,
        email=" Demo@EXAMPLE.TEST ",
        password=synthetic if correct else "different synthetic password",
        passwords=passwords,
    )
    assert result == (active and not archived, correct)
    calls = connection.execute.call_args_list
    assert len(calls) == 2
    assert str(calls[0].args[0]) == "SET TRANSACTION READ ONLY"
    assert str(calls[1].args[0]).startswith("SELECT ")
    assert calls[1].args[1] == {"email": "demo@example.test"}
    connection.begin.return_value.rollback.assert_called_once()
    connection.begin.return_value.commit.assert_not_called()
    assert row.password_hash == encoded


def test_diagnostic_rejects_production_before_prompt(settings, monkeypatch, capsys):
    monkeypatch.setattr("sys.argv", ["diagnose", "--email", "demo@example.test"])
    monkeypatch.setattr(
        diagnose, "load_settings", lambda: settings.model_copy(update={"environment": "production"})
    )
    prompt = MagicMock()
    monkeypatch.setattr(diagnose.getpass, "getpass", prompt)
    assert diagnose.main() == 1
    prompt.assert_not_called()
    assert "Diagnostic unavailable" in capsys.readouterr().err


def test_diagnostic_outputs_only_eligibility_and_match(settings, monkeypatch, capsys):
    monkeypatch.setattr("sys.argv", ["diagnose", "--email", "demo@example.test"])
    monkeypatch.setattr(diagnose, "load_settings", lambda: settings)
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr(diagnose.getpass, "getpass", lambda _: "synthetic hidden password")
    monkeypatch.setattr(diagnose, "build_engine", MagicMock())
    monkeypatch.setattr(diagnose, "inspect_password", MagicMock(return_value=(True, False)))
    assert diagnose.main() == 0
    captured = capsys.readouterr()
    assert captured.out == "User eligible: yes\nPassword: no-match\n"
    assert captured.err == ""
