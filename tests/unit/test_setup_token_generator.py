"""The setup-token helper writes a valid pair and never prints secret material."""

import hashlib
import importlib.util
import re
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "init-setup-token.py"
SPEC = importlib.util.spec_from_file_location("init_setup_token", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


def test_create_pair_is_high_entropy_consistent_and_non_overwriting(tmp_path, capsys):
    raw_path, digest_path = MODULE.create_pair(tmp_path / "secrets")
    raw = raw_path.read_text(encoding="ascii")
    digest = digest_path.read_text(encoding="ascii")
    assert re.fullmatch(r"[A-Za-z0-9_-]{43}", raw)
    assert digest == hashlib.sha256(raw.encode("ascii")).hexdigest()
    with pytest.raises(FileExistsError):
        MODULE.create_pair(tmp_path / "secrets")
    assert raw not in capsys.readouterr().out
