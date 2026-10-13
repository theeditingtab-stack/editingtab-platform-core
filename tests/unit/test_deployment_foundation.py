from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def read(relative_path: str) -> str:
    return (ROOT / relative_path).read_text(encoding="utf-8")


def test_image_is_locked_non_root_and_does_not_migrate_on_startup():
    dockerfile = read("Dockerfile")

    assert "python:3.12-slim-bookworm@sha256:" in dockerfile
    assert "uv sync --locked --no-dev --no-editable" in dockerfile
    assert "USER core" in dockerfile
    assert "--reload" not in dockerfile
    assert "COPY .env" not in dockerfile
    assert "editingtab_core.app:create_app" in dockerfile
    assert "alembic upgrade" not in dockerfile


def test_migration_is_an_explicit_command():
    migration = read("scripts/run-migrations.py")

    assert '[sys.executable, "-m", "alembic", "upgrade", "head"]' in migration
    assert "CORE_ENVIRONMENT must be production" in migration


def test_secret_loader_reads_files_without_echoing_values():
    loader = read("scripts/load-production-secrets.sh")

    assert "CORE_DB_PASSWORD_FILE" in loader
    assert "CORE_BOOKING_SERVICE_CURRENT_DIGEST_FILE" in loader
    assert "set -x" not in loader
    assert 'exec "$@"' in loader


def test_production_validator_accepts_deployment_specific_https_origin():
    validator = read("scripts/validate-production-config.py")

    assert "https://demo.theeditingtab.com" not in validator
    assert "at least one exact HTTPS browser origin" in validator
