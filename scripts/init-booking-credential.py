"""Local-only secret pair creation. Neither file is printed or written to .env."""

import hashlib
import os
import secrets
from pathlib import Path


def create_pair(directory):
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    raw_path = directory / "booking-service.secret"
    digest_path = directory / "booking-service.sha256"
    if raw_path.exists() or digest_path.exists():
        raise FileExistsError("Credential file already exists; nothing overwritten.")
    # Reserve BOTH exclusive files before writing any value. On failure retain
    # owned placeholders, never delete files another process may have created.
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    raw_fd = os.open(raw_path, flags, 0o600)
    try:
        digest_fd = os.open(digest_path, flags, 0o600)
        try:
            raw = secrets.token_urlsafe(32)
            digest = hashlib.sha256(raw.encode("ascii")).hexdigest()
            with os.fdopen(os.dup(raw_fd), "w", encoding="ascii") as stream:
                stream.write(raw)
            with os.fdopen(os.dup(digest_fd), "w", encoding="ascii") as stream:
                stream.write(digest)
        finally:
            os.close(digest_fd)
    finally:
        os.close(raw_fd)
    return raw_path, digest_path


def main():
    root = Path(__file__).resolve().parents[1]
    if Path.cwd().resolve() != root:
        print("Run from the Core project root.")
        return 1
    try:
        paths = create_pair(root / ".secrets")
    except OSError:
        print("Credential setup failed; inspect file existence/permissions. Nothing overwritten.")
        return 1
    for path in paths:
        print(path.relative_to(root))
    print(
        "Load the digest into Core configuration; securely transfer only the raw file to Booking."
    )
    print("Files are ignored. Restrict local Windows file ACLs; do not display or commit contents.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
