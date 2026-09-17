"""Create a local development .env once; never print its generated password."""

import secrets
from pathlib import Path


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    template = (root / ".env.example").read_text(encoding="utf-8")
    content = template.replace("REPLACE_WITH_GENERATED_LOCAL_PASSWORD", secrets.token_urlsafe(32))
    try:
        # Exclusive creation also protects against concurrent invocations.
        with (root / ".env").open("x", encoding="utf-8", newline="\n") as file:
            file.write(content)
    except FileExistsError:
        print("Existing .env preserved.")
    else:
        print("Created local development .env; password was not displayed.")


if __name__ == "__main__":
    main()
