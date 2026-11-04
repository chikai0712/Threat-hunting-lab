"""Create a local .env once without overwriting existing configuration."""

import os
import secrets
from pathlib import Path


def initialize(destination, template):
    contents = template.read_text().replace(
        "DART_API_TOKEN=\n", "DART_API_TOKEN=" + secrets.token_urlsafe(32) + "\n", 1
    )
    try:
        fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        return False
    with os.fdopen(fd, "w") as stream:
        stream.write(contents)
    return True


if __name__ == "__main__":
    root = Path(__file__).resolve().parents[1]
    created = initialize(root / ".env", root / ".env.example")
    print(
        "Created .env; fill in device sender IPs."
        if created
        else ".env already exists; preserved unchanged."
    )
