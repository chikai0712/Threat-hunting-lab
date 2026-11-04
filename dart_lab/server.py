"""Start the environment-configured API and source listeners with one command."""

import os
from pathlib import Path

import uvicorn
from dotenv import load_dotenv


def main():
    load_dotenv(Path.cwd() / ".env", override=False)
    # Socket peer is authoritative. Never let forwarded headers bypass source IP restrictions.
    uvicorn.run(
        "dart_lab.api:app",
        host=os.getenv("LISTEN_IP", "0.0.0.0"),
        port=int(os.getenv("HTTP_PORT", "8000")),
        proxy_headers=False,
        workers=1,
    )


if __name__ == "__main__":
    main()
