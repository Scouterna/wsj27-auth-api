"""Process launcher.

Configures logging before uvicorn gets a chance to install its own dictConfig
(hence log_config=None), then serves app.main:app.

Settings are read through the settings object rather than os.getenv, so that
values in .env are honoured here exactly as they are inside the app.
"""

import logging
import sys

import uvicorn

from app.config import get_settings

LOGFORMAT = "%(asctime)s [%(name)-18s] [%(levelname)-5s] %(message)s"

try:
    settings = get_settings()
except Exception as exc:
    logging.basicConfig(level=logging.INFO, format=LOGFORMAT)
    logging.fatal("Configuration error: %s", exc)
    sys.exit(1)

logging.basicConfig(level=logging.DEBUG if settings.DEBUG else logging.INFO, format=LOGFORMAT)

# These are chatty at DEBUG and rarely tell us anything we want.
logging.getLogger("uvicorn").setLevel(logging.WARNING)
logging.getLogger("uvicorn.access").setLevel(logging.INFO)
logging.getLogger("httpx").setLevel(logging.WARNING)

logging.info("Starting wsj27-auth-api on port %d", settings.PORT)

try:
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=settings.PORT,
        log_config=None,
        # We sit behind an ingress that terminates TLS and strips the /auth
        # prefix; trust its X-Forwarded-* headers.
        proxy_headers=True,
        forwarded_allow_ips="*",
    )
except Exception as exc:
    logging.fatal("Fatal error: %s", exc, exc_info=True)

logging.info("Stopping wsj27-auth-api")
