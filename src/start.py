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


class SuppressHealthCheckAccessLog(logging.Filter):
    """Drop successful health-check hits from the access log.

    uvicorn.access logs with args (client_addr, method, full_path, http_version,
    status_code), so this matches on those rather than the formatted string.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        args = record.args
        if not isinstance(args, tuple) or len(args) != 5:
            return True
        _, method, path, _, status_code = args
        return not (method == "GET" and path == "/" and isinstance(status_code, int) and status_code < 400)


# These are chatty at DEBUG and rarely tell us anything we want.
logging.getLogger("uvicorn").setLevel(logging.WARNING)
logging.getLogger("uvicorn.access").setLevel(logging.INFO)
logging.getLogger("httpx").setLevel(logging.WARNING)

if not settings.DEBUG:
    logging.getLogger("uvicorn.access").addFilter(SuppressHealthCheckAccessLog())

logging.info("Starting wsj27-auth-api on port %d", settings.PORT)

if settings.FAKE_USER_ID:
    banner = "!" * 72
    logging.warning(
        "%s\n"
        "!! FAKE_USER_ID is set — normal login is BYPASSED.\n"
        "!! /login signs in %s without authenticating anyone, and /refresh re-mints\n"
        "!! for them. The identity provider is never contacted, not even for discovery.\n"
        "!! This must never be set in production.\n"
        "%s",
        banner,
        settings.FAKE_USER_ID.get("preferred_username") or settings.FAKE_USER_ID.get("sub"),
        banner,
    )

if settings.ALLOW_IMPERSONATION:
    logging.warning(
        "ALLOW_IMPERSONATION is set: users holding %r can become any other member via POST /impersonate "
        "for up to %ds. This must never be set in production.",
        settings.IMPERSONATOR_ROLE,
        settings.IMPERSONATION_TTL_SECONDS,
    )

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
