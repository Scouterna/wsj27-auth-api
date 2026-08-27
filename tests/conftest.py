"""Test configuration.

`app.config` builds its Settings at import time and fails loudly when required
values are missing — deliberately, so a misconfigured deployment cannot start.
Tests therefore need those values in the environment *before* the first import
of anything under `app`, which is what this file is for: conftest is imported
ahead of the test modules that do the importing.

The values are placeholders. Nothing here reaches the network.
"""

import os

os.environ.setdefault("PUBLIC_URL", "https://example.test/auth")
os.environ.setdefault("OIDC_SERVER", "https://idp.example.test")
os.environ.setdefault("OIDC_CLIENT_ID", "test-client")
os.environ.setdefault("OIDC_CLIENT_SECRET", "test-secret")
