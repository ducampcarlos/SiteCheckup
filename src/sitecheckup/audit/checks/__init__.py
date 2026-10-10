"""Built-in checks. Importing this package registers all of them."""

from sitecheckup.audit.checks import (  # noqa: F401
    cookies,
    exposed,
    headers,
    hygiene,
    transport,
    wordpress,
)
