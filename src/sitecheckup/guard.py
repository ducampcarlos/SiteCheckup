"""Authorization guardrail: scanning requires an explicit opt-in flag."""

from __future__ import annotations

from urllib.parse import urlsplit

PERMISSION_MESSAGE = """\
sitecheckup sends real HTTP requests to the sites you point it at.

Refusing to run without --i-have-permission. Pass that flag only if you own the
target or have explicit, written authorization to test it. Unauthorized testing
may be illegal. See SECURITY.md for the full policy.
"""


class InvalidTarget(ValueError):
    """Raised when a user-supplied URL is not a usable http(s) URL."""


def normalize_target(url: str) -> str:
    """Validate ``url`` and return it with a scheme and a non-empty host.

    A bare host such as ``example.com`` is accepted and treated as ``https://``.
    URLs that embed credentials are rejected so they never end up in reports.
    """
    candidate = url.strip()
    if "://" not in candidate:
        candidate = f"https://{candidate}"
    parts = urlsplit(candidate)
    if parts.scheme not in {"http", "https"}:
        raise InvalidTarget(f"Unsupported scheme {parts.scheme!r}; use http or https.")
    if not parts.hostname:
        raise InvalidTarget(f"No host found in {url!r}.")
    if parts.username or parts.password:
        raise InvalidTarget("URLs with embedded credentials are not accepted.")
    return candidate
