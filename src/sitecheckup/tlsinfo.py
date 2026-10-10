"""TLS certificate inspection (a single handshake, nothing else)."""

from __future__ import annotations

import socket
import ssl
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime

DEFAULT_TIMEOUT = 8.0


@dataclass(frozen=True)
class CertInfo:
    """Summary of the certificate presented by a server."""

    verified: bool
    error: str | None = None
    not_after: datetime | None = None
    issuer: str | None = None
    subject: str | None = None

    def days_left(self, now: datetime | None = None) -> int | None:
        """Whole days until expiry, or None if the expiry date is unknown."""
        if self.not_after is None:
            return None
        return (self.not_after - (now or datetime.now(UTC))).days


CertProvider = Callable[[str, int], CertInfo]


def _name(rdns: object) -> str | None:
    if not isinstance(rdns, tuple):
        return None
    pairs = {k: v for rdn in rdns for k, v in rdn}
    return pairs.get("commonName") or pairs.get("organizationName")


def cert_from_dict(cert: ssl._PeerCertRetDictType) -> CertInfo:
    """Convert the dict returned by ``SSLSocket.getpeercert()`` to :class:`CertInfo`."""
    expiry = cert.get("notAfter")
    not_after = (
        datetime.fromtimestamp(ssl.cert_time_to_seconds(str(expiry)), UTC) if expiry else None
    )
    return CertInfo(
        verified=True,
        not_after=not_after,
        issuer=_name(cert.get("issuer")),
        subject=_name(cert.get("subject")),
    )


def fetch_certificate(host: str, port: int = 443, timeout: float = DEFAULT_TIMEOUT) -> CertInfo:
    """Perform one verified TLS handshake and describe the certificate.

    Verification failures (expired, self-signed, hostname mismatch) are reported
    through ``CertInfo.verified``/``error`` instead of raising.
    """
    context = ssl.create_default_context()
    try:
        with (
            socket.create_connection((host, port), timeout=timeout) as raw,
            context.wrap_socket(raw, server_hostname=host) as tls,
        ):
            return cert_from_dict(tls.getpeercert() or {})
    except ssl.SSLCertVerificationError as exc:
        return CertInfo(verified=False, error=exc.verify_message or str(exc))
    except (OSError, ssl.SSLError) as exc:
        return CertInfo(verified=False, error=f"{type(exc).__name__}: {exc}")
