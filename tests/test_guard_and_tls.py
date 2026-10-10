from __future__ import annotations

import socket
import ssl
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from sitecheckup.guard import InvalidTarget, normalize_target
from sitecheckup.tlsinfo import CertInfo, cert_from_dict, fetch_certificate


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("example.com", "https://example.com"),
        (" http://localhost:8080/path ", "http://localhost:8080/path"),
        ("https://example.org", "https://example.org"),
    ],
)
def test_normalize_target(raw: str, expected: str) -> None:
    assert normalize_target(raw) == expected


@pytest.mark.parametrize(
    "raw", ["ftp://example.com", "file:///etc/passwd", "https://", "https://u:p@example.com"]
)
def test_normalize_target_rejects(raw: str) -> None:
    with pytest.raises(InvalidTarget):
        normalize_target(raw)


def test_cert_from_dict_and_days_left() -> None:
    expiry = (datetime.now(UTC) + timedelta(days=40)).strftime("%b %d %H:%M:%S %Y GMT")
    cert = cert_from_dict(
        {
            "notAfter": expiry,
            "issuer": (
                (("organizationName", "Example CA"),),
                (("commonName", "Example Issuing CA"),),
            ),
            "subject": ((("commonName", "example.com"),),),
        }  # type: ignore[typeddict-item]
    )
    assert cert.verified
    assert cert.issuer == "Example Issuing CA"
    assert cert.subject == "example.com"
    assert cert.days_left() in {39, 40}
    assert cert_from_dict({}).days_left() is None


def test_cert_info_days_left_handles_unknown() -> None:
    assert CertInfo(verified=False, error="x").days_left() is None


class _FakeTls:
    def __init__(self, cert: dict[str, Any]) -> None:
        self._cert = cert

    def __enter__(self) -> _FakeTls:
        return self

    def __exit__(self, *_: object) -> None:
        return None

    def getpeercert(self) -> dict[str, Any]:
        return self._cert


class _FakeContext:
    def __init__(self, outcome: Exception | dict[str, Any]) -> None:
        self.outcome = outcome

    def wrap_socket(self, raw: object, server_hostname: str) -> _FakeTls:
        if isinstance(self.outcome, Exception):
            raise self.outcome
        return _FakeTls(self.outcome)


class _Raw:
    def __enter__(self) -> _Raw:
        return self

    def __exit__(self, *_: object) -> None:
        return None


def patch_network(monkeypatch: pytest.MonkeyPatch, outcome: Exception | dict[str, Any]) -> None:
    monkeypatch.setattr(socket, "create_connection", lambda *_a, **_k: _Raw())
    monkeypatch.setattr(ssl, "create_default_context", lambda: _FakeContext(outcome))


def test_fetch_certificate_success(monkeypatch: pytest.MonkeyPatch) -> None:
    patch_network(monkeypatch, {"subject": ((("commonName", "example.com"),),)})
    assert fetch_certificate("example.com").verified


def test_fetch_certificate_reports_verification_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    error = ssl.SSLCertVerificationError(1, "certificate verify failed")
    error.verify_message = "certificate has expired"
    patch_network(monkeypatch, error)
    cert = fetch_certificate("example.com")
    assert (cert.verified, cert.error) == (False, "certificate has expired")


def test_fetch_certificate_reports_connection_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    patch_network(monkeypatch, ConnectionRefusedError("refused"))
    cert = fetch_certificate("example.com")
    assert not cert.verified
    assert "ConnectionRefusedError" in (cert.error or "")
