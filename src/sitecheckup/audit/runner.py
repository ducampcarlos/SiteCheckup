"""Run all registered checks against a target and assemble the report."""

from __future__ import annotations

from collections.abc import Callable, Collection

from sitecheckup.audit.base import Check, Outcome, all_checks
from sitecheckup.audit.context import AuditContext
from sitecheckup.audit.models import AuditReport, Finding, Status
from sitecheckup.audit.scoring import compute_score
from sitecheckup.http import PoliteClient, RequestBudgetExceeded
from sitecheckup.tlsinfo import CertProvider, fetch_certificate


class TargetUnreachable(RuntimeError):
    """Raised when the homepage cannot be fetched at all."""


def _run_one(check: Check, ctx: AuditContext) -> Finding:
    if check.wordpress_only and not ctx.is_wordpress:
        return check.finding(Outcome.skip("WordPress was not detected on the homepage."))
    try:
        return check.finding(check.run(ctx))
    except RequestBudgetExceeded:
        raise
    except Exception as exc:
        return check.finding(Outcome(Status.ERROR, f"{type(exc).__name__}: {exc}"))


def run_audit(
    target: str,
    client: PoliteClient,
    *,
    skip: Collection[str] = (),
    cert_provider: CertProvider = fetch_certificate,
    on_check: Callable[[Check], None] | None = None,
) -> AuditReport:
    """Run every registered check (except those in ``skip``) against ``target``.

    Raises:
        TargetUnreachable: if the homepage cannot be fetched.
    """
    ctx = AuditContext(target, client, cert_provider)
    try:
        home = ctx.homepage
    except RequestBudgetExceeded as exc:  # pragma: no cover - needs max_requests < 1
        raise TargetUnreachable(str(exc)) from exc
    if not home.ok:
        raise TargetUnreachable(f"Could not reach {target}: {home.error}")

    findings: list[Finding] = []
    truncated = False
    for check in all_checks():
        if check.id in skip:
            continue
        if on_check:
            on_check(check)
        if truncated:
            findings.append(check.finding(Outcome.skip("Request cap reached before this check.")))
            continue
        try:
            findings.append(_run_one(check, ctx))
        except RequestBudgetExceeded:
            truncated = True
            findings.append(check.finding(Outcome.skip("Request cap reached before this check.")))

    score, grade = compute_score(findings)
    return AuditReport(
        target=target,
        requests_made=client.requests_made,
        truncated=truncated,
        wordpress_detected=ctx.is_wordpress,
        score=score,
        grade=grade,
        findings=findings,
    )
