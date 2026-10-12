"""The shared scanning engine used by the CLI and the web application."""

from __future__ import annotations

import logging
import threading
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass

import httpx

from white import __version__
from white.scanner.checks.base import Check, Outcome, ScanContext
from white.scanner.http import SafeHttpClient, ScanBudgetExceeded, ScanCancelled
from white.scanner.models import (
    CheckResult,
    CheckStatus,
    ScanConfig,
    ScanReport,
    ScanState,
    utcnow,
)
from white.scanner.netsafety import validate_target_url
from white.scanner.registry import all_checks

log = logging.getLogger("white.scanner")


@dataclass
class Progress:
    stage: str
    completed: int
    total: int
    current_check: str | None = None


ProgressCallback = Callable[[Progress], None]


class Scanner:
    def __init__(
        self,
        config: ScanConfig | None = None,
        *,
        checks: list[Check] | None = None,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self.config = config or ScanConfig()
        self.checks = checks if checks is not None else all_checks()
        self._transport = transport

    def run(
        self,
        url: str,
        *,
        scan_id: str | None = None,
        progress: ProgressCallback | None = None,
        cancel_event: threading.Event | None = None,
    ) -> ScanReport:
        """Run every registered check against ``url``.

        Raises :class:`TargetValidationError` before any network activity if the URL is not
        permitted. All other problems are recorded in the report rather than raised.
        """
        target = validate_target_url(url, self.config)
        cancel_event = cancel_event or threading.Event()
        notify = progress or (lambda _p: None)
        started = utcnow()
        started_mono = time.monotonic()
        report = ScanReport(
            tool_version=__version__,
            scan_id=scan_id or str(uuid.uuid4()),
            target_url=target.url,
            hostname=target.host,
            state=ScanState.RUNNING,
            started_at=started,
            active_checks_enabled=self.config.active_checks,
        )
        total = len(self.checks)
        client = SafeHttpClient(
            self.config,
            transport=self._transport,
            cancel_event=cancel_event,
            deadline=started_mono + self.config.max_scan_seconds,
        )
        ctx = ScanContext(target=target, client=client, config=self.config)
        stop_reason: str | None = None
        cancelled = False
        main = None
        try:
            notify(Progress("Connecting to the website", 0, total))
            try:
                main = ctx.primary()
            except ScanCancelled:
                cancelled, stop_reason = True, "The scan was cancelled."
            except ScanBudgetExceeded as exc:
                stop_reason = str(exc)
            for index, check in enumerate(self.checks):
                if not cancelled and cancel_event.is_set():
                    cancelled, stop_reason = True, "The scan was cancelled."
                if stop_reason:
                    report.checks.append(
                        check.result(Outcome(CheckStatus.NOT_TESTED, f"Not run: {stop_reason}"))
                    )
                    continue
                notify(Progress(f"Running check: {check.name}", index, total, check.name))
                try:
                    result = self._run_check(check, ctx)
                except ScanCancelled:
                    cancelled, stop_reason = True, "The scan was cancelled."
                    result = check.result(Outcome(CheckStatus.NOT_TESTED, f"Not run: {stop_reason}"))
                except ScanBudgetExceeded as exc:
                    stop_reason = str(exc)
                    result = check.result(
                        Outcome(CheckStatus.NOT_TESTED, f"Stopped before completion: {stop_reason}")
                    )
                report.checks.append(result)
        finally:
            client.close()

        report.final_url = main.final_url if main is not None and main.ok else None
        if stop_reason and not cancelled:
            report.errors.append(stop_reason)
        if main is not None and not main.ok and main.error:
            report.errors.append(f"Target unreachable: {main.error}")
        report.finished_at = utcnow()
        report.duration_seconds = round(time.monotonic() - started_mono, 2)
        if cancelled:
            report.state = ScanState.CANCELLED
        elif main is None or not main.ok:
            report.state = ScanState.FAILED
        elif stop_reason or any(c.status == CheckStatus.ERROR for c in report.checks):
            report.state = ScanState.COMPLETED_WITH_ERRORS
        else:
            report.state = ScanState.COMPLETED
        report.compute_summary()
        notify(Progress("Finished", total, total))
        return report

    def _run_check(self, check: Check, ctx: ScanContext) -> CheckResult:
        """Run one check. ScanCancelled/ScanBudgetExceeded propagate to the caller."""
        start = time.monotonic()
        try:
            result = check.result(check.evaluate(ctx))
        except (ScanCancelled, ScanBudgetExceeded):
            raise
        except Exception as exc:  # noqa: BLE001 - a failing check must not abort the scan
            log.exception("check %s failed", check.id)
            result = check.result(
                Outcome(
                    CheckStatus.ERROR,
                    "The check failed to run.",
                    errors=[f"{exc.__class__.__name__}: {str(exc)[:200]}"],
                )
            )
        result.duration_ms = int((time.monotonic() - start) * 1000)
        return result
