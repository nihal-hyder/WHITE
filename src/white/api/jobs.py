"""In-process scan job manager with concurrency, per-user and duplicate-submission limits.

This is suitable for a single local server process. Jobs do not survive a restart (they are
marked 'interrupted'). A production multi-instance deployment would replace this with a
durable worker queue; the scanner itself needs no changes for that.
"""

from __future__ import annotations

import logging
import threading
import time
from collections import defaultdict, deque
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import UTC, datetime

from white.scanner.engine import Progress, Scanner
from white.scanner.models import ScanConfig, ScanReport, ScanState

log = logging.getLogger("white.jobs")
DUPLICATE_WINDOW = 30.0


class JobRejected(Exception):
    def __init__(self, message: str, status_code: int = 429) -> None:
        super().__init__(message)
        self.status_code = status_code


@dataclass
class Job:
    scan_id: str
    owner_id: str
    target_url: str
    state: ScanState = ScanState.QUEUED
    stage: str = "Waiting to start"
    completed: int = 0
    total: int = 0
    submitted_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    started_monotonic: float | None = None
    finished_monotonic: float | None = None
    error: str | None = None
    cancel_event: threading.Event = field(default_factory=threading.Event)

    @property
    def elapsed_seconds(self) -> float:
        if self.started_monotonic is None:
            return 0.0
        end = self.finished_monotonic or time.monotonic()
        return round(end - self.started_monotonic, 1)

    def to_status(self) -> dict:
        return {
            "scan_id": self.scan_id,
            "state": self.state.value,
            "stage": self.stage,
            "completed_checks": self.completed,
            "total_checks": self.total,
            "elapsed_seconds": self.elapsed_seconds,
            "error": self.error,
            "live": True,
        }


SaveCallback = Callable[[ScanReport], None]
FailCallback = Callable[[ScanState, str], None]


class JobManager:
    def __init__(
        self,
        max_concurrent: int = 3,
        per_user_per_hour: int = 20,
        scanner_factory: Callable[[ScanConfig], Scanner] | None = None,
    ) -> None:
        self.max_concurrent = max_concurrent
        self.per_user_per_hour = per_user_per_hour
        self._executor = ThreadPoolExecutor(max_workers=max_concurrent, thread_name_prefix="white-scan")
        self._jobs: dict[str, Job] = {}
        self._history: dict[str, deque[float]] = defaultdict(deque)
        self._recent: dict[tuple[str, str], float] = {}
        self._lock = threading.Lock()
        self.scanner_factory = scanner_factory or (lambda config: Scanner(config))

    def get(self, scan_id: str, owner_id: str) -> Job | None:
        job = self._jobs.get(scan_id)
        return job if job is not None and job.owner_id == owner_id else None

    def active_for(self, owner_id: str) -> list[Job]:
        return [
            j
            for j in self._jobs.values()
            if j.owner_id == owner_id and j.state in {ScanState.QUEUED, ScanState.RUNNING}
        ]

    def reserve(self, owner_id: str, target_url: str, scan_id: str) -> Job:
        """Apply abuse limits and register a job. Raises JobRejected."""
        now = time.monotonic()
        with self._lock:
            if self.active_for(owner_id):
                raise JobRejected(
                    "You already have a scan in progress. Wait for it to finish or cancel it.", 409
                )
            last = self._recent.get((owner_id, target_url))
            if last is not None and now - last < DUPLICATE_WINDOW:
                raise JobRejected(
                    "This website was just scanned. Please wait a moment before scanning it again.", 409
                )
            history = self._history[owner_id]
            while history and now - history[0] > 3600:
                history.popleft()
            if len(history) >= self.per_user_per_hour:
                raise JobRejected("You have reached the hourly scan limit. Please try again later.")
            queued = sum(1 for j in self._jobs.values() if j.state in {ScanState.QUEUED, ScanState.RUNNING})
            if queued >= self.max_concurrent * 2:
                raise JobRejected("The scanner is busy. Please try again in a minute.", 503)
            history.append(now)
            self._recent[(owner_id, target_url)] = now
            job = Job(scan_id=scan_id, owner_id=owner_id, target_url=target_url)
            self._jobs[scan_id] = job
            self._prune()
            return job

    def release(self, job: Job) -> None:
        """Undo a reservation when the scan record could not be created."""
        with self._lock:
            self._jobs.pop(job.scan_id, None)

    def start(self, job: Job, config: ScanConfig, on_save: SaveCallback, on_fail: FailCallback) -> None:
        self._executor.submit(self._run, job, config, on_save, on_fail)

    def cancel(self, scan_id: str, owner_id: str) -> bool:
        job = self.get(scan_id, owner_id)
        if job is None or job.state not in {ScanState.QUEUED, ScanState.RUNNING}:
            return False
        job.cancel_event.set()
        job.stage = "Cancelling"
        return True

    def _run(self, job: Job, config: ScanConfig, on_save: SaveCallback, on_fail: FailCallback) -> None:
        job.state = ScanState.RUNNING
        job.started_monotonic = time.monotonic()
        job.stage = "Starting"

        def progress(p: Progress) -> None:
            job.stage, job.completed, job.total = p.stage, p.completed, p.total

        try:
            scanner = self.scanner_factory(config)
            job.total = len(scanner.checks)
            report = scanner.run(
                job.target_url, scan_id=job.scan_id, progress=progress, cancel_event=job.cancel_event
            )
        except Exception as exc:  # noqa: BLE001
            log.exception("scan %s crashed", job.scan_id)
            job.state, job.error = ScanState.FAILED, f"The scan could not run: {exc.__class__.__name__}"
            job.finished_monotonic = time.monotonic()
            self._safe(on_fail, ScanState.FAILED, job.error)
            return
        job.stage = "Saving results"
        try:
            on_save(report)
        except Exception as exc:  # noqa: BLE001
            log.exception("saving scan %s failed", job.scan_id)
            job.state = ScanState.FAILED
            job.error = f"The scan finished but the results could not be saved: {exc}"
            job.finished_monotonic = time.monotonic()
            self._safe(on_fail, ScanState.FAILED, job.error)
            return
        job.state = report.state
        job.stage = "Finished"
        job.completed = len(report.checks)
        job.finished_monotonic = time.monotonic()

    @staticmethod
    def _safe(callback: FailCallback, state: ScanState, message: str) -> None:
        try:
            callback(state, message)
        except Exception:  # noqa: BLE001
            log.exception("could not record scan failure")

    def _prune(self) -> None:
        finished = [
            j
            for j in self._jobs.values()
            if j.finished_monotonic and time.monotonic() - j.finished_monotonic > 3600
        ]
        for job in finished:
            self._jobs.pop(job.scan_id, None)
        cutoff = time.monotonic() - DUPLICATE_WINDOW
        for key in [k for k, v in self._recent.items() if v < cutoff]:
            self._recent.pop(key, None)

    def shutdown(self) -> None:
        for job in self._jobs.values():
            job.cancel_event.set()
        self._executor.shutdown(wait=False, cancel_futures=True)
