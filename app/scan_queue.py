from queue import Queue
import threading
import time
from typing import Optional

class ScanQueue:
    """Thread-safe FIFO queue tracking mail scan jobs and progress.

    Wraps a standard ``queue.Queue`` with progress counters (total/completed),
    a one-shot notification flag for HTMX clients, and a grace period after
    the last scan completes so the status bar stays visible briefly.

    Attributes:
        queue: Underlying FIFO of mail ids waiting to be scanned.
        total: Total number of jobs added since the last reset.
        completed: Number of jobs whose scan has finished.
        lock: Mutex guarding all counter mutations.
        finished_at: Wall-clock timestamp when the last job completed,
            or ``None`` while jobs are still pending.
        notify_pending: One-shot flag consumed by ``pop_notify`` to trigger
            an HTMX ``scanComplete`` event on the next response.
    """

    def __init__(self) -> None:
        """Initializes an empty queue with zeroed counters."""
        self.queue: Queue[int] = Queue()
        self.total: int = 0
        self.completed: int = 0
        self.lock = threading.Lock()
        self.finished_at: Optional[float] = None
        self.notify_pending: bool = False

    def add(self, mail_id: int) -> None:
        """Enqueues a mail id for scanning.

        If the previous batch has fully completed, counters are reset before
        adding the new job so the progress bar starts from zero again.

        Args:
            mail_id: Primary key of the ``Mail`` row to scan.
        """
        with self.lock:
            self.notify_pending = True
            self.finished_at = None
            if self.completed == self.total:
                self.total = 0
                self.completed = 0
            self.queue.put(mail_id)
            self.total += 1

    def complete(self) -> None:
        """Marks one queued job as finished.

        Increments the completed counter and, if this was the last
        outstanding job, records the completion timestamp used by
        ``is_visible`` to keep the status bar shown for a grace period.
        """
        with self.lock:
            self.completed += 1
            self.notify_pending = True
            if self.completed == self.total:
                self.finished_at = time.time()

    def pop_notify(self) -> bool:
        """Atomically consumes the pending-notification flag.

        Returns:
            ``True`` exactly once after each ``add``/``complete`` call,
            then ``False`` until the next state change. Endpoints use this
            to emit an ``HX-Trigger: scanComplete`` header.
        """
        with self.lock:
            if self.notify_pending:
                self.notify_pending = False
                return True
            return False

    def is_visible(self) -> bool:
        """Reports whether the scan status bar should still be rendered.

        The bar stays visible while jobs are pending and for a one-second
        grace period after the final job completes, giving the user time
        to see the 100 %% state before it disappears.

        Returns:
            ``True`` if the status bar should be displayed.
        """
        with self.lock:
            if self.finished_at:
                return self.total > 0 and time.time() - self.finished_at < 1.0
            return self.total > 0 and self.completed < self.total

