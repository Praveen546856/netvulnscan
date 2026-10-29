"""In-memory scan history and simple request limits. Nothing is written to disk."""
import threading
import time
from collections import OrderedDict, deque

from . import config
from .schemas import ScanResult


class ScanStore:
    def __init__(self, max_items: int = config.MAX_HISTORY):
        self._items: "OrderedDict[str, ScanResult]" = OrderedDict()
        self._lock = threading.Lock()
        self._max = max_items

    def add(self, scan: ScanResult) -> None:
        with self._lock:
            self._items[scan.scan_id] = scan
            while len(self._items) > self._max:
                self._items.popitem(last=False)  # drop the oldest

    def get(self, scan_id: str) -> ScanResult | None:
        with self._lock:
            return self._items.get(scan_id)

    def list(self) -> list[ScanResult]:
        with self._lock:
            return list(reversed(self._items.values()))

    def clear(self) -> None:
        with self._lock:
            self._items.clear()


class ScanLimiter:
    """Allow one scan at a time and a maximum number of scans per minute."""

    def __init__(self, per_minute: int = config.MAX_SCANS_PER_MINUTE):
        self._running = threading.Lock()
        self._times: deque[float] = deque()
        self._guard = threading.Lock()
        self._per_minute = per_minute

    def try_start(self) -> str | None:
        """Return None if the scan may start, otherwise a reason string."""
        with self._guard:
            now = time.monotonic()
            while self._times and now - self._times[0] > 60:
                self._times.popleft()
            if len(self._times) >= self._per_minute:
                return "Too many scans. Please wait a minute and try again."
            if not self._running.acquire(blocking=False):
                return "Another scan is already running. Please wait for it to finish."
            self._times.append(now)
            return None

    def finish(self) -> None:
        if self._running.locked():
            self._running.release()

    def reset(self) -> None:
        with self._guard:
            self._times.clear()
        self.finish()


store = ScanStore()
limiter = ScanLimiter()
