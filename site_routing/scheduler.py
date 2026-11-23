"""Coalesced network events and bounded, serialized background reconciliation."""
from concurrent.futures import ThreadPoolExecutor
import logging
import threading


class ReconciliationWorker:
    def __init__(self, manager, executor=None):
        self.manager = manager
        self.executor = executor if executor is not None else ThreadPoolExecutor(max_workers=1, thread_name_prefix='site-routing-refresh')
        self._lock = threading.RLock()
        self._closed = threading.Event()
        self._pending = self._force = self._running = False

    def request(self, force_dns: bool = False) -> None:
        with self._lock:
            if self._closed.is_set():
                return
            self._pending = True
            self._force |= force_dns
            if self._running:
                return
            self._running = True
            self.executor.submit(self._drain)

    def _drain(self) -> None:
        while not self._closed.is_set():
            with self._lock:
                if not self._pending:
                    self._running = False
                    return
                force, self._force, self._pending = self._force, False, False
            try:
                self.manager.refresh(force_dns=force)
            except Exception:
                try:
                    self.manager.emergency_block()
                except Exception:
                    logging.error('Site Routing protection could not be confirmed; manual recovery is required.')
            with self._lock:
                pending = self._pending
            if pending:
                self._closed.wait(1)

    def close(self) -> None:
        self._closed.set()
        self.executor.shutdown(wait=True, cancel_futures=True)
