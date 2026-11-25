"""Coalesce network events and reconcile routes while DNS lookups are in flight."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
import logging
import threading
from typing import Callable


@dataclass
class _RefreshTask:
    run: Callable[[bool], None]
    pending: bool = False
    force: bool = False
    running: bool = False


class ReconciliationWorker:
    def __init__(self, manager, executor=None):
        self.manager = manager
        self.executor = executor if executor is not None else ThreadPoolExecutor(max_workers=2, thread_name_prefix='site-routing-refresh')
        self._lock = threading.RLock()
        self._closed = threading.Event()
        self._routes = _RefreshTask(self._refresh_routes)
        self._dns = _RefreshTask(manager.refresh_dns)

    def request(self, force_dns: bool = False) -> None:
        self._enqueue(self._routes, force_dns)

    def _refresh_routes(self, force_dns: bool) -> None:
        self.manager.refresh(resolve_dns=False)
        self._enqueue(self._dns, force_dns)

    def _enqueue(self, task: _RefreshTask, force: bool) -> None:
        with self._lock:
            if self._closed.is_set():
                return
            task.pending = True
            task.force |= force
            if task.running:
                return
            task.running = True
            self.executor.submit(self._drain, task)

    def _drain(self, task: _RefreshTask) -> None:
        while not self._closed.is_set():
            with self._lock:
                if not task.pending:
                    task.running = False
                    return
                force, task.force, task.pending = task.force, False, False
            try:
                task.run(force)
            except Exception:
                try:
                    self.manager.emergency_block()
                except Exception:
                    logging.error('Site Routing protection could not be confirmed; manual recovery is required.')
            with self._lock:
                pending = task.pending
            if pending:
                self._closed.wait(1)

    def close(self) -> None:
        with self._lock:
            self._closed.set()
        self.executor.shutdown(wait=True, cancel_futures=True)
