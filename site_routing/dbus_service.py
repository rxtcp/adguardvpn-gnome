"""Asynchronous, bounded D-Bus request execution; no privileged work on the loop."""
from concurrent.futures import ThreadPoolExecutor
import threading

from .domain import MAX_REQUEST_BYTES
from .rpc import envelope


class DbusService:
    def __init__(self, dispatcher, glib, executor=None):
        self.dispatcher, self.glib = dispatcher, glib
        self.executor = executor if executor is not None else ThreadPoolExecutor(max_workers=4, thread_name_prefix='site-routing-api')
        self.slots = threading.BoundedSemaphore(16)

    def method_call(self, connection, sender, object_path, interface, method, parameters, invocation):
        contents = parameters.unpack()[0]
        if method != 'Request' or not isinstance(contents, str) or len(contents.encode('utf-8')) > MAX_REQUEST_BYTES:
            self._reply(invocation, envelope(code='invalid-request', message='Invalid Site Routing request.'))
            return
        if not self.slots.acquire(blocking=False):
            self._reply(invocation, envelope(code='busy', message='Site Routing is busy. Try again shortly.'))
            return
        future = self.executor.submit(self.dispatcher.dispatch, invocation.get_sender(), contents)
        def completed(result):
            self.slots.release()
            try:
                response = result.result()
            except Exception:
                response = envelope(code='internal-error', message='The service did not complete the request.')
            self.glib.idle_add(self._reply, invocation, response)
        future.add_done_callback(completed)

    def _reply(self, invocation, response: str):
        invocation.return_value(self.glib.Variant('(s)', (response,)))
        return self.glib.SOURCE_REMOVE

    def close(self) -> None:
        self.executor.shutdown(wait=True, cancel_futures=True)
