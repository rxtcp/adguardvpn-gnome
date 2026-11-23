from concurrent.futures import Future
import unittest

from site_routing.lifecycle import restore_guard, release_all, check_empty
from site_routing.scheduler import ReconciliationWorker
from site_routing_fakes import MemoryStore, Kernel


class ImmediateExecutor:
    def submit(self, function, *args):
        future = Future()
        try: future.set_result(function(*args))
        except BaseException as error: future.set_exception(error)
        return future
    def shutdown(self, **kwargs): pass


class RoutingLifecycleTests(unittest.TestCase):
    def test_early_restore_uses_only_persisted_intent_and_does_nothing_when_empty(self):
        store = MemoryStore()
        kernel = Kernel(store)
        restore_guard(store, kernel)
        self.assertEqual(kernel.calls, [])
        store.state['kernel']['known'] = ['198.51.100.8']
        restore_guard(store, kernel)
        self.assertEqual(kernel.calls, [('block', {'198.51.100.8'})])
        self.assertFalse(check_empty(store))

    def test_explicit_release_guards_before_removing_only_owned_objects(self):
        store = MemoryStore()
        store.state['kernel']['known'] = ['198.51.100.8']
        kernel = Kernel(store)
        release_all(store, kernel)
        self.assertEqual(kernel.calls, [('block', {'198.51.100.8'}), ('apply', {})])
        self.assertTrue(check_empty(store))

    def test_empty_and_unresolved_configuration_release_does_not_invent_addresses(self):
        store = MemoryStore(); kernel = Kernel(store)
        release_all(store, kernel); self.assertEqual(kernel.calls, [])
        store.state['rules'] = [{'addresses': []}]
        restore_guard(store, kernel); self.assertEqual(kernel.calls, [])
        original = kernel.apply
        def apply(assignments, journal, installation, checkpoint):
            checkpoint({**journal, 'pending_objects': []})
            return original(assignments, journal, installation)
        kernel.apply = apply
        release_all(store, kernel)
        self.assertTrue(check_empty(store)); self.assertEqual(kernel.calls, [('apply', {})])

    def test_worker_serializes_refresh_and_no_new_work_starts_after_close(self):
        class Manager:
            def __init__(self): self.calls = []
            def refresh(self, force_dns=False): self.calls.append(force_dns)
        manager = Manager()
        worker = ReconciliationWorker(manager, executor=ImmediateExecutor())
        worker.request(True)
        worker.request(False)
        worker.close()
        worker.request(True)
        self.assertEqual(manager.calls, [True, False])

    def test_failed_background_refresh_reasserts_guard(self):
        class Manager:
            def __init__(self): self.blocked = False
            def refresh(self, force_dns=False): raise RuntimeError('failed')
            def emergency_block(self): self.blocked = True
        manager = Manager()
        worker = ReconciliationWorker(manager, executor=ImmediateExecutor())
        worker.request()
        worker.close()
        self.assertTrue(manager.blocked)
