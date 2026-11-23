"""System service boundaries using native variants and isolated fake processes."""
from concurrent.futures import Future
import io
import json
from pathlib import Path
import runpy
import stat
import subprocess
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from gi.repository import Gio, GLib

from routing_system import launch
from site_routing import commands, daemon, entry
from site_routing.dbus_service import DbusService
from site_routing.network_events import NetworkEvents
from site_routing.scheduler import ReconciliationWorker


class QueuedExecutor:
    def __init__(self): self.jobs, self.closed = [], False
    def submit(self, function, *args):
        future = Future()
        self.jobs.append((future, function, args))
        return future
    def run(self):
        future, function, args = self.jobs.pop(0)
        try: future.set_result(function(*args))
        except Exception as error: future.set_exception(error)
    def shutdown(self, **kwargs): self.closed = kwargs


class CommandTests(unittest.TestCase):
    def test_numeric_kernel_output_has_stable_ids_and_canonical_protocol_scope_action_names(self):
        runner = commands.CommandRunner()
        rows = [{'table': '40000', 'protocol': '196', 'scope': '253', 'type': '1'},
                {'table': 880, 'protocol': '4', 'scope': '0', 'type': '7'}, {'dst': 'default'}]
        with patch.object(runner, 'run', return_value=json.dumps(rows)):
            self.assertEqual(runner.read_ip(4, 'route', 'show'), [
                {'table': 40000, 'protocol': '196', 'scope': 'link', 'type': 'unicast'},
                {'table': 880, 'protocol': 'static', 'scope': 'global', 'type': 'unreachable'}, {'dst': 'default'}])
        with patch.object(runner, 'run', return_value='[{"action":"1"},{"action":"7"}]'):
            self.assertEqual(runner.read_ip(6, 'rule', 'show'), [{'action': 'lookup'}, {'action': 'unreachable'}])
        for malformed in ('[42]', '[{"table":true}]', '[{"table":"unknown-alias"}]',
                          '[{"table":-1}]', '[{"table":4294967296}]'):
            with patch.object(runner, 'run', return_value=malformed), self.assertRaises(ValueError):
                runner.read_ip(4, 'route', 'show')

    def test_fixed_commands_bound_output_timeout_environment_and_no_shell(self):
        runner = commands.CommandRunner()
        with patch.object(commands.subprocess, 'run', return_value=SimpleNamespace(returncode=0, stdout='[]')) as run:
            self.assertEqual(runner.read_ip(6, 'rule', 'show'), [])
            self.assertEqual(run.call_args.args[0], ['/usr/sbin/ip', '-N', '-6', '-j', 'rule', 'show'])
            self.assertEqual(runner.read_links(), [])
            runner.write_ip(4, 'rule', 'add')
            runner.nft_apply('fixture transaction')
            self.assertEqual(run.call_args.args[0], ['/usr/sbin/nft', '-f', '-'])
            self.assertEqual(run.call_args.kwargs['input'], 'fixture transaction')
            self.assertIsNone(run.call_args.kwargs['stdin'])
            self.assertEqual(run.call_args.kwargs['timeout'], 12)
            self.assertEqual(run.call_args.kwargs['env'], commands.ENVIRONMENT)
            self.assertNotIn('shell', run.call_args.kwargs)
            run.return_value.stdout = '{"nftables": []}'
            self.assertEqual(runner.nft_json('list', 'tables'), {'nftables': []})
            for output in ('{}', 'null', '1'):
                run.return_value.stdout = output
                with self.assertRaises(ValueError): runner.read_ip(4, 'rule', 'show')
                with self.assertRaises(ValueError): runner.read_links()
                with self.assertRaises(ValueError): runner.nft_json('list', 'tables')
            run.return_value.stdout = '{"nftables": {}}'
            with self.assertRaises(ValueError): runner.nft_json('list', 'tables')
            for result in (SimpleNamespace(returncode=1, stdout='private command details'),
                           SimpleNamespace(returncode=0, stdout='x' * (2 * 1024 * 1024 + 1))):
                run.return_value = result
                with self.assertRaisesRegex(RuntimeError, 'no successful routing'): runner.run(['/usr/sbin/ip'])
            for error in (OSError('private path'), subprocess.TimeoutExpired('ip', 12)):
                run.side_effect = error
                with self.assertRaisesRegex(RuntimeError, 'unavailable or timed out'): runner.run(['/usr/sbin/ip'])


class ServiceTests(unittest.TestCase):
    def test_executor_shutdown_rejects_new_calls_without_leaking_capacity_or_throwing(self):
        replies = []
        invocation = SimpleNamespace(get_sender=lambda: ':1.42', return_value=replies.append)
        service = DbusService(Mock(), GLib, Mock(submit=Mock(side_effect=RuntimeError('executor stopped'))))
        service.method_call(None, ':1.42', '/', 'fixture', 'Request', GLib.Variant('(s)', ('{}',)), invocation)
        self.assertEqual(json.loads(replies[0].unpack()[0])['error']['code'], 'busy')
        self.assertTrue(all(service.slots.acquire(blocking=False) for _index in range(16)))

    def test_requests_use_actual_sender_and_reply_on_main_loop_with_a_bounded_queue(self):
        executor, replies, idle = QueuedExecutor(), [], []
        glib = SimpleNamespace(Variant=GLib.Variant, SOURCE_REMOVE=False,
                               idle_add=lambda function, *args: idle.append((function, args)))
        dispatcher = SimpleNamespace(dispatch=Mock(return_value='{"ok": true}'))
        service = DbusService(dispatcher, glib, executor)
        invocation = SimpleNamespace(get_sender=lambda: ':1.42', return_value=replies.append)
        def request(method='Request', value='{}'):
            service.method_call(None, ':1.forged', '/', 'fixture', method, SimpleNamespace(unpack=lambda: (value,)), invocation)
        for method, value in [('Other', '{}'), ('Request', 5), ('Request', 'я' * 16384)]:
            request(method, value)
            self.assertEqual(json.loads(replies.pop().unpack()[0])['error']['code'], 'invalid-request')
        for _index in range(16): request()
        request()
        self.assertEqual(json.loads(replies.pop().unpack()[0])['error']['code'], 'busy')
        executor.run()
        dispatcher.dispatch.assert_called_once_with(':1.42', '{}')
        self.assertEqual(replies, [])
        function, args = idle.pop(0)
        self.assertFalse(function(*args))
        self.assertEqual(replies.pop().unpack(), ('{"ok": true}',))
        dispatcher.dispatch.side_effect = RuntimeError('private diagnostic')
        executor.run()
        function, args = idle.pop(0); function(*args)
        self.assertEqual(json.loads(replies.pop().unpack()[0])['error']['code'], 'internal-error')
        service.close()
        self.assertEqual(executor.closed, {'wait': True, 'cancel_futures': True})
        DbusService(dispatcher, glib).close()

    def test_network_monitor_is_read_only_and_shutdown_handles_eof_and_kill(self):
        callback = Mock()
        process = Mock(stdout=io.StringIO('fixture link change\nfixture route change\n'))
        process.poll.return_value = None
        process.wait.side_effect = [subprocess.TimeoutExpired('ip', 2), 0]
        popen = Mock(return_value=process)
        monitor = NetworkEvents(callback, popen)
        monitor.start(); monitor.thread.join(timeout=2)
        self.assertEqual(callback.call_count, 2)
        self.assertEqual(popen.call_args.args[0], ['/usr/sbin/ip', 'monitor', 'link', 'address', 'route', 'rule'])
        monitor.close()
        process.terminate.assert_called_once(); process.kill.assert_called_once()
        self.assertTrue(process.stdout.closed)
        missing = NetworkEvents(callback, Mock(side_effect=OSError('not installed')))
        missing.start(); missing.close()
        process = Mock(stdout=io.StringIO(''))
        process.poll.return_value = 0
        finished = NetworkEvents(callback, Mock(return_value=process))
        finished.start(); finished.thread.join(timeout=2); finished.close()
        process.terminate.assert_not_called()
        stopped = NetworkEvents(callback)
        stopped.close(); stopped._read()

    def test_worker_coalesces_events_and_blocks_on_unexpected_refresh_failure(self):
        executor, manager = QueuedExecutor(), Mock()
        worker = ReconciliationWorker(manager, executor)
        worker.request(); worker.request(True); worker.request()
        self.assertEqual(len(executor.jobs), 1)
        def refresh(**kwargs):
            if manager.refresh.call_count == 1:
                worker.request(True)
                raise RuntimeError('fixture discovery failure')
        manager.refresh.side_effect = refresh
        with patch.object(worker._closed, 'wait', return_value=False): executor.run()
        self.assertEqual(manager.refresh.call_count, 2)
        manager.emergency_block.assert_called_once()
        self.assertTrue(manager.refresh.call_args.kwargs['force_dns'])
        manager.refresh.side_effect = RuntimeError('fixture refresh failure')
        manager.emergency_block.side_effect = RuntimeError('fixture firewall failure')
        worker.request()
        with self.assertLogs(level='ERROR') as logs: executor.run()
        self.assertIn('protection could not be confirmed', logs.output[0])
        worker.request(); worker.close(); worker.request(); executor.run()
        self.assertEqual(manager.refresh.call_count, 3)
        ReconciliationWorker(manager).close()

    def test_daemon_restores_guards_before_discovery_and_releases_every_runtime_resource(self):
        sequence, callbacks, sources, subscriptions = [], [], [], []
        connection = Mock()
        connection.register_object.return_value = 27
        def subscribe(*args):
            subscriptions.append(args[-1]); return len(subscriptions)
        connection.signal_subscribe.side_effect = subscribe
        def source(*args):
            sources.append(args[-1]); return len(sources)
        loop = Mock()
        def run():
            for callback in sources: self.assertTrue(callback())
            for callback in subscriptions: callback()
            for callback in callbacks: callback()
        loop.run.side_effect = run
        glib = SimpleNamespace(MainLoop=lambda: loop, SOURCE_CONTINUE=True, PRIORITY_DEFAULT=0,
            timeout_add_seconds=source, unix_signal_add=source, source_remove=Mock())
        gio = SimpleNamespace(DBusNodeInfo=Gio.DBusNodeInfo, BusNameOwnerFlags=Gio.BusNameOwnerFlags,
            DBusSignalFlags=Gio.DBusSignalFlags, bus_unown_name=Mock())
        def own(*args): callbacks.append(args[-1]); return 9
        gio.bus_own_name_on_connection = own
        bus = SimpleNamespace(connection=connection)
        with patch.multiple(daemon, bindings=Mock(return_value=(gio, glib)), SystemBus=Mock(return_value=bus),
                restore_guard=Mock(side_effect=lambda *_args: sequence.append('guard')),
                NetworkManagerReader=Mock(side_effect=lambda *_args: sequence.append('reader') or Mock()),
                ProviderRegistry=Mock(), RoutingManager=Mock(), DnsResolver=Mock(), MigrationManager=Mock(),
                PolkitAuthorizer=Mock(), DbusService=Mock(), RequestDispatcher=Mock(), ReconciliationWorker=Mock(), NetworkEvents=Mock()):
            daemon.serve(Mock(), Mock(), Mock())
            self.assertEqual(sequence, ['guard', 'reader'])
            worker = daemon.ReconciliationWorker.return_value
            self.assertGreaterEqual(worker.request.call_count, 4)
            daemon.NetworkEvents.call_args.args[0](); self.assertEqual(worker.request.call_args.args, (True,))
            with patch.object(daemon, 'protected_tunnel', return_value={}) as tunnel:
                self.assertEqual(daemon.ProviderRegistry.call_args.args[1](), {}); tunnel.assert_called_once()
            daemon.NetworkEvents.return_value.close.assert_called_once()
            daemon.DbusService.return_value.close.assert_called_once(); worker.close.assert_called_once()
        self.assertEqual(connection.signal_unsubscribe.call_count, 2)
        self.assertEqual(glib.source_remove.call_count, 3)
        connection.unregister_object.assert_called_once_with(27); gio.bus_unown_name.assert_called_once_with(9)


class BootstrapTests(unittest.TestCase):
    def test_entry_accepts_only_root_and_fixed_operations_and_preserves_failure(self):
        with patch.object(entry.os, 'geteuid', return_value=1000): self.assertEqual(entry.main('serve'), 1)
        with patch.object(entry.os, 'geteuid', return_value=0):
            self.assertEqual(entry.main('shell'), 1)
            with patch.multiple(entry, StateStore=Mock(), CommandRunner=Mock(), KernelBackend=Mock(),
                    restore_guard=Mock(), release_all=Mock(), check_empty=Mock(return_value=True)), patch.object(daemon, 'serve') as serve:
                for mode in ('serve', 'restore', 'release', 'check-empty'): self.assertEqual(entry.main(mode), 0)
                serve.assert_called_once(); entry.restore_guard.assert_called_once(); entry.release_all.assert_called_once()
                entry.check_empty.return_value = False; self.assertEqual(entry.main('check-empty'), 2)
                entry.StateStore.side_effect = ValueError('corrupt journal'); self.assertEqual(entry.main('restore'), 1)

    def test_installed_launcher_checks_all_ancestors_and_entries_before_import(self):
        trusted = Path('/fixture/package.py')
        for mode, owner, directory, file, accepted in [(stat.S_IFREG | 0o644, 0, False, True, True),
                (stat.S_IFDIR | 0o755, 0, True, False, True), (stat.S_IFREG | 0o666, 0, False, True, False),
                (stat.S_IFREG | 0o644, 1000, False, True, False), (stat.S_IFLNK | 0o777, 0, False, True, False),
                (stat.S_IFIFO | 0o600, 0, False, False, False)]:
            with patch.object(Path, 'lstat', return_value=SimpleNamespace(st_uid=owner, st_mode=mode)), \
                 patch.object(Path, 'is_dir', return_value=directory), patch.object(Path, 'is_file', return_value=file):
                if accepted: launch.trusted(trusted)
                else:
                    with self.assertRaises(RuntimeError): launch.trusted(trusted)
        with patch.object(launch.os, 'geteuid', return_value=1000): self.assertEqual(launch.main(['serve']), 1)
        with patch.object(launch.os, 'geteuid', return_value=0):
            for arguments in ([], ['serve', 'release'], ['shell']): self.assertEqual(launch.main(arguments), 1)
            original = list(sys.path)
            try:
                with patch.object(launch, 'trusted') as verify, patch.object(Path, 'rglob', return_value=[trusted]), \
                     patch.object(entry, 'main', return_value=0) as run:
                    self.assertEqual(launch.main(['restore']), 0)
                    run.assert_called_once_with('restore'); self.assertEqual(verify.call_count, 4)
                    verify.side_effect = RuntimeError('unsafe installation')
                    self.assertEqual(launch.main(['restore']), 1)
            finally: sys.path[:] = original
        with patch.object(sys, 'argv', ['launch.py']), patch('os.geteuid', return_value=1000):
            with self.assertRaises(SystemExit) as stopped: runpy.run_path(str(Path(launch.__file__)), run_name='__main__')
            self.assertEqual(stopped.exception.code, 1)
