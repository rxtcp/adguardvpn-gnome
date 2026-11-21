"""Characterization of the privileged boundary, without executing root commands."""

from contextlib import redirect_stderr, redirect_stdout
import io
from pathlib import Path
import runpy
import stat
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import mock_open, patch

from test_control import control


class PrivilegedBoundaryTests(unittest.TestCase):
    def test_location_validation_boundaries(self):
        for name in (None, 7, '', 'a' * 101, ' Miami', 'Miami ', '-f',
                     'Mi\nami', 'Mi\x7fami', '$x', '`x`', 'a\\b', 'a"b', 'a;b'):
            with self.subTest(name=name):
                self.assertFalse(control.valid_location(name))
        self.assertTrue(control.valid_location('a' * 100))

    def test_protected_paths_reject_symlinks_ownership_and_writable_ancestors(self):
        for mode, uid in ((stat.S_IFLNK | 0o755, 0), (stat.S_IFDIR | 0o777, 0),
                          (stat.S_IFDIR | 0o755, 1000)):
            with self.subTest(mode=mode, uid=uid), \
                 patch.object(Path, 'lstat', return_value=SimpleNamespace(st_mode=mode, st_uid=uid)):
                with self.assertRaisesRegex(RuntimeError, 'Untrusted'):
                    control.ensure_protected(Path('/trusted/child'), directory=True)

    def test_protected_path_types_and_private_permissions(self):
        for mode, directory, private, expected in (
            (stat.S_IFREG | 0o644, True, False, 'Not a directory'),
            (stat.S_IFDIR | 0o755, False, False, 'Not a regular file'),
            (stat.S_IFDIR | 0o755, True, True, 'Private directory'),
        ):
            with self.subTest(mode=mode), \
                 patch.object(Path, 'lstat', return_value=SimpleNamespace(st_mode=mode, st_uid=0)):
                with self.assertRaisesRegex(RuntimeError, expected):
                    control.ensure_protected(Path('/trusted'), directory=directory, private=private)
        for mode, directory in ((stat.S_IFREG | 0o755, False), (stat.S_IFDIR | 0o700, True)):
            with patch.object(Path, 'lstat', return_value=SimpleNamespace(st_mode=mode, st_uid=0)):
                control.ensure_protected(Path('/trusted'), directory=directory, private=directory)

    def test_invoke_uses_fixed_environment_closed_stdin_and_timeout(self):
        with patch.object(control.subprocess, 'run') as run:
            control.invoke(['/fixed', 'status'], 6)
        run.assert_called_once_with(['/fixed', 'status'], env=control.environment(),
                                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, text=True, timeout=6, check=False)
        self.assertEqual(control.environment()['HOME'], str(control.PROFILE))
        self.assertEqual(control.environment()['PATH'], '/usr/sbin:/usr/bin:/sbin:/bin')

    def test_service_activity_uses_exit_code_and_short_timeout(self):
        for code in (0, 1, 3):
            with self.subTest(code=code), patch.object(control, 'invoke',
                    return_value=subprocess.CompletedProcess([], code)) as invoke:
                self.assertEqual(control.is_active(), code == 0)
                invoke.assert_called_once_with([control.SYSTEMCTL, 'is-active', '--quiet', control.UNIT], 5)

    def test_executable_entry_refuses_unprivileged_invocation(self):
        with patch('os.geteuid', return_value=1000), patch('sys.argv', ['control', 'status']), \
             redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as exit_status:
            runpy.run_path(str(Path(control.__file__)), run_name='__main__')
        self.assertEqual(exit_status.exception.code, 1)

    def test_journal_requires_a_valid_current_invocation(self):
        for code, output in ((1, 'a' * 32), (0, ''), (0, '../other'), (0, 'g' * 32)):
            with self.subTest(output=output), patch.object(control, 'invoke',
                    return_value=subprocess.CompletedProcess([], code, output)) as invoke:
                self.assertEqual(control.journal_connection_state(), 'unknown')
                self.assertEqual(invoke.call_count, 1)

    def test_journal_handles_failure_disconnected_and_missing_events(self):
        for code, output, expected in ((1, 'VPN_SS_CONNECTED', 'unknown'),
                (0, 'VPN_SS_DISCONNECTED', 'disconnected'), (0, '', 'unknown')):
            with self.subTest(output=output), patch.object(control, 'invoke', side_effect=[
                    subprocess.CompletedProcess([], 0, 'a' * 32),
                    subprocess.CompletedProcess([], code, output)]):
                self.assertEqual(control.journal_connection_state(), expected)

    def test_selection_corruption_and_invalid_shapes_do_not_invent_a_location(self):
        with tempfile.TemporaryDirectory() as folder:
            selection = Path(folder) / 'selection.json'
            with patch.object(control, 'SELECTION', selection):
                self.assertIsNone(control.selection_label())
                for content in ('{broken', 'null', '[]', '{"mode":"connect","location":"--bad"}',
                                '{"mode":"other"}'):
                    with self.subTest(content=content):
                        selection.write_text(content)
                        self.assertIsNone(control.selection_label())

    def test_failed_atomic_replace_keeps_old_selection_and_removes_temporary_file(self):
        with tempfile.TemporaryDirectory() as folder:
            profile = Path(folder)
            selection = profile / 'selection.json'
            selection.write_text('old')
            with patch.object(control, 'PROFILE', profile), patch.object(control, 'SELECTION', selection), \
                 patch.object(control.os, 'replace', side_effect=OSError('failed')):
                with self.assertRaises(OSError):
                    control.write_selection('connect', 'Miami')
            self.assertEqual(selection.read_text(), 'old')
            self.assertEqual(list(profile.iterdir()), [selection])

    def test_status_is_never_inferred_from_service_activity_alone(self):
        for state, location, expected in (('unknown', 'Miami', 'status unavailable'),
                ('disconnected', 'Miami', 'Disconnected'), ('connected', None, 'status unavailable')):
            output = io.StringIO()
            with self.subTest(state=state, location=location), \
                 patch.object(control, 'is_active', return_value=True), \
                 patch.object(control, 'journal_connection_state', return_value=state), \
                 patch.object(control, 'selection_label', return_value=location), redirect_stdout(output):
                self.assertEqual(control.cli_status(), 0)
                self.assertIn(expected, output.getvalue())

    def test_failed_stop_reports_error_only_if_service_remains_active(self):
        for active, expected in ((True, 1), (False, 0)):
            output = io.StringIO()
            with self.subTest(active=active), patch.object(control, 'is_active', side_effect=[True, active]), \
                 patch.object(control, 'invoke', side_effect=[subprocess.CompletedProcess([], 0, ''),
                    subprocess.CompletedProcess([], 1, '')]), redirect_stderr(output), redirect_stdout(output):
                self.assertEqual(control.stop(), expected)
                if active:
                    self.assertIn('systemd stop failed', output.getvalue())

    def test_connect_does_not_start_after_failed_stop(self):
        with patch.object(control, 'is_active', return_value=True), \
             patch.object(control, 'stop', return_value=1), patch.object(control, 'invoke') as invoke, \
             patch.object(control, 'write_selection') as selection:
            self.assertEqual(control.connect('connect', 'Miami'), 1)
            invoke.assert_not_called()
            selection.assert_not_called()

    def test_failed_systemd_start_reports_diagnostic_and_fixed_hardening(self):
        for message in ('denied', ''):
            output = io.StringIO()
            with patch.object(control, 'is_active', return_value=False), patch.object(control, 'write_selection'), \
                 patch.object(control, 'invoke', return_value=subprocess.CompletedProcess([], 1, message)) as invoke, \
                 redirect_stderr(output):
                self.assertEqual(control.connect('fastest', None), 1)
                self.assertIn(message or 'systemd could not start', output.getvalue())
                self.assertIn('--property=NoNewPrivileges=yes', invoke.call_args.args[0])
                self.assertIn('--property=UMask=0077', invoke.call_args.args[0])

    def test_nonroot_main_never_dispatches(self):
        with patch.object(control.os, 'geteuid', return_value=1000), \
             patch.object(control, 'validate_command') as validate, redirect_stderr(io.StringIO()):
            self.assertEqual(control.main(['status']), 1)
            validate.assert_not_called()

    def test_main_checks_all_protected_paths_and_serializes_mutations(self):
        for arguments, target in ((['status'], 'cli_status'), (['disconnect'], 'stop'),
                                  (['connect', '--fastest'], 'connect')):
            with self.subTest(arguments=arguments), patch.object(control.os, 'geteuid', return_value=0), \
                 patch.object(control, 'ensure_protected') as protect, \
                 patch('builtins.open', mock_open()), patch.object(control.fcntl, 'flock') as lock, \
                 patch.object(control, target, return_value=42):
                self.assertEqual(control.main(arguments), 42)
                self.assertEqual(protect.call_count, 4)
                self.assertEqual(lock.call_count, 0 if target == 'cli_status' else 1)

    def test_main_reports_validation_filesystem_and_timeout_errors(self):
        for error in (ValueError('bad'), OSError('missing'), RuntimeError('untrusted'),
                      subprocess.TimeoutExpired('test', 1)):
            output = io.StringIO()
            with self.subTest(error=error), patch.object(control.os, 'geteuid', return_value=0), \
                 patch.object(control, 'ensure_protected', side_effect=error), redirect_stderr(output):
                self.assertEqual(control.main(['status']), 1)
                self.assertIn('AdGuard VPN helper:', output.getvalue())


if __name__ == '__main__':
    unittest.main()
