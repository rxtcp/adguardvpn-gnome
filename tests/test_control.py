"""Pure tests; no polkit, root privileges, network, or VPN needed."""

import importlib.util
import io
from pathlib import Path
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch


SOURCE = Path(__file__).resolve().parents[1] / 'helper' / 'control.py'
spec = importlib.util.spec_from_file_location('adguard_control', SOURCE)
control = importlib.util.module_from_spec(spec)
spec.loader.exec_module(control)


class ControllerTests(unittest.TestCase):
    def test_allowed_commands(self):
        self.assertEqual(control.validate_command(['status']), ('status', None))
        self.assertEqual(control.validate_command(['disconnect']), ('disconnect', None))
        self.assertEqual(control.validate_command(['connect', '--fastest']), ('fastest', None))
        self.assertEqual(control.validate_command(['connect', '--location', 'New York']),
                         ('connect', 'New York'))
        self.assertEqual(control.validate_command(['connect', '--location', 'São Paulo']),
                         ('connect', 'São Paulo'))

    def test_rejects_command_injection_and_extra_flags(self):
        for arguments in (
            [], ['connect'], ['connect', '--location', '--help'],
            ['connect', '--location', 'Miami; id'],
            ['connect', '--location', 'Miami\nrm -rf /'],
            ['connect', '--location', '$USER'],
            ['connect', '--location', 'Miami', '--verbose'],
            ['config', 'set-tun-routing-mode', 'SCRIPT'],
            ['update'], ['status', '--debug'],
        ):
            with self.subTest(arguments=arguments):
                with self.assertRaises(ValueError):
                    control.validate_command(arguments)

    def test_systemd_start_uses_fixed_executable_and_arguments(self):
        calls = []

        def fake_invoke(argv, timeout=20):
            calls.append(argv)
            return subprocess.CompletedProcess(argv, 0, 'ok')

        with patch.object(control, 'is_active', return_value=False), \
             patch.object(control, 'invoke', fake_invoke), \
             patch.object(control, 'write_selection'):
            self.assertEqual(control.connect('connect', 'New York'), 0)
            self.assertEqual(control.connect('fastest', None), 0)

        self.assertEqual(calls[0][0], control.SYSTEMD_RUN)
        self.assertEqual(calls[0][-6:], [str(control.CLI), 'connect', '--no-fork',
                                         '-y', '-l', 'New York'])
        self.assertEqual(calls[1][-5:], [str(control.CLI), 'connect',
                                         '--no-fork', '-y', '-f'])
        self.assertNotIn('/bin/sh', calls[0])

    def test_inactive_status_and_disconnect(self):
        with patch.object(control, 'is_active', return_value=False):
            self.assertEqual(control.cli_status(), 0)
            self.assertEqual(control.stop(), 0)

    def test_current_invocation_journal_connection(self):
        current_id = 'a' * 32
        calls = []

        def fake_invoke(argv, timeout=20):
            calls.append(argv)
            if argv[0] == control.SYSTEMCTL:
                return subprocess.CompletedProcess(argv, 0, current_id + '\n')
            return subprocess.CompletedProcess(argv, 0, 'VPNCORE raise_state: VPN_SS_CONNECTED\n')

        with patch.object(control, 'invoke', fake_invoke):
            self.assertEqual(control.journal_connection_state(), 'connected')
        self.assertIn(f'_SYSTEMD_INVOCATION_ID={current_id}', calls[1])
        self.assertEqual(calls[1][0], control.JOURNALCTL)

    def test_status_uses_journal_not_cli_pid(self):
        output = io.StringIO()
        with patch.object(control, 'is_active', return_value=True), \
             patch.object(control, 'journal_connection_state', return_value='connected'), \
             patch.object(control, 'selection_label', return_value='Miami'), \
             redirect_stdout(output):
            self.assertEqual(control.cli_status(), 0)
        self.assertIn('Connected to Miami', output.getvalue())

    def test_disconnect_falls_back_to_systemd(self):
        calls = []

        def fake_invoke(argv, timeout=20):
            calls.append(argv)
            if argv[0] == str(control.CLI):
                return subprocess.CompletedProcess(argv, 1, 'Process is not running')
            return subprocess.CompletedProcess(argv, 0, '')

        with patch.object(control, 'is_active', return_value=True), \
             patch.object(control, 'invoke', fake_invoke):
            self.assertEqual(control.stop(), 0)
        self.assertIn([control.SYSTEMCTL, 'stop', control.UNIT], calls)

    def test_selection_is_root_profile_local(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)
            with patch.object(control, 'PROFILE', path), \
                 patch.object(control, 'SELECTION', path / 'selection.json'):
                control.write_selection('connect', 'Miami')
                self.assertEqual(control.selection_label(), 'Miami')
                control.write_selection('fastest', None)
                self.assertEqual(control.selection_label(), 'FASTEST')


if __name__ == '__main__':
    unittest.main()
