"""Execute a sandbox copy with inert commands; never install or release host rules."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class UninstallationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(dir=ROOT / '.tmp')
        self.addCleanup(temporary.cleanup)
        self.folder = Path(temporary.name)
        self.log = self.folder / 'commands.jsonl'
        self.protected = self.folder / 'protected'
        self.protected.mkdir()
        (self.protected / 'launch.py').touch()
        source = (ROOT / 'scripts/uninstall-site-routing.sh').read_text()
        source = source.replace('${EUID}', '0')  # Exercise argument/sequence logic without elevation.
        destinations = {'/usr/libexec/adguardvpn-site-routing': str(self.protected),
            '/var/lib/adguardvpn-site-routing': str(self.folder / 'state'),
            '/etc/systemd/system': str(self.folder / 'systemd'),
            '/usr/share/dbus-1': str(self.folder / 'dbus'), '/usr/share/polkit-1': str(self.folder / 'polkit')}
        for before, after in destinations.items(): source = source.replace(before, after)
        for command in ('systemctl', 'python3', 'rmdir', 'rm'):
            executable = self.folder / command
            executable.write_text(f'#!{sys.executable}\n' + '''import json, os, sys
from pathlib import Path
name = Path(sys.argv[0]).name
with open(os.environ['FAKE_LOG'], 'a') as log: log.write(json.dumps([name, *sys.argv[1:]]) + '\\n')
if name == 'python3':
    operation = sys.argv[-1]
    if operation == '-':
        sys.stdin.read()
        sys.exit(int(os.environ.get('FAKE_TRUST', '0')))
    sys.exit(int(os.environ.get('FAKE_RELEASE' if operation == 'release' else 'FAKE_EMPTY', '0')))
''')
            executable.chmod(0o755)
            source = source.replace('/usr/bin/' + command, str(executable))
        self.script = self.folder / 'uninstall.sh'
        self.script.write_text(source)

    def run_script(self, *arguments, **environment):
        if self.log.exists(): self.log.unlink()
        result = subprocess.run(['bash', str(self.script), *arguments], text=True, capture_output=True,
            env={**os.environ, 'FAKE_LOG': str(self.log), **environment})
        calls = [json.loads(line) for line in self.log.read_text().splitlines()] if self.log.exists() else []
        return result, calls

    def test_untrusted_launcher_is_refused_before_executing_or_stopping_any_service(self):
        result, calls = self.run_script(FAKE_TRUST='1')
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(calls)
        self.assertTrue(all(call[0] == 'python3' and call[-1] == '-' for call in calls))

    def test_nonempty_rules_abort_removal_and_restart_the_manager(self):
        result, calls = self.run_script(FAKE_EMPTY='2')
        self.assertEqual(result.returncode, 1)
        self.assertEqual([call[1:] for call in calls if call[0] == 'systemctl'], [
            ['stop', 'adguardvpn-site-routing.service'], ['start', 'adguardvpn-site-routing.service']])
        self.assertFalse(any(call[0] == 'rm' for call in calls))
        self.assertIn('Remove rules in settings', result.stderr)

    def test_failed_release_retains_guard_and_success_removes_only_owned_integration(self):
        result, calls = self.run_script('--release-rules', FAKE_RELEASE='1')
        self.assertEqual(result.returncode, 1)
        self.assertIn('guards and service files are retained', result.stderr)
        self.assertFalse(any('disable' in call or call[0] == 'rm' for call in calls))
        result, calls = self.run_script('--release-rules')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('ordinary system routing', result.stdout)
        self.assertEqual(calls[-1], ['systemctl', 'daemon-reload'])
        self.assertFalse(any(str(self.folder / 'state') in call for call in calls if call[0] == 'rm'))
        self.assertTrue(all(str(self.folder) in path or path in ('rm', '-f', '-rf', '--')
                            for call in calls if call[0] == 'rm' for path in call))

    def test_already_removed_and_incomplete_installation_are_distinguished(self):
        (self.protected / 'launch.py').unlink()
        result, calls = self.run_script()
        self.assertEqual(result.returncode, 0); self.assertEqual(calls, [])
        unit = self.folder / 'systemd/adguardvpn-site-routing.service'
        unit.parent.mkdir(); unit.touch()
        result, calls = self.run_script()
        self.assertEqual(result.returncode, 1); self.assertEqual(calls, [])
        self.assertIn('restore the installation', result.stderr)
        result, calls = self.run_script('--unknown')
        self.assertEqual(result.returncode, 2); self.assertEqual(calls, [])
