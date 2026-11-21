"""Exercise the actual archive and installer with a fake GNOME command."""

import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest
import zipfile


PROJECT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(shutil.which('node') and shutil.which('zip'), 'Node.js and zip required')
class ExtensionInstallationTests(unittest.TestCase):
    def test_compile_failure_cannot_disable_or_install_an_existing_extension(self):
        with tempfile.TemporaryDirectory() as folder:
            temporary = Path(folder)
            scripts = temporary / 'scripts'
            scripts.mkdir()
            for name in ('build.mjs', 'install-extension.sh'):
                shutil.copyfile(PROJECT / 'scripts' / name, scripts / name)
            (temporary / 'package.json').write_text(json.dumps({'scripts': {'build': 'node scripts/build.mjs'}}))
            compiler = temporary / 'node_modules/typescript/bin/tsc'
            compiler.parent.mkdir(parents=True)
            compiler.write_text('process.exit(2);\n')
            stale = temporary / 'dist'
            stale.mkdir()
            (stale / 'extension.js').write_text('stale build')
            command = temporary / 'gnome-extensions'
            command.write_text('#!/bin/sh\ntouch "$TEST_CALLED"\n')
            command.chmod(0o755)
            environment = {**os.environ, 'PATH': f'{temporary}:{os.environ["PATH"]}',
                           'TEST_CALLED': str(temporary / 'called')}
            result = subprocess.run(['bash', str(scripts / 'install-extension.sh')],
                                    env=environment, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((temporary / 'called').exists())
            self.assertFalse(stale.exists())

    def test_installer_packages_every_runtime_import_and_keeps_development_files_out(self):
        with tempfile.TemporaryDirectory() as folder:
            temporary = Path(folder)
            command = temporary / 'gnome-extensions'
            command.write_text('''#!/usr/bin/env python3
import json, os, shutil, sys
from pathlib import Path
root = Path(os.environ['TEST_INSTALL_ROOT'])
with (root / 'calls.jsonl').open('a') as log:
    log.write(json.dumps(sys.argv[1:]) + '\\n')
if sys.argv[1] == 'install':
    shutil.copyfile(sys.argv[-1], root / 'extension.zip')
''')
            command.chmod(0o755)
            environment = {**os.environ, 'PATH': f'{temporary}:{os.environ["PATH"]}',
                           'TEST_INSTALL_ROOT': str(temporary), 'TMPDIR': str(temporary)}
            result = subprocess.run(['bash', str(PROJECT / 'scripts/install-extension.sh')],
                                    cwd=temporary, env=environment, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            calls = [json.loads(line) for line in (temporary / 'calls.jsonl').read_text().splitlines()]
            self.assertEqual([call[0] for call in calls], ['info', 'disable', 'install'])
            self.assertFalse(Path(calls[-1][-1]).exists(), 'Temporary archive must be cleaned up')
            with zipfile.ZipFile(temporary / 'extension.zip') as archive:
                names = set(archive.namelist())
                self.assertIn('extension.js', names)
                self.assertIn('metadata.json', names)
                self.assertIn('icons/planet-symbolic.svg', names)
                self.assertEqual(json.loads(archive.read('metadata.json'))['uuid'],
                                 'adguardvpn-toggle@chatgpt.local')
                self.assertFalse(any(name.endswith(('.ts', '.map')) or name.startswith(('tests/', 'node_modules/')) for name in names))
                for name in names:
                    if name.endswith('.js'):
                        for relative in re.findall(r"from ['\"](\.[^'\"]+)['\"]", archive.read(name).decode()):
                            resolved = os.path.normpath(str(Path(name).parent / relative))
                            self.assertIn(resolved, names, f'{name} imports missing module {relative}')

    def test_uninstaller_uses_only_gnome_extension_commands_and_keeps_uuid(self):
        with tempfile.TemporaryDirectory() as folder:
            temporary = Path(folder)
            command = temporary / 'gnome-extensions'
            command.write_text('#!/bin/sh\nprintf "%s %s\\n" "$1" "$2" >> "$TEST_CALLS"\n')
            command.chmod(0o755)
            environment = {**os.environ, 'PATH': f'{temporary}:{os.environ["PATH"]}',
                           'TEST_CALLS': str(temporary / 'calls')}
            result = subprocess.run(['bash', str(PROJECT / 'scripts/uninstall-extension.sh')],
                                    env=environment, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual((temporary / 'calls').read_text().splitlines(), [
                'disable adguardvpn-toggle@chatgpt.local', 'uninstall adguardvpn-toggle@chatgpt.local'])


if __name__ == '__main__':
    unittest.main()
