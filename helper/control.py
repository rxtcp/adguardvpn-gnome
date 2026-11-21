#!/usr/bin/python3
"""Polkit-authorized, deliberately narrow AdGuard VPN controller.

Installed root-owned at /usr/libexec/adguardvpn-gnome/control.
Never invoke this source-tree copy with elevated privileges.
"""

import fcntl
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile


ROOT = Path('/usr/libexec/adguardvpn-gnome')
CLI = ROOT / 'adguardvpn-cli'
PROFILE = Path('/var/lib/adguardvpn-gnome')
UNIT = 'adguardvpn-gnome.service'
SYSTEMCTL = '/usr/bin/systemctl'
SYSTEMD_RUN = '/usr/bin/systemd-run'
JOURNALCTL = '/usr/bin/journalctl'
LOCK = PROFILE / 'control.lock'
SELECTION = PROFILE / 'selection.json'


def valid_location(name):
    """Location is one CLI argument, never a shell command or option."""
    return (isinstance(name, str) and 1 <= len(name) <= 100 and
            name == name.strip() and not name.startswith('-') and
            all(ch.isprintable() and ch not in '$`\\";' for ch in name))


def validate_command(args):
    if args == ['status']:
        return ('status', None)
    if args == ['disconnect']:
        return ('disconnect', None)
    if args == ['connect', '--fastest']:
        return ('fastest', None)
    if len(args) == 3 and args[:2] == ['connect', '--location'] and valid_location(args[2]):
        return ('connect', args[2])
    raise ValueError('Allowed: status | disconnect | connect --fastest | connect --location CITY')


def ensure_protected(path, directory=False, private=False):
    """Refuse writable/symlinked executable ancestors and profile paths."""
    for current in [*reversed(path.parents), path]:
        # Skip '/' itself, but inspect every other component.
        if current == Path('/'):
            continue
        metadata = current.lstat()
        if stat.S_ISLNK(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_mode & 0o022:
            raise RuntimeError(f'Untrusted ownership or permissions: {current}')
    mode = path.lstat().st_mode
    if directory and not stat.S_ISDIR(mode):
        raise RuntimeError(f'Not a directory: {path}')
    if not directory and not stat.S_ISREG(mode):
        raise RuntimeError(f'Not a regular file: {path}')
    if private and mode & 0o077:
        raise RuntimeError(f'Private directory must not be group/world accessible: {path}')


def environment():
    return {
        'HOME': str(PROFILE),
        'XDG_CONFIG_HOME': str(PROFILE / 'config'),
        'XDG_DATA_HOME': str(PROFILE / 'data'),
        'XDG_CACHE_HOME': str(PROFILE / 'cache'),
        'USER': 'root',
        'LOGNAME': 'root',
        'LANG': 'C.UTF-8',
        'PATH': '/usr/sbin:/usr/bin:/sbin:/bin',
    }


def invoke(argv, timeout=20):
    return subprocess.run(argv, env=environment(), stdin=subprocess.DEVNULL,
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                          text=True, timeout=timeout, check=False)


def is_active():
    return invoke([SYSTEMCTL, 'is-active', '--quiet', UNIT], 5).returncode == 0


def journal_connection_state():
    """Use the current systemd invocation, not the CLI's background PID file.

    `connect --no-fork` can reach VPN_SS_CONNECTED without creating the PID
    file expected by a separate `adguardvpn-cli status` process.
    """
    invocation = invoke([SYSTEMCTL, 'show', UNIT, '--property=InvocationID',
                         '--value'], 5)
    invocation_id = invocation.stdout.strip()
    if invocation.returncode != 0 or not re.fullmatch(r'[0-9a-fA-F]{32}', invocation_id):
        return 'unknown'
    logs = invoke([JOURNALCTL, '--no-pager', '--output=cat', '--lines=1',
                   '--grep=VPN_SS_(CONNECTED|DISCONNECTED)',
                   f'_SYSTEMD_INVOCATION_ID={invocation_id}'], 8)
    if logs.returncode != 0:
        return 'unknown'
    if 'VPN_SS_DISCONNECTED' in logs.stdout:
        return 'disconnected'
    if 'VPN_SS_CONNECTED' in logs.stdout:
        return 'connected'
    return 'unknown'


def write_selection(mode, location):
    selection = {'mode': mode, 'location': location if mode == 'connect' else None}
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8',
                                         prefix='.selection-', suffix='.json',
                                         dir=PROFILE, delete=False) as handle:
            temporary = handle.name
            json.dump(selection, handle)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, SELECTION)
    finally:
        if temporary and os.path.exists(temporary):
            os.unlink(temporary)


def selection_label():
    try:
        with SELECTION.open('r', encoding='utf-8') as handle:
            selection = json.load(handle)
        if selection.get('mode') == 'fastest':
            return 'FASTEST'
        if selection.get('mode') == 'connect' and valid_location(selection.get('location')):
            return selection['location']
    except (OSError, ValueError, TypeError, AttributeError):
        pass
    return None


def cli_status():
    if not is_active():
        print('Disconnected')
        return 0
    state = journal_connection_state()
    if state == 'connected':
        location = selection_label()
        print(f'Connected to {location} in TUN mode' if location else 'VPN active, but status unavailable')
    elif state == 'disconnected':
        print('Disconnected')
    else:
        print('VPN active, but status unavailable')
    return 0


def stop():
    if not is_active():
        print('Disconnected')
        return 0
    # The CLI's PID-file-based disconnect may not see our --no-fork process.
    # Try graceful CLI control first, then always ask systemd to stop the
    # service; SIGTERM was observed to cleanly release TUN and DNS on Fedora.
    result = invoke([str(CLI), 'disconnect'], 20)
    stopped = invoke([SYSTEMCTL, 'stop', UNIT], 20)
    # AdGuard may exit as soon as disconnect completes; --collect can then
    # unload the transient unit before systemctl stop reaches it.
    if stopped.returncode != 0 and is_active():
        print(stopped.stdout.strip() or 'systemd stop failed', file=sys.stderr)
        return 1
    if result.returncode != 0:
        print('AdGuard CLI had no background PID; stopped the systemd service instead.')
    print('Disconnected')
    return 0


def connect(mode, location):
    if is_active() and stop() != 0:
        return 1
    # Persist intent before the asynchronous unit can report CONNECTED.
    write_selection(mode, location)
    # Transient systemd service: fixed unit name and fixed privileged binary.
    # The caller controls only an independently validated location argument.
    argv = [SYSTEMD_RUN, '--system', f'--unit={UNIT}', '--collect',
            '--service-type=exec', '--property=Restart=no',
            '--property=NoNewPrivileges=yes',
            '--property=UMask=0077']
    for name in ('HOME', 'XDG_CONFIG_HOME', 'XDG_DATA_HOME',
                 'XDG_CACHE_HOME', 'LANG', 'PATH'):
        argv.append(f'--setenv={name}={environment()[name]}')
    argv += [str(CLI), 'connect', '--no-fork', '-y']
    if mode == 'fastest':
        argv.append('-f')
    else:
        argv += ['-l', location]
    result = invoke(argv, 30)
    if result.returncode != 0:
        print(result.stdout.strip() or 'systemd could not start AdGuard VPN', file=sys.stderr)
        return 1
    print('Connection requested; checking status…')
    return 0


def main(args):
    if os.geteuid() != 0:
        print('This controller must be started by pkexec.', file=sys.stderr)
        return 1
    try:
        action, location = validate_command(args)
        ensure_protected(ROOT, directory=True)
        ensure_protected(Path(__file__))
        ensure_protected(CLI)
        ensure_protected(PROFILE, directory=True, private=True)
        if action == 'status':
            return cli_status()
        # Serialize concurrent clicks from the GNOME session.
        with open(LOCK, 'a', encoding='utf-8') as lock_file:
            fcntl.flock(lock_file, fcntl.LOCK_EX)
            return stop() if action == 'disconnect' else connect(action, location)
    except (OSError, RuntimeError, subprocess.TimeoutExpired, ValueError) as exc:
        print(f'AdGuard VPN helper: {exc}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
