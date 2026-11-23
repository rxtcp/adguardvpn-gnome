"""Find only the TUN descriptors owned by the verified protected systemd process."""
from pathlib import Path
import re

from .security import verify_path

CONTROL = Path('/usr/libexec/adguardvpn-gnome/control')
CLI = Path('/usr/libexec/adguardvpn-gnome/adguardvpn-cli')
SYSTEMD = 'org.freedesktop.systemd1'


def protected_tunnel(bus, runner) -> dict:
    if not CONTROL.exists() or not CLI.exists():
        return {'installed': False}
    try:
        verify_path(CONTROL)
        verify_path(CLI)
        output = runner.run([str(CONTROL), 'status'])
        if not re.search(r'^Connected to ', output, re.M):
            return {'installed': True, 'connected': False, 'interfaces': []}
        unit = bus.call(SYSTEMD, '/org/freedesktop/systemd1', SYSTEMD + '.Manager', 'GetUnit',
                        '(s)', ('adguardvpn-gnome.service',))[0]
        pid = bus.properties(SYSTEMD, unit, SYSTEMD + '.Service')['MainPID']
        if type(pid) is not int or pid <= 0:
            raise ValueError('No protected AdGuard process.')
        process = Path('/proc') / str(pid)
        if process.stat().st_uid != 0 or (process / 'exe').resolve(strict=True) != CLI:
            raise ValueError('Protected AdGuard executable does not match.')
        interfaces = set()
        for descriptor in list((process / 'fdinfo').iterdir())[:4096]:
            with descriptor.open(encoding='utf-8') as handle:
                contents = handle.read(32768)
            match = re.search(r'^iff:\s*([A-Za-z0-9_.][A-Za-z0-9_.:@-]{0,14})\s*$', contents, re.M)
            if match:
                interfaces.add(match[1])
        return {'installed': True, 'connected': True, 'interfaces': sorted(interfaces)}
    except (OSError, RuntimeError, ValueError, KeyError):
        return {'installed': True, 'connected': False, 'interfaces': []}
