#!/usr/bin/python3
"""Invoke only through /usr/bin/python3 -I -B at the protected installed path."""
import os
from pathlib import Path
import stat
import sys

ROOT = Path('/usr/libexec/adguardvpn-site-routing')


def trusted(path: Path) -> None:
    for current in (*reversed(path.parents), path):
        if current == Path('/'):
            continue
        metadata = current.lstat()
        if metadata.st_uid != 0 or metadata.st_mode & 0o022 or stat.S_ISLNK(metadata.st_mode):
            raise RuntimeError('Untrusted Site Routing installation.')
    if not (path.is_dir() or path.is_file()):
        raise RuntimeError('Invalid Site Routing installation entry.')


def main(arguments: list[str]) -> int:
    fixed = len(arguments) == 1 and arguments[0] in (
        'serve', 'restore', 'release', 'check-empty', 'apply-underlay', 'remove-underlay')
    openvpn = len(arguments) == 2 and arguments[0] == 'openvpn-underlay'
    if os.geteuid() != 0 or not (fixed or openvpn):
        print('Use the installed Site Routing system component with a fixed operation.', file=sys.stderr)
        return 1
    try:
        trusted(Path(__file__))
        trusted(ROOT)
        trusted(ROOT / 'site_routing')
        for entry in ROOT.rglob('*'):
            trusted(entry)
        sys.path.insert(0, str(ROOT))
        if openvpn:
            from site_routing.underlay import launch_mark
            return launch_mark(arguments[1])
        from site_routing.entry import main as run
        return run(arguments[0])
    except (OSError, RuntimeError):
        print('Refused an untrusted Site Routing installation.', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
