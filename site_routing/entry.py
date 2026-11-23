"""Installed bootstrap entry; never run the source checkout as a privileged tool."""
import os
import sys

from .commands import CommandRunner
from .kernel import KernelBackend
from .lifecycle import check_empty, release_all, restore_guard
from .storage import StateStore


def main(mode: str) -> int:
    if os.geteuid() != 0:
        print('The Site Routing system component must run as root.', file=sys.stderr)
        return 1
    if mode not in ('serve', 'restore', 'release', 'check-empty'):
        print('Unsupported Site Routing service operation.', file=sys.stderr)
        return 1
    try:
        store, runner = StateStore(), CommandRunner()
        kernel = KernelBackend(runner)
        if mode == 'serve':
            from .daemon import serve
            serve(store, kernel, runner)
        elif mode == 'restore':
            restore_guard(store, kernel)
        elif mode == 'release':
            release_all(store, kernel)
        elif not check_empty(store):
            print('Managed rules or protection remain. Remove rules in settings or explicitly release them.', file=sys.stderr)
            return 2
        return 0
    except (OSError, RuntimeError, ValueError):
        print('Site Routing could not verify a safe state; retained protection must be reviewed.', file=sys.stderr)
        return 1
