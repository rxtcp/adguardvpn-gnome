"""Installed bootstrap entry; never run the source checkout as a privileged tool."""
import os
import sys

from .commands import CommandRunner
from .kernel import KernelBackend
from .lifecycle import check_empty, release_all, restore_guard
from .storage import StateStore
from .underlay import change_policy, has_policy, read_config


def restore_underlay(store, runner) -> None:
    try:
        if read_config():
            with store.lock():
                change_policy(runner, remove=False)
    except (OSError, RuntimeError, ValueError):
        print('OpenVPN underlay could not be restored. The marked launcher will refuse activation.', file=sys.stderr)


def main(mode: str) -> int:
    if os.geteuid() != 0:
        print('The Site Routing system component must run as root.', file=sys.stderr)
        return 1
    if mode not in ('serve', 'restore', 'release', 'check-empty', 'apply-underlay', 'remove-underlay'):
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
            restore_underlay(store, runner)
        elif mode in ('apply-underlay', 'remove-underlay'):
            remove = mode == 'remove-underlay'
            with store.lock():
                if bool(read_config()) == remove:
                    advice = ('Disconnect marked OpenVPN and remove its underlay configuration before removing the kernel policy.'
                              if remove else 'Install the private OpenVPN underlay configuration before enabling its kernel policy.')
                    print(advice, file=sys.stderr)
                    return 2
                change_policy(runner, remove=remove)
        elif read_config() or has_policy(runner):
            print('Remove the optional OpenVPN underlay before uninstalling Site Routing.', file=sys.stderr)
            return 2
        elif mode == 'release':
            release_all(store, kernel)
        elif not check_empty(store):
            print('Managed rules or protection remain. Remove rules in settings or explicitly release them.', file=sys.stderr)
            return 2
        return 0
    except (OSError, RuntimeError, ValueError):
        print('Site Routing could not verify a safe state; retained protection must be reviewed.', file=sys.stderr)
        return 1
