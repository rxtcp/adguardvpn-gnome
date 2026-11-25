"""Apply independent owned destinations; failed writes retain recoverable intent."""
from dataclasses import dataclass

from .kernel_objects import OwnedObject

OBJECT_NAMES = {'route': 'route', 'lookup': 'lookup rule', 'block': 'unreachable rule'}


@dataclass
class ObjectChanges:
    allowed: dict[str, int]
    failures: dict[str, dict[str, str]]
    pending: list[OwnedObject]
    objects: list[OwnedObject]


def apply_objects(runner, previous: list, desired: list, snapshots: dict,
                  present, verified, stable: set[str]) -> ObjectChanges:
    failures, allowed = {}, {}
    added = set()

    def write(item, action):
        if item.address in failures:
            return
        try:
            runner.write_ip(item.family, *item.arguments(action))
            if action == 'add':
                added.add(item)
        except (OSError, RuntimeError, ValueError) as error:
            failures[item.address] = {'status': 'apply-error', 'detail':
                f'IPv{item.family} {OBJECT_NAMES[item.kind]} {action} failed: {error} Known IP protection is retained; reconciliation will retry.'}

    for item in desired:
        if item.kind == 'block' and not present(item, snapshots):
            write(item, 'add')
    for item in desired:
        if item.kind == 'lookup' and item.address in stable and not present(item, snapshots):
            write(item, 'add')
    for item in previous:
        if item not in desired and present(item, snapshots):
            write(item, 'del')
    for item in desired:
        if item.kind != 'block' and item not in added and not present(item, snapshots):
            write(item, 'add')
    for item in desired:
        if item.kind != 'route' or item.address in failures:
            continue
        try:
            if not verified(item):
                raise RuntimeError('Kernel route/interface verification failed.')
            allowed[item.address] = item.path.ifindex
        except (OSError, RuntimeError, ValueError) as error:
            failures[item.address] = {'status': 'apply-error', 'detail':
                f'IPv{item.family} route verification failed: {error} Known IP protection is retained; reconciliation will retry.'}
    pending = [item for item in dict.fromkeys([*previous, *desired]) if item.address in failures]
    return ObjectChanges(allowed, failures, pending, [item for item in desired if item.address not in failures])
