"""Plan owned objects while quarantining only unapproved destination overlaps."""
from dataclasses import dataclass
import ipaddress

from .kernel_objects import OwnedObject, choose_priority, choose_tables, table_number
from .models import Assignment
from .policy_inspection import PolicyConflict, foreign_overlaps, signature


@dataclass
class PolicyPlan:
    objects: list[OwnedObject]
    tables: dict[str, int]
    priority: int
    failures: dict[str, dict[str, str]]


def prepare_policy(assignments: dict, journal: dict, snapshots: dict, previous: list,
                   approved) -> PolicyPlan:
    approved_ids = {signature(item['kind'], item['family'], item['data']) for item in approved}
    failures = {}
    candidates = {address: item for address, item in assignments.items() if item.path}
    for overlap in foreign_overlaps(snapshots, previous, candidates):
        if signature(overlap['kind'], overlap['family'], overlap['data']) in approved_ids:
            continue
        network = ipaddress.ip_network(overlap['data'].get('dst', overlap['data'].get('to')), strict=False)
        for address in candidates:
            if ipaddress.ip_address(address) in network:
                failures[address] = {'status': 'conflict', 'detail':
                    'An unapproved destination policy overlaps this IP. Use Check to review its migration diff; this IP stays blocked.'}
    paths = {address: item if address not in failures else Assignment(item.target_key, None)
             for address, item in assignments.items()}
    foreign_rules = [row for family, data in snapshots.items() for row in data['rule']
                    if not any(item.family == family and item.kind != 'route' and item.matches(row) for item in previous)]
    routes = [row for data in snapshots.values() for row in data['route']]
    tables = choose_tables({item.target_key for item in paths.values() if item.path}, journal['tables'], routes, foreign_rules)
    for family, data in snapshots.items():
        if any(table_number(row.get('table', 254)) in journal['tables'].values() and not any(
                item.family == family and item.kind == 'route' and item.matches(row) for item in previous) for row in data['route']):
            raise PolicyConflict('An owned table contains a foreign route; it was not modified.')
    priority = choose_priority(foreign_rules) if paths else 0
    desired = []
    for address, assignment in sorted(paths.items()):
        desired.append(OwnedObject('block', address, priority + 1))
        if assignment.path:
            table = tables[assignment.target_key]
            desired += [OwnedObject('route', address, table=table, path=assignment.path),
                        OwnedObject('lookup', address, priority, table)]
    return PolicyPlan(desired, tables, priority, failures)
