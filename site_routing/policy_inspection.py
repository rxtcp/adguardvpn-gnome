"""Detect unmanaged destination policies without deleting or adopting them."""
import ipaddress
import json

from .kernel_objects import table_number


class PolicyConflict(RuntimeError):
    conflict = True


def signature(kind: str, family: int, row: dict) -> str:
    return json.dumps({'kind': kind, 'family': family, 'data': row}, sort_keys=True)


def foreign_overlaps(snapshots: dict, previous: list, addresses) -> list[dict]:
    matches = []
    destinations = [ipaddress.ip_address(value) for value in addresses]
    for family, snapshot in snapshots.items():
        for kind, rows in snapshot.items():
            for row in rows:
                if any(item.family == family and (item.kind == 'route') == (kind == 'route') and item.matches(row) for item in previous):
                    continue
                destination = row.get('dst', row.get('to', 'all'))
                if destination in ('all', 'default', '0.0.0.0/0', '::/0') or table_number(row.get('table')) == 255:
                    continue
                network = ipaddress.ip_network(destination, strict=False)
                if kind == 'route' and network.prefixlen != network.max_prefixlen:
                    continue
                if any(value.version == family and value in network for value in destinations):
                    matches.append({'kind': kind, 'family': family, 'data': row})
    return matches
