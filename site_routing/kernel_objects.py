"""Owned route/rule records and allocation after inspecting the live RPDB."""
from dataclasses import asdict, dataclass
import ipaddress

from .models import NetworkPath

PROTOCOL = 196


def table_number(value) -> int:
    return {'main': 254, 'local': 255, 'default': 253}.get(value, int(value) if str(value).isdigit() else -1)


def host_prefix(address: str) -> str:
    parsed = ipaddress.ip_address(address)
    return f'{parsed}/{parsed.max_prefixlen}'


@dataclass(frozen=True)
class OwnedObject:
    kind: str
    address: str
    priority: int = 0
    table: int = 0
    path: NetworkPath | None = None

    def __post_init__(self):
        if self.kind not in ('route', 'lookup', 'block') or not isinstance(self.address, str):
            raise ValueError('Invalid owned kernel object.')
        ipaddress.ip_address(self.address)
        if self.kind != 'route' and (type(self.priority) is not int or not 1 <= self.priority <= 32765):
            raise ValueError('Invalid rule priority.')
        if self.kind != 'block' and (type(self.table) is not int or not 40000 <= self.table <= 49999):
            raise ValueError('Invalid owned routing table.')
        if self.kind == 'route' and not isinstance(self.path, NetworkPath):
            raise ValueError('A verified route path is required.')

    @property
    def family(self) -> int:
        return ipaddress.ip_address(self.address).version

    @classmethod
    def parse(cls, value: dict) -> 'OwnedObject':
        try:
            data = dict(value)
            if data.get('path') is not None:
                data['path'] = NetworkPath(**data['path'])
            return cls(**data)
        except (TypeError, KeyError) as error:
            raise ValueError('Invalid kernel ownership journal.') from error

    def json(self) -> dict:
        return asdict(self)

    def arguments(self, action: str) -> tuple[str, ...]:
        if self.kind == 'route':
            path = self.path
            result = ['route', action, 'table', str(self.table), host_prefix(self.address)]
            if path.gateway:
                result += ['via', path.gateway]
            result += ['dev', path.interface, 'src', path.source]
            if path.gateway:
                result.append('onlink')
            return (*result, 'proto', str(PROTOCOL))
        result = ['rule', action]
        if self.kind == 'block':
            result.append('unreachable')
        result += ['priority', str(self.priority), 'to', host_prefix(self.address)]
        if self.kind == 'lookup':
            result += ['table', str(self.table)]
        return (*result, 'protocol', str(PROTOCOL))

    def matches(self, value: dict) -> bool:
        destination = value.get('dst', value.get('to', 'all'))
        if destination == 'all' or str(value.get('protocol')) != str(PROTOCOL):
            return False
        try:
            if ipaddress.ip_network(destination, strict=False) != ipaddress.ip_network(host_prefix(self.address)):
                return False
        except ValueError:
            return False
        if self.kind == 'route':
            return table_number(value.get('table', 254)) == self.table and value.get('dev') == self.path.interface and value.get('prefsrc', value.get('src')) == self.path.source and value.get('gateway', '') == self.path.gateway and not value.get('multipath')
        if value.get('src', 'all') != 'all' or any(key in value for key in ('fwmark', 'iif', 'oif', 'uidrange', 'ipproto', 'sport', 'dport')) or value.get('flags'):
            return False
        action = value.get('action', value.get('type', 'lookup'))
        return value.get('priority') == self.priority and (action == 'unreachable' if self.kind == 'block' else table_number(value.get('table')) == self.table)


def choose_priority(rules: list[dict]) -> int:
    priorities = [int(rule['priority']) for rule in rules if int(rule.get('priority', 0)) > 0]
    priority = min(priorities, default=32766) - 2
    if priority < 1 or any(int(rule.get('priority', -1)) == 0 and table_number(rule.get('table')) != 255 for rule in rules):
        raise RuntimeError('No safe policy-rule priority is available; known IPs remain blocked.')
    return priority


def choose_tables(keys: set[str], previous: dict, routes: list[dict], rules: list[dict]) -> dict:
    if any(type(value) is not int or not 40000 <= value <= 49999 for value in previous.values()) or len(set(previous.values())) != len(previous):
        raise ValueError('Invalid table ownership journal.')
    used = {table_number(row.get('table')) for row in [*routes, *rules]} | set(previous.values())
    tables = {key: value for key, value in previous.items() if key in keys}
    for key in sorted(keys - set(tables)):
        available = next((value for value in range(40000, 50000) if value not in used), None)
        if available is None:
            raise RuntimeError('No unused Site Routing table is available.')
        tables[key] = available
        used.add(available)
    return tables
