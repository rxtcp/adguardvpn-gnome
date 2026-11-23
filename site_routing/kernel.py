"""Guard-first policy routing with terminal unreachable rules and owned cleanup."""
from .firewall import Firewall
from .kernel_objects import OwnedObject, table_number
from .kernel_plan import prepare_policy
from .kernel_changes import apply_objects
from .policy_inspection import foreign_overlaps
from .legacy_objects import legacy_arguments


class KernelBackend:
    def __init__(self, runner):
        self.runner = runner
        self.firewall = Firewall(runner)

    def snapshot(self) -> dict:
        return {family: {'rule': self.runner.read_ip(family, 'rule', 'show'),
                         'route': self.runner.read_ip(family, 'route', 'show', 'table', 'all')}
                for family in (4, 6)}

    def block(self, addresses, installation_id: str) -> None:
        self.firewall.apply(addresses, {}, installation_id)

    def protect_subset(self, addresses, journal: dict, installation_id: str) -> None:
        blocked = set(addresses)
        allowed = {item.address: item.path.ifindex for row in journal['objects']
                   if (item := OwnedObject.parse(row)).kind == 'route'
                   and item.address not in blocked and self._confirmed(item)}
        self.firewall.apply(set(journal['known']) | blocked, allowed, installation_id)

    def apply(self, assignments: dict, journal: dict, installation_id: str, approved=(), checkpoint=None) -> dict:
        known = sorted(set(journal['known']) | set(assignments))
        snapshots = self.snapshot()
        previous = list(dict.fromkeys(OwnedObject.parse(row) for row in [*journal['objects'], *journal.get('pending_objects', [])]))
        try:
            plan = prepare_policy(assignments, journal, snapshots, previous, approved)
        except (ValueError, RuntimeError):
            self.block(known, installation_id)
            raise
        desired = plan.objects
        stable = {}
        for item in desired:
            if item.kind == 'route' and item in previous and self._present(item, snapshots) and self._confirmed(item):
                stable[item.address] = item.path.ifindex
        self.firewall.apply(known, stable, installation_id)
        pending = {**journal, 'known': known, 'tables': {**journal['tables'], **plan.tables}, 'priority': plan.priority,
                   'pending_objects': [item.json() for item in dict.fromkeys([*previous, *desired])]}
        if checkpoint:
            checkpoint(pending)
        changes = apply_objects(self.runner, previous, desired, snapshots, self._present, self._verified, set(stable))
        protected = set(assignments) | set(changes.failures)
        self.firewall.apply(protected, changes.allowed, installation_id)
        retained = {item.table for item in changes.pending if item.kind != 'block'}
        tables = {key: value for key, value in journal['tables'].items() if value in retained} | plan.tables
        return {'objects': [item.json() for item in changes.objects],
                'pending_objects': [item.json() for item in changes.pending],
                'known': sorted(protected), 'tables': tables, 'priority': plan.priority,
                'failures': plan.failures | changes.failures}

    @staticmethod
    def _present(item: OwnedObject, snapshots: dict) -> bool:
        return any(item.matches(row) for row in snapshots[item.family]['route' if item.kind == 'route' else 'rule'])

    def _verified(self, item: OwnedObject) -> bool:
        path = item.path
        addresses = self.runner.read_ip(item.family, 'address', 'show', 'dev', path.interface)
        if not any(row.get('ifindex') == path.ifindex and 'UP' in row.get('flags', []) and any(
                address.get('local') == path.source and not address.get('tentative') and not address.get('dadfailed') and
                not {'tentative', 'dadfailed'} & set(address.get('flags', [])) for address in row.get('addr_info', [])) for row in addresses):
            return False
        routes = self.runner.read_ip(item.family, 'route', 'get', item.address)
        return bool(routes) and routes[0].get('dev') == path.interface and table_number(routes[0].get('table', 254)) == item.table and routes[0].get('gateway', '') == path.gateway

    def _confirmed(self, item: OwnedObject) -> bool:
        try:
            return self._verified(item)
        except (OSError, RuntimeError, ValueError):
            return False

    def diagnostics(self, addresses) -> list[dict]:
        result = []
        import ipaddress
        for address in addresses:
            try:
                rows = self.runner.read_ip(ipaddress.ip_address(address).version, 'route', 'get', address)
                result.append({'address': address, **{key: rows[0][key] for key in ('dev', 'table', 'gateway', 'type') if rows and key in rows[0]}})
            except (ValueError, RuntimeError):
                result.append({'address': address, 'type': 'unreachable-or-unavailable'})
        return result

    def overlaps(self, addresses, journal) -> list[dict]:
        previous = [OwnedObject.parse(row) for row in [*journal['objects'], *journal.get('pending_objects', [])]]
        result = foreign_overlaps(self.snapshot(), previous, addresses)
        for item in result:
            legacy_arguments(item, 'del')
        return result

    def verify_replacement(self, addresses, journal) -> bool:
        routes = [OwnedObject.parse(row) for row in journal['objects'] if row['kind'] == 'route']
        return bool(addresses) and all(any(item.address == address and self._confirmed(item) for item in routes) for address in addresses)

    def change_legacy(self, entries: list[dict], action: str) -> None:
        for item in entries:
            arguments = legacy_arguments(item, action)
            rows = self.runner.read_ip(item['family'], item['kind'], 'show', *(['table', 'all'] if item['kind'] == 'route' else []))
            present = item['data'] in rows
            if (action == 'del' and present) or (action == 'add' and not present):
                self.runner.write_ip(item['family'], *arguments)
