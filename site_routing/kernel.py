"""Guard-first policy routing with terminal unreachable rules and owned cleanup."""
from .firewall import Firewall
from .kernel_objects import OwnedObject, choose_priority, choose_tables, table_number
from .policy_inspection import PolicyConflict, foreign_overlaps, signature
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

    def apply(self, assignments: dict, journal: dict, installation_id: str, approved=(), checkpoint=None) -> dict:
        known = sorted(set(journal['known']) | set(assignments))
        snapshots = self.snapshot()
        previous = list(dict.fromkeys(OwnedObject.parse(row) for row in [*journal['objects'], *journal.get('pending_objects', [])]))
        try:
            approved_ids = {signature(item['kind'], item['family'], item['data']) for item in approved}
            overlaps = foreign_overlaps(snapshots, previous, assignments)
            if any(signature(item['kind'], item['family'], item['data']) not in approved_ids for item in overlaps):
                raise PolicyConflict('Existing destination policies overlap. Review the migration diff before changing them.')
            foreign_rules = [row for family, data in snapshots.items() for row in data['rule']
                             if not any(item.family == family and item.kind != 'route' and item.matches(row) for item in previous)]
            routes = [row for data in snapshots.values() for row in data['route']]
            tables = choose_tables({item.target_key for item in assignments.values() if item.path}, journal['tables'], routes, foreign_rules)
            for family, data in snapshots.items():
                if any(table_number(row.get('table', 254)) in journal['tables'].values() and not any(
                        item.family == family and item.kind == 'route' and item.matches(row) for item in previous) for row in data['route']):
                    raise PolicyConflict('An owned table contains a foreign route; it was not modified.')
            priority = choose_priority(foreign_rules) if assignments else 0
        except (ValueError, RuntimeError):
            self.block(known, installation_id)
            raise
        desired = []
        for address, assignment in sorted(assignments.items()):
            desired.append(OwnedObject('block', address, priority + 1))
            if assignment.path:
                table = tables[assignment.target_key]
                desired += [OwnedObject('route', address, table=table, path=assignment.path),
                            OwnedObject('lookup', address, priority, table)]
        stable = {}
        for item in desired:
            if item.kind == 'route' and item in previous and self._present(item, snapshots) and self._verified(item):
                stable[item.address] = item.path.ifindex
        self.firewall.apply(known, stable, installation_id)
        pending = {**journal, 'known': known, 'tables': tables, 'priority': priority,
                   'pending_objects': [item.json() for item in dict.fromkeys([*previous, *desired])]}
        if checkpoint:
            checkpoint(pending)
        for item in desired:
            if item.kind == 'block' and not self._present(item, snapshots):
                self.runner.write_ip(item.family, *item.arguments('add'))
        for item in previous:
            if item not in desired and self._present(item, snapshots):
                self.runner.write_ip(item.family, *item.arguments('del'))
        for item in desired:
            if item.kind != 'block' and not self._present(item, snapshots):
                self.runner.write_ip(item.family, *item.arguments('add'))
        allowed = {}
        for item in desired:
            if item.kind == 'route':
                if not self._verified(item):
                    raise RuntimeError('Kernel route verification failed; protection remains blocked.')
                allowed[item.address] = item.path.ifindex
        self.firewall.apply(assignments, allowed, installation_id)
        return {'objects': [item.json() for item in desired], 'pending_objects': [],
                'known': sorted(assignments), 'tables': tables, 'priority': priority}

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
        return bool(addresses) and all(any(item.address == address and self._verified(item) for item in routes) for address in addresses)

    def change_legacy(self, entries: list[dict], action: str) -> None:
        for item in entries:
            arguments = legacy_arguments(item, action)
            rows = self.runner.read_ip(item['family'], item['kind'], 'show', *(['table', 'all'] if item['kind'] == 'route' else []))
            present = item['data'] in rows
            if (action == 'del' and present) or (action == 'add' and not present):
                self.runner.write_ip(item['family'], *arguments)
