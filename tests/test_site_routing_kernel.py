import copy
import unittest

from site_routing.firewall import guard_script
from site_routing.kernel import KernelBackend
from site_routing.kernel_objects import OwnedObject, choose_priority, choose_tables
from site_routing.models import Assignment
from site_routing_fakes import PATH4, PATH6

INSTALLATION = '00000000-0000-4000-8000-000000000010'


class KernelFixture:
    def __init__(self):
        self.events = []
        self.tables = []
        self.current = {4: {'rule': [{'priority': 0, 'table': 'local'}, {'priority': 1000, 'table': 880}, {'priority': 32766, 'table': 'main'}], 'route': []},
                        6: {'rule': [{'priority': 0, 'table': 'local'}, {'priority': 32766, 'table': 'main'}], 'route': []}}
        self.route_error = False

    def read_ip(self, family, *args):
        if args[:2] == ('rule', 'show') or args[:2] == ('route', 'show'):
            return copy.deepcopy(self.current[family][args[0]])
        if args[:2] == ('address', 'show'):
            path = PATH4 if family == 4 else PATH6
            return [{'ifindex': path.ifindex, 'ifname': path.interface, 'flags': ['UP'],
                     'addr_info': [{'local': path.source}]}]
        if args[:2] == ('route', 'get'):
            if self.route_error:
                return [{'dev': 'wrongvpn', 'table': 880}]
            route = next(row for row in self.current[family]['route'] if row['dst'].split('/')[0] == args[2])
            return [route]
        raise AssertionError(args)

    def write_ip(self, family, *args):
        self.events.append(('ip', family, args))
        category, action = args[:2]
        fields = list(args[2:])
        def value(key, default=None):
            return fields[fields.index(key) + 1] if key in fields else default
        if category == 'rule':
            row = {'priority': int(value('priority')), 'dst': value('to'), 'protocol': value('protocol', '196')}
            if 'unreachable' in fields:
                row['action'] = 'unreachable'
            else:
                row['table'] = int(value('table'))
        else:
            prefix = next(field for field in fields if '/' in str(field))
            row = {'dst': prefix, 'table': int(value('table')), 'protocol': value('proto', '196'),
                   'dev': value('dev'), 'prefsrc': value('src')}
            if value('via'):
                row['gateway'] = value('via')
        rows = self.current[family][category]
        if action == 'add':
            if row not in rows:
                rows.append(row)
        else:
            rows.remove(row)

    def nft_json(self, *args):
        if args == ('list', 'tables'):
            return {'nftables': self.tables}
        return {'nftables': [{'table': {'family': 'inet', 'name': 'adguardvpn_site_routing',
                                       'comment': f'adguardvpn-site-routing:{INSTALLATION}'}}]}

    def nft_apply(self, script):
        self.events.append(('nft', script))
        self.tables = [] if script.strip() == 'delete table inet adguardvpn_site_routing' else [
            {'table': {'family': 'inet', 'name': 'adguardvpn_site_routing'}}]


class RoutingKernelTests(unittest.TestCase):
    def test_dynamic_priority_and_table_allocation_never_assume_adguard_table(self):
        self.assertEqual(choose_priority([{'priority': 0, 'table': 'local'}, {'priority': 1000, 'table': 880}]), 998)
        with self.assertRaises(RuntimeError):
            choose_priority([{'priority': 1, 'table': 123}])
        tables = choose_tables({'provider'}, {}, [{'table': 40000}], [])
        self.assertNotEqual(tables['provider'], 40000)

    def test_atomic_firewall_uses_both_address_families_and_kernel_interface_indices(self):
        script = guard_script(INSTALLATION, ['198.51.100.8', '2001:db8::8'], {'198.51.100.8': 17}, False)
        self.assertIn('198.51.100.8 . 17', script)
        self.assertIn('ip6 daddr', script)
        self.assertIn('meta oif', script)
        self.assertIn('hook output', script)
        self.assertNotIn('flush ruleset', script)
        self.assertNotIn('tun0', script)

    def test_guard_precedes_all_allow_routes_with_unreachable_fallback_and_verified_lookup(self):
        runner = KernelFixture()
        backend = KernelBackend(runner)
        manifest = {'objects': [], 'known': ['198.51.100.8', '2001:db8::8'], 'tables': {}, 'priority': 0}
        checkpoints = []
        result = backend.apply({'198.51.100.8': Assignment('vpn', PATH4),
                                '2001:db8::8': Assignment('vpn', PATH6)}, manifest, INSTALLATION,
                               checkpoint=lambda value: checkpoints.append(copy.deepcopy(value)))
        self.assertEqual(runner.events[0][0], 'nft')
        self.assertTrue(checkpoints[0]['pending_objects'])
        commands = [event[2] for event in runner.events if event[0] == 'ip']
        self.assertTrue(any('unreachable' in command for command in commands))
        self.assertEqual(result['priority'], 998)
        self.assertEqual(len(result['objects']), 6)
        runner.events.clear()
        backend.apply({'198.51.100.8': Assignment('vpn', PATH4), '2001:db8::8': Assignment('vpn', PATH6)}, result, INSTALLATION)
        self.assertEqual([event for event in runner.events if event[0] == 'ip'], [])

    def test_disconnect_removes_owned_allow_paths_and_keeps_terminal_blocks(self):
        runner = KernelFixture()
        backend = KernelBackend(runner)
        manifest = backend.apply({'198.51.100.8': Assignment('vpn', PATH4)},
                                 {'objects': [], 'known': ['198.51.100.8'], 'tables': {}, 'priority': 0}, INSTALLATION)
        result = backend.apply({'198.51.100.8': Assignment('vpn', None)}, manifest, INSTALLATION)
        self.assertTrue(all(item['kind'] == 'block' for item in result['objects']))
        self.assertTrue(any(row.get('action') == 'unreachable' for row in runner.current[4]['rule']))
        self.assertEqual(runner.current[4]['route'], [])

    def test_foreign_specific_policy_is_retained_and_reported_as_conflict(self):
        runner = KernelFixture()
        foreign = {'priority': 999, 'dst': '198.51.100.8/32', 'table': 777}
        runner.current[4]['rule'].append(foreign)
        result = KernelBackend(runner).apply({'198.51.100.8': Assignment('vpn', PATH4)},
            {'objects': [], 'known': ['198.51.100.8'], 'tables': {}, 'priority': 0}, INSTALLATION)
        self.assertEqual(result['failures']['198.51.100.8']['status'], 'conflict')
        self.assertIn(foreign, runner.current[4]['rule'])
        self.assertEqual(runner.current[4]['route'], [])
        self.assertTrue(all('unreachable' in event[2] for event in runner.events if event[0] == 'ip'))

    def test_route_mismatch_is_never_allowed_by_firewall(self):
        runner = KernelFixture()
        runner.route_error = True
        result = KernelBackend(runner).apply({'198.51.100.8': Assignment('vpn', PATH4)},
            {'objects': [], 'known': ['198.51.100.8'], 'tables': {}, 'priority': 0}, INSTALLATION)
        self.assertEqual(result['failures']['198.51.100.8']['status'], 'apply-error')
        self.assertTrue(result['pending_objects'])
        self.assertEqual(len([event for event in runner.events if event[0] == 'nft']), 1)

    def test_route_lookup_must_select_the_verified_source_address(self):
        runner = KernelFixture()
        original = runner.read_ip

        def read_ip(family, *args):
            rows = original(family, *args)
            return [{**rows[0], 'prefsrc': '192.0.2.99'}] if args[:2] == ('route', 'get') else rows

        runner.read_ip = read_ip
        result = KernelBackend(runner).apply({'198.51.100.8': Assignment('vpn', PATH4)},
            {'objects': [], 'known': ['198.51.100.8'], 'tables': {}, 'priority': 0}, INSTALLATION)
        self.assertEqual(result['failures']['198.51.100.8']['status'], 'apply-error')
        scripts = [script for event, script in (entry[:2] for entry in runner.events) if event == 'nft']
        self.assertNotIn('198.51.100.8 .', scripts[-1])

    def test_ownership_journal_rejects_arbitrary_arguments(self):
        for value in ({'kind': 'shell', 'address': '198.51.100.8'},
                      {'kind': 'block', 'address': '198.51.100.8;id', 'priority': 2}):
            with self.assertRaises(ValueError):
                OwnedObject.parse(value)
