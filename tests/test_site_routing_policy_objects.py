"""Ownership and migration must never grant permission over unrelated policy."""
import copy
import unittest
from unittest.mock import Mock

from site_routing.firewall import Firewall, guard_script
from site_routing.kernel import KernelBackend
from site_routing.kernel_objects import OwnedObject, choose_priority, choose_tables, table_number
from site_routing.legacy_objects import legacy_arguments
from site_routing.models import Assignment, NetworkPath
from site_routing.policy_inspection import foreign_overlaps, signature
from site_routing_fakes import PATH4
from test_site_routing_kernel import INSTALLATION, KernelFixture


class PolicyOwnershipTests(unittest.TestCase):
    def test_migration_identity_survives_numeric_protocol_and_table_rendering(self):
        named = {'dst': '198.51.100.8', 'table': 'main', 'protocol': 'static'}
        numeric = {**named, 'table': 254, 'protocol': 4}
        self.assertEqual(signature('route', 4, named), signature('route', 4, numeric))
        self.assertNotEqual(signature('route', 4, {**named, 'table': 'unknown-one'}),
                            signature('route', 4, {**named, 'table': 'unknown-two'}))

    def test_objects_validate_allocation_ranges_and_compare_every_ownership_selector(self):
        for value in ({'kind': 'block', 'address': '198.51.100.8', 'priority': True},
                      {'kind': 'lookup', 'address': '198.51.100.8', 'priority': 2, 'table': 880},
                      {'kind': 'route', 'address': '198.51.100.8', 'table': 40000},
                      {'kind': 'route', 'address': '198.51.100.8', 'table': 40000, 'path': 'untrusted'},
                      {'kind': 'block', 'address': '198.51.100.8', 'priority': 2, 'extra': 'command'}):
            with self.subTest(value=value), self.assertRaises(ValueError): OwnedObject.parse(value)
        lookup = OwnedObject('lookup', '198.51.100.8', 998, 40000)
        row = {'dst': '198.51.100.8/32', 'priority': 998, 'table': 40000, 'protocol': 196}
        self.assertTrue(lookup.matches(row))
        for changed in ({'dst': 'all'}, {'protocol': 'static'}, {'dst': 'bad'}, {'dst': '198.51.100.9/32'},
                        {'src': '192.0.2.0/24'}, {'fwmark': 1}, {'flags': ['not']}, {'priority': 999},
                        {'tos': 16}, {'suppress_prefixlength': 0}, {'action': 'blackhole'}):
            self.assertFalse(lookup.matches({**row, **changed}))
        self.assertEqual(table_number('unknown'), -1)
        self.assertEqual(table_number('40000'), 40000)
        path = NetworkPath('fixturewan', 4, '192.0.2.3', '192.0.2.1')
        route = OwnedObject('route', '198.51.100.8', table=40000, path=path)
        self.assertIn('onlink', route.arguments('add'))
        self.assertEqual(route.arguments('add')[route.arguments('add').index('via') + 1], path.gateway)
        self.assertIn('table', lookup.arguments('del'))
        self.assertIn('unreachable', OwnedObject('block', row['dst'].split('/')[0], 999).arguments('add'))
        owned_route = {'dst': '198.51.100.8/32', 'table': 40000, 'protocol': 196,
            'dev': path.interface, 'prefsrc': path.source, 'gateway': path.gateway, 'flags': ['onlink']}
        self.assertTrue(route.matches(owned_route))
        self.assertTrue(route.matches({**owned_route, 'flags': ['onlink', 'linkdown']}))
        for changed in ({'metric': 5}, {'tos': 16}, {'type': 'blackhole'}, {'flags': ['onlink', 'pervasive']},
                        {'pref': 'high'}, {'scope': 'host'}):
            self.assertFalse(route.matches({**owned_route, **changed}), changed)
        for journal in ({'a': True}, {'a': 880}, {'a': 40000, 'b': 40000}):
            with self.assertRaises(ValueError): choose_tables({'a'}, journal, [], [])
        with self.assertRaises(RuntimeError): choose_tables({'new'}, {}, [{'table': value} for value in range(40000, 50000)], [])
        with self.assertRaises(RuntimeError): choose_priority([{'priority': 0, 'table': 880}])

    def test_foreign_host_routes_are_reported_but_broad_routes_and_unrelated_hosts_are_retained(self):
        rows = [{'dst': '198.51.100.8/32', 'table': 777}, {'dst': '198.51.100.0/24', 'table': 777},
                {'dst': '198.51.100.9/32', 'table': 777}, {'dst': '198.51.100.8/32', 'table': 'local'}]
        overlaps = foreign_overlaps({4: {'route': rows}, 6: {'rule': [{'dst': '2001:db8::/64', 'table': 777}]}}, [], ['198.51.100.8'])
        self.assertEqual(overlaps, [{'kind': 'route', 'family': 4, 'data': rows[0]}])

    def test_firewall_ownership_failure_and_empty_cleanup_preserve_foreign_tables(self):
        with self.assertRaises(ValueError): guard_script(INSTALLATION, ['198.51.100.8'], {'198.51.100.8': True}, False)
        runner = KernelFixture(); firewall = Firewall(runner)
        firewall.apply([], {}, INSTALLATION); self.assertEqual(runner.events, [])
        firewall.apply(['198.51.100.8'], {}, INSTALLATION)
        firewall.apply([], {}, INSTALLATION)
        self.assertEqual(runner.events[-1][1], 'delete table inet adguardvpn_site_routing')
        runner.tables = [{'table': {'family': 'inet', 'name': 'adguardvpn_site_routing'}}]
        runner.nft_json = lambda *args: {'nftables': runner.tables}
        with self.assertRaisesRegex(RuntimeError, 'foreign firewall'): firewall.apply([], {}, INSTALLATION)

    def test_stale_owned_table_with_a_foreign_route_is_never_reused_or_cleaned(self):
        runner, manifest = KernelFixture(), {'objects': [], 'known': ['198.51.100.8'], 'tables': {'vpn': 40000}, 'priority': 998}
        foreign = {'dst': '203.0.113.0/24', 'table': 40000, 'dev': 'other'}
        runner.current[4]['route'] = [foreign]
        with self.assertRaisesRegex(RuntimeError, 'foreign route'):
            KernelBackend(runner).apply({'198.51.100.8': Assignment('vpn', PATH4)}, manifest, INSTALLATION)
        self.assertIn(foreign, runner.current[4]['route'])
        self.assertFalse(any(event[0] == 'ip' for event in runner.events))

    def test_cleanup_refuses_a_route_whose_attributes_were_changed_outside_the_manager(self):
        runner = KernelFixture(); backend = KernelBackend(runner)
        manifest = backend.apply({'198.51.100.8': Assignment('vpn', PATH4)},
            {'objects': [], 'known': ['198.51.100.8'], 'tables': {}, 'priority': 0}, INSTALLATION)
        runner.current[4]['route'][0]['metric'] = 5
        changed = copy.deepcopy(runner.current)
        runner.events.clear()
        with self.assertRaisesRegex(RuntimeError, 'foreign route'):
            backend.apply({}, manifest, INSTALLATION)
        self.assertEqual(runner.current, changed)
        self.assertTrue(runner.events)
        self.assertTrue(all(event[0] == 'nft' for event in runner.events))

    def test_lost_source_or_interface_index_cannot_verify_a_route_and_diagnostics_are_sanitized(self):
        runner, backend = KernelFixture(), None
        backend = KernelBackend(runner)
        manifest = backend.apply({'198.51.100.8': Assignment('vpn', PATH4)},
            {'objects': [], 'known': ['198.51.100.8'], 'tables': {}, 'priority': 0}, INSTALLATION)
        self.assertTrue(backend.verify_replacement(['198.51.100.8'], manifest))
        self.assertFalse(backend.verify_replacement([], manifest))
        self.assertFalse(backend.verify_replacement(['198.51.100.9'], manifest))
        route = next(OwnedObject.parse(row) for row in manifest['objects'] if row['kind'] == 'route')
        original = runner.read_ip
        runner.read_ip = lambda family, *args: [{'ifindex': 99, 'flags': ['UP'], 'addr_info': [{'local': PATH4.source}]}] if args[0] == 'address' else original(family, *args)
        self.assertFalse(backend._verified(route))
        runner.read_ip = lambda family, *args: [{'ifindex': PATH4.ifindex, 'flags': ['UP'], 'addr_info': [{'local': PATH4.source, 'flags': ['tentative']}]}] if args[0] == 'address' else original(family, *args)
        self.assertFalse(backend._verified(route))
        runner.read_ip = lambda *args: [{'dev': 'fixturevpn', 'table': 40000, 'gateway': '192.0.2.1', 'type': 'unicast', 'private': 'never return'}]
        self.assertEqual(backend.diagnostics(['198.51.100.8']), [{'address': '198.51.100.8', 'dev': 'fixturevpn', 'table': 40000, 'gateway': '192.0.2.1', 'type': 'unicast'}])
        runner.read_ip = lambda *args: []
        self.assertEqual(backend.diagnostics(['198.51.100.8']), [{'address': '198.51.100.8'}])
        runner.read_ip = Mock(side_effect=RuntimeError('not reachable'))
        self.assertEqual(backend.diagnostics(['198.51.100.8'])[0]['type'], 'unreachable-or-unavailable')
        self.assertFalse(backend.verify_replacement(['198.51.100.8'], manifest))

    def test_reviewed_legacy_changes_are_exact_idempotent_and_keep_unrelated_rows(self):
        runner = KernelFixture(); backend = KernelBackend(runner)
        row = {'priority': 900, 'dst': '198.51.100.8/32', 'table': 777, 'protocol': '196'}
        runner.current[4]['rule'].append(copy.deepcopy(row))
        entries = backend.overlaps(['198.51.100.8'], {'objects': []})
        self.assertEqual(entries, [{'kind': 'rule', 'family': 4, 'data': row}])
        backend.change_legacy(entries, 'del'); backend.change_legacy(entries, 'del')
        self.assertNotIn(row, runner.current[4]['rule'])
        backend.change_legacy(entries, 'add'); backend.change_legacy(entries, 'add')
        self.assertEqual(runner.current[4]['rule'].count(row), 1)
        self.assertIn({'priority': 1000, 'table': 880}, runner.current[4]['rule'])


class LegacyArgumentTests(unittest.TestCase):
    def test_only_simple_reviewed_host_rules_are_converted_to_fixed_argument_arrays(self):
        item = {'kind': 'rule', 'family': 4, 'data': {'dst': '198.51.100.8/32', 'priority': 900, 'table': 777}}
        self.assertEqual(legacy_arguments(item, 'del'), ('rule', 'del', 'priority', '900', 'to', '198.51.100.8/32', 'table', '777', 'protocol', 'static'))
        invalid = [{**item, 'kind': 'shell'}, {**item, 'family': 3}]
        invalid += [{**item, 'data': {**item['data'], **changed}} for changed in (
            {'dst': '198.51.100.0/24'}, {'dst': '2001:db8::8/128'}, {'table': 0}, {'table': 'local'},
            {'protocol': 'shell'}, {'protocol': 256}, {'fwmark': 1}, {'src': '192.0.2.0/24'},
            {'priority': True}, {'priority': 0}, {'action': 'unreachable'}, {'flags': ['bad']})]
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(ValueError): legacy_arguments(value, 'del')
        with self.assertRaises(ValueError): legacy_arguments(item, 'replace')

    def test_route_migration_preserves_gateway_source_metric_scope_and_ipv6_preference(self):
        row = {'dst': '2001:db8::8/128', 'table': 777, 'dev': 'fixturevpn', 'protocol': 4,
               'gateway': '2001:db8:1::1', 'prefsrc': '2001:db8:1::2', 'metric': 20, 'scope': 'global', 'pref': 'high'}
        item = {'kind': 'route', 'family': 6, 'data': row}
        args = legacy_arguments(item, 'add')
        for value in ('via', 'src', 'metric', 'scope', 'pref'): self.assertIn(value, args)
        for changed in ({'multipath': []}, {'dev': '-shell'}, {'type': 'unreachable'}, {'flags': ['onlink']},
                        {'gateway': '192.0.2.1'}, {'metric': -1}, {'metric': True}):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                legacy_arguments({**item, 'data': {**row, **changed}}, 'del')
        minimal = {'kind': 'route', 'family': 4, 'data': {'dst': '198.51.100.8', 'dev': 'fixturevpn'}}
        self.assertNotIn('metric', legacy_arguments(minimal, 'del'))
