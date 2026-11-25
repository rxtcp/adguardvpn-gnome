"""Modern and legacy NM representations are matched without broadening a diff."""
import ipaddress
import socket
import struct
import unittest

from site_routing.migration_fields import entry_address, settings_hash
from site_routing.migration_matching import matches_entry


def matches_profile(live, profile):
    setting = profile['settings'][f'ipv{live["family"]}']
    return any(matches_entry(live, profile, field, row) for field, rows in setting.items()
               if field in ('routing-rules', 'route-data', 'routes') for row in rows)


class MigrationMatchingTests(unittest.TestCase):
    def test_deprecated_arrays_preserve_network_byte_order_and_host_prefix_length(self):
        packed = struct.unpack('=I', socket.inet_pton(socket.AF_INET, '198.51.100.8'))[0]
        self.assertEqual(entry_address(4, 'routes', [packed, 32, 0, 20]), '198.51.100.8')
        packed6 = list(ipaddress.IPv6Address('2001:db8::8').packed)
        self.assertEqual(entry_address(6, 'routes', [packed6, 128, [0] * 16, 20]), '2001:db8::8')
        self.assertIsNone(entry_address(4, 'routes', []))
        self.assertIsNone(entry_address(4, 'route-data', {'dest': '2001:db8::8', 'prefix': 128}))
        self.assertIsNone(entry_address(4, 'routing-rules', {'to': '198.51.100.8', 'to-len': 24}))
        self.assertEqual(entry_address(6, 'routing-rules', {'to': '2001:db8::8', 'to-len': 128}), '2001:db8::8')
        self.assertEqual(settings_hash({'bytes': b'fixture'}), settings_hash({'bytes': list(b'fixture')}))

    def test_rule_matching_refuses_identical_rules_without_ownership(self):
        live = {'kind': 'rule', 'family': 4, 'data': {'dst': '198.51.100.8/32', 'table': 777, 'priority': 900, 'protocol': 'static'}}
        row = {'to': '198.51.100.8', 'to-len': 32, 'table': 777, 'priority': 900}
        profile = {'settings': {'ipv4': {'routing-rules': [row]}}}
        self.assertFalse(matches_profile(live, profile))

    def test_route_matching_checks_interface_gateway_source_metric_table_and_legacy_arrays(self):
        live = {'kind': 'route', 'family': 4, 'data': {'dst': '198.51.100.8/32', 'table': 777,
            'dev': 'fixturevpn', 'gateway': '192.0.2.1', 'metric': 20, 'protocol': 'static'}}
        row = {'dest': '198.51.100.8', 'prefix': 32, 'next-hop': '192.0.2.1', 'metric': 20, 'table': 777}
        profile = {'interfaces': ['fixturevpn'], 'settings': {'ipv4': {'route-data': [row]}}}
        self.assertTrue(matches_profile(live, profile))
        self.assertFalse(matches_profile({**live, 'data': {**live['data'], 'protocol': 99}}, profile))
        self.assertFalse(matches_profile({**live, 'data': {**live['data'], 'dst': '198.51.100.8/31'}}, profile))
        self.assertFalse(matches_profile(live, {**profile, 'interfaces': ['other']}))
        for changed in ({'table': 778}, {'next-hop': '192.0.2.9'}, {'metric': 21}, {'src': '192.0.2.3'},
                        {'type': 'blackhole'}, {'onlink': True}):
            self.assertFalse(matches_profile(live, {**profile, 'settings': {'ipv4': {'route-data': [{**row, **changed}]}}}))
        for changed in ({'scope': 'host'}, {'pref': 'low'}):
            self.assertFalse(matches_profile({**live, 'data': {**live['data'], **changed}}, profile))
        packed = lambda address: struct.unpack('=I', socket.inet_pton(socket.AF_INET, address))[0]
        old = {'settings': {'connection': {'interface-name': 'fixturevpn'}, 'ipv4': {'route-table': 777,
            'routes': [[packed('198.51.100.8'), 32, packed('192.0.2.1'), 20]]}}}
        self.assertFalse(matches_profile(live, old))
        old['interfaces'] = ['fixturevpn']
        self.assertTrue(matches_profile(live, old))
        for row in ([packed('198.51.100.8'), 32], [packed('198.51.100.8'), 32, 'bad', 20]):
            self.assertFalse(matches_profile(live, {**old, 'settings': {**old['settings'], 'ipv4': {'routes': [row]}}}))
        live6 = {'kind': 'route', 'family': 6, 'data': {'dst': '2001:db8::8/128', 'dev': 'fixturevpn', 'protocol': 'static'}}
        old6 = {'interfaces': ['fixturevpn'], 'settings': {'ipv6': {'routes': [[list(ipaddress.IPv6Address('2001:db8::8').packed), 128, [0] * 16, 0]]}}}
        self.assertTrue(matches_profile(live6, old6))
