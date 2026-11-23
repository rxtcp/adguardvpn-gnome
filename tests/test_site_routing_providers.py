import copy
import unittest

from site_routing.providers import ProviderRegistry, paths_from_active, nameservers
from site_routing_fakes import NM_ID


LINKS = [
    {'ifindex': 4, 'ifname': 'fixturewan', 'flags': ['UP'], 'linkinfo': {'info_kind': 'ether'},
     'addr_info': [{'local': '192.0.2.3'}, {'local': '2001:db8:2::3'}]},
    {'ifindex': 17, 'ifname': 'fixturevpn', 'flags': ['UP', 'POINTOPOINT'], 'linkinfo': {'info_kind': 'tun'},
     'addr_info': [{'local': '192.0.2.2'}, {'local': '2001:db8:1::2'}]},
]
ACTIVE = {'state': 2, 'uuid': NM_ID, 'interfaces': ['fixturewan'],
          'ip4': {'AddressData': [{'address': '192.0.2.2'}], 'Gateway': ''},
          'ip6': {'AddressData': [{'address': '2001:db8:1::2'}], 'Gateway': ''}}


class ProviderTests(unittest.TestCase):
    def test_nm_activation_alone_is_not_a_verified_tunnel(self):
        self.assertEqual(paths_from_active(ACTIVE, []), {})
        self.assertEqual(paths_from_active({**ACTIVE, 'state': 1}, LINKS), {})
        paths = paths_from_active(ACTIVE, LINKS)
        self.assertEqual(paths[4].ifindex, 17)
        self.assertEqual(paths[6].interface, 'fixturevpn')
        renamed = copy.deepcopy(LINKS)
        renamed[1]['ifname'], renamed[1]['ifindex'] = 'fixturevpn2', 27
        self.assertEqual(paths_from_active(ACTIVE, renamed)[4].ifindex, 27)

    def test_ambiguous_addresses_and_down_interfaces_are_not_guessed(self):
        duplicate = copy.deepcopy(LINKS[1])
        duplicate['ifname'], duplicate['ifindex'] = 'othervpn', 30
        self.assertEqual(paths_from_active(ACTIVE, [*LINKS, duplicate]), {})
        down = copy.deepcopy(LINKS)
        down[1]['flags'] = []
        self.assertEqual(paths_from_active(ACTIVE, down), {})
        invalid = copy.deepcopy(LINKS)
        invalid[1]['addr_info'] = [{'local': 'fe80::1'}, {'local': '127.0.0.1'}]
        active = {**ACTIVE, 'ip4': {'AddressData': [{'address': '127.0.0.1'}]}, 'ip6': {'AddressData': [{'address': 'fe80::1'}]}}
        self.assertEqual(paths_from_active(active, invalid), {})
        physical = {'state': 2, 'interfaces': ['fixturewan'], 'ip4': {'AddressData': [{'address': '192.0.2.3'}]}}
        self.assertEqual(paths_from_active(physical, LINKS, tunnel=False), {})
        self.assertEqual(nameservers({'ip4': {'NameserverData': [{'address': '192.0.2.53'}, {}]},
                                     'ip6': {'NameserverData': [{'address': '2001:db8::53'}, {'address': '192.0.2.53'}]}}),
                         ('192.0.2.53', '2001:db8::53'))

    def test_registry_preserves_saved_inactive_profiles_and_selects_real_physical_direct_path(self):
        class Reader:
            def snapshot(self):
                return {'profiles': [{'uuid': NM_ID, 'name': 'Saved VPN', 'type': 'vpn', 'users': ()},
                                     {'uuid': '00000000-0000-4000-8000-000000000003', 'name': 'Saved WG', 'type': 'wireguard', 'users': ('fixtureuser',)}],
                        'active': [{**ACTIVE, 'type': 'vpn'},
                                   {'state': 2, 'type': '802-3-ethernet', 'interfaces': ['fixturewan'],
                                    'ip4': {'AddressData': [{'address': '192.0.2.3'}], 'Gateway': '192.0.2.1'}, 'ip6': {}}],
                        'links': LINKS}
        registry = ProviderRegistry(Reader(), lambda: {'installed': True, 'connected': False, 'interfaces': []})
        providers = registry.discover()
        self.assertEqual(providers['networkmanager:' + NM_ID].paths[4].interface, 'fixturevpn')
        self.assertFalse(providers['networkmanager:00000000-0000-4000-8000-000000000003'].paths)
        self.assertEqual(providers['direct:direct'].paths[4].gateway, '192.0.2.1')
        self.assertFalse(providers['adguard:adguardvpn-gnome'].paths)

    def test_adguard_requires_confirmed_status_and_the_service_owned_tun(self):
        class Reader:
            def snapshot(self):
                return {'profiles': [{'type': '802-3-ethernet'}], 'active': [], 'links': LINKS}
        def state():
            return {'installed': True, 'connected': True, 'interfaces': ['fixturevpn']}
        provider = ProviderRegistry(Reader(), state).discover()['adguard:adguardvpn-gnome']
        self.assertEqual(provider.paths[4].ifindex, 17)
        self.assertNotIn('adguard:adguardvpn-gnome', ProviderRegistry(Reader(), lambda: {'installed': False}).discover())

    def test_wireguard_routes_require_peer_allowed_ips_not_only_a_live_interface(self):
        from site_routing.manager import RoutingManager
        from site_routing_fakes import Kernel, MemoryStore, Resolver, TARGET
        link = copy.deepcopy(LINKS[1])
        link['linkinfo']['info_kind'] = 'wireguard'
        profile = {'uuid': NM_ID, 'name': 'Fixture WG', 'type': 'wireguard', 'settings': {
            'wireguard': {'peers': [{'allowed-ips': ['198.51.100.0/24']}]}}}
        class Reader:
            def snapshot(self):
                return {'profiles': [profile], 'active': [ACTIVE], 'links': [link]}
        registry = ProviderRegistry(Reader(), lambda: {'installed': False})
        store, resolver = MemoryStore(), Resolver()
        kernel = Kernel(store)
        manager = RoutingManager(store, registry, resolver, kernel, clock=lambda: 1000)
        result = manager.handle({'operation': 'add-rule', 'domain': 'one.example', 'target': TARGET}, 1000, 'fixtureuser')
        self.assertEqual(result['rule']['status'], 'blocked-offline')
        self.assertTrue(all(assignment.path is None for assignment in kernel.calls[-1][1].values()))
        profile['settings']['wireguard']['peers'][0]['allowed-ips'].append('2001:db8::/32')
        manager.refresh()
        self.assertEqual(manager.rules(1000)[0]['status'], 'active')
