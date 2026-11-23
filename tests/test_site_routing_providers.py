import copy
import unittest

from site_routing.providers import ProviderRegistry, paths_from_active
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
                return {'profiles': [], 'active': [], 'links': LINKS}
        def state():
            return {'installed': True, 'connected': True, 'interfaces': ['fixturevpn']}
        provider = ProviderRegistry(Reader(), state).discover()['adguard:adguardvpn-gnome']
        self.assertEqual(provider.paths[4].ifindex, 17)
        self.assertNotIn('adguard:adguardvpn-gnome', ProviderRegistry(Reader(), lambda: {'installed': False}).discover())
