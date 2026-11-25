"""Real Linux routing/nft tests. The parent network namespace must be different.

Run only via the CI wrapper or an explicitly created disposable namespace.
There are no vendor binaries, credentials, corporate networks or internet peers.
"""
import os
import socket
import struct
import subprocess
import unittest
from unittest.mock import patch

from site_routing.commands import CommandRunner, IP
from site_routing.kernel import KernelBackend
from site_routing.models import Assignment, NetworkPath
from site_routing.underlay import MARK, TABLE, change_policy, has_policy, verify_policy

INSTALLATION = '00000000-0000-4000-8000-000000000010'


class NamespaceRoutingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        parent = os.environ.get('SITE_ROUTING_PARENT_NETNS')
        if os.geteuid() != 0 or not parent or os.readlink('/proc/self/ns/net') == parent:
            raise RuntimeError('Refusing network tests outside an explicitly isolated root namespace.')

    def command(self, *arguments):
        subprocess.run([IP, *arguments], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    def setUp(self):
        # Each case owns a fresh child namespace; no fixture cleanup touches host state.
        os.unshare(os.CLONE_NEWNET)
        self.assertNotEqual(os.readlink('/proc/self/ns/net'), os.environ['SITE_ROUTING_PARENT_NETNS'])

    def tunnel(self, source4='192.0.2.2', source6='2001:db8:1::2', *, name='fixturevpn', prefix4=24):
        self.command('link', 'add', name, 'type', 'dummy')
        self.command('link', 'set', name, 'up')
        self.command('address', 'add', source4 + f'/{prefix4}', 'dev', name)
        self.command('-6', 'address', 'add', source6 + '/64', 'dev', name, 'nodad')
        index = socket.if_nametoindex(name)
        return NetworkPath(name, index, source4), NetworkPath(name, index, source6)

    def test_legacy_route_restore_binds_to_index_even_if_the_name_is_reused_during_the_write(self):
        self.command('link', 'set', 'lo', 'up')
        original, original6 = self.tunnel()
        runner = CommandRunner()
        backend = KernelBackend(runner)
        def legacy_routes(family):
            return [row for row in runner.read_ip(family, 'route', 'show', 'table', 'all') if row.get('table') == 777]

        for family, destination, path in ((4, '198.51.100.8/32', original), (6, '2001:db8::8/128', original6)):
            self.command(f'-{family}', 'route', 'add', destination, 'table', '777',
                         'dev', path.interface, 'src', path.source, 'proto', 'static', 'metric', '20')
        row6 = legacy_routes(6)[0]
        item6 = {'kind': 'route', 'family': 6, 'data': row6}
        binding6 = backend.legacy_route_binding(item6)
        backend.change_legacy(item6, 'del', binding=binding6)
        backend.change_legacy(item6, 'add', binding=binding6)
        self.assertEqual(legacy_routes(6), [row6])

        row4 = legacy_routes(4)[0]
        item4 = {'kind': 'route', 'family': 4, 'data': row4}
        binding4 = backend.legacy_route_binding(item4)
        backend.change_legacy(item4, 'del', binding=binding4)
        change = runner.change_legacy_route

        def reuse_name(item, action, index):
            self.command('link', 'set', original.interface, 'down')
            self.command('link', 'set', original.interface, 'name', 'fixtureverified')
            self.command('link', 'set', 'fixtureverified', 'up')
            replacement, _ = self.tunnel('192.0.2.7', '2001:db8:2::7', name=original.interface)
            self.assertNotEqual(replacement.ifindex, index)
            change(item, action, index)

        with patch.object(runner, 'change_legacy_route', side_effect=reuse_name):
            backend.change_legacy(item4, 'add', binding=binding4)
        self.assertEqual(legacy_routes(4), [{**row4, 'dev': 'fixtureverified'}])

        self.command('link', 'del', 'fixtureverified')
        with self.assertRaisesRegex(RuntimeError, 'kernel refused'):
            change(item4, 'add', original.ifindex)
        self.assertEqual(legacy_routes(4), [])

    def test_legacy_route_delete_preserves_identical_route_on_reused_interface_name(self):
        self.command('link', 'set', 'lo', 'up')
        original, _ = self.tunnel()
        runner = CommandRunner()
        backend = KernelBackend(runner)
        route_args = ('-4', 'route', 'add', '198.51.100.8/32', 'table', '777',
                      'dev', original.interface, 'proto', 'static', 'metric', '20')
        self.command(*route_args)
        def legacy_routes():
            return [row for row in runner.read_ip(4, 'route', 'show', 'table', 'all') if row.get('table') == 777]

        row = legacy_routes()[0]
        item = {'kind': 'route', 'family': 4, 'data': row}
        reviewed = backend.legacy_route_binding(item)

        def reuse_name(binding):
            self.assertEqual(binding['ifindex'], original.ifindex)
            self.command('link', 'del', original.interface)
            unrelated, _ = self.tunnel(name=original.interface)
            self.assertNotEqual(unrelated.ifindex, original.ifindex)
            self.command(*route_args)
            self.assertEqual(legacy_routes(), [row])

        with self.assertRaisesRegex(RuntimeError, 'kernel refused'):
            backend.change_legacy(item, 'del', binding=reviewed, before_delete=reuse_name)
        with self.assertRaisesRegex(RuntimeError, 'interface binding changed'):
            backend.change_legacy(item, 'del', binding=reviewed, before_delete=lambda _: self.fail('unreviewed deletion'))
        self.assertEqual(legacy_routes(), [row])

    def test_legacy_route_index_survives_name_reuse_between_dump_and_interface_check(self):
        self.command('link', 'set', 'lo', 'up')
        original, _ = self.tunnel()
        runner = CommandRunner()
        backend = KernelBackend(runner)
        route_args = ('-4', 'route', 'add', '198.51.100.8/32', 'table', '777',
                      'dev', original.interface, 'proto', 'static', 'metric', '20')
        self.command(*route_args)

        def legacy_routes():
            return [row for row in runner.read_ip(4, 'route', 'show', 'table', 'all') if row.get('table') == 777]

        row = legacy_routes()[0]
        item = {'kind': 'route', 'family': 4, 'data': row}
        reviewed = backend.legacy_route_binding(item)
        original_name = socket.if_indextoname

        def reuse_name(index):
            self.assertEqual(index, original.ifindex)
            self.command('link', 'del', original.interface)
            unrelated, _ = self.tunnel(name=original.interface)
            self.assertNotEqual(unrelated.ifindex, index)
            self.command(*route_args)
            return original_name(index)

        with patch('site_routing.route_netlink.socket.if_indextoname', side_effect=reuse_name) as name:
            with self.assertRaises(OSError):
                backend.change_legacy(item, 'del', binding=reviewed, before_delete=lambda _: self.fail('no deletion was verified'))
        name.assert_called_once_with(original.ifindex)
        self.assertEqual(legacy_routes(), [row])

    def test_independent_conflict_and_real_device_loss_recover_without_releasing_known_ips(self):
        self.command('link', 'set', 'lo', 'up')
        corporate, _corporate6 = self.tunnel()
        adguard, _adguard6 = self.tunnel('203.0.113.2', '2001:db8:3::2', name='fixtureguard', prefix4=32)
        self.command('-4', 'route', 'add', 'default', 'table', '880', 'dev', 'fixtureguard')
        self.command('-4', 'rule', 'add', 'priority', '30801', 'table', '880')
        self.command('-4', 'rule', 'add', 'priority', '900', 'to', '198.51.100.8/32', 'table', '777', 'protocol', 'static')
        runner, backend = CommandRunner(), KernelBackend(CommandRunner())
        assignments = {'198.51.100.8': Assignment('fixture-corporate', corporate),
                       '198.51.100.9': Assignment('fixture-corporate', corporate)}
        journal = {'objects': [], 'pending_objects': [], 'known': list(assignments), 'tables': {}, 'priority': 0}
        manifest = backend.apply(assignments, journal, INSTALLATION)
        self.assertEqual(manifest['failures']['198.51.100.8']['status'], 'conflict')
        self.assertNotIn('198.51.100.9', manifest['failures'])
        self.assertTrue(any(row.get('priority') == 900 for row in runner.read_ip(4, 'rule', 'show')))
        with self.assertRaises(RuntimeError): runner.read_ip(4, 'route', 'get', '198.51.100.8')
        self.assertEqual(runner.read_ip(4, 'route', 'get', '198.51.100.9')[0]['dev'], 'fixturevpn')
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as outgoing:
            self.assertEqual(outgoing.sendto(b'fixture', ('198.51.100.9', 443)), 7)
        self.command('-4', 'rule', 'del', 'priority', '900', 'to', '198.51.100.8/32', 'table', '777', 'protocol', 'static')
        self.command('link', 'del', 'fixturevpn')
        # The old verified provider snapshot races with actual device disappearance.
        assignments['198.51.100.9'] = Assignment('fixture-adguard', adguard)
        manifest = backend.apply(assignments, manifest, INSTALLATION)
        self.assertEqual(manifest['failures']['198.51.100.8']['status'], 'apply-error')
        self.assertIn('kernel interface disappeared', manifest['failures']['198.51.100.8']['detail'])
        self.assertNotIn('198.51.100.9', manifest['failures'])
        self.assertEqual(runner.read_ip(4, 'route', 'get', '198.51.100.9')[0]['dev'], 'fixtureguard')
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as outgoing:
            with self.assertRaises(OSError): outgoing.sendto(b'fixture', ('198.51.100.8', 443))
        replacement, _replacement6 = self.tunnel('192.0.2.4', '2001:db8:1::4', name='fixturevpn2')
        assignments['198.51.100.8'] = Assignment('fixture-corporate', replacement)
        manifest = backend.apply(assignments, manifest, INSTALLATION)
        self.assertEqual(manifest['failures'], {})
        self.assertEqual(manifest['pending_objects'], [])
        self.assertEqual(runner.read_ip(4, 'route', 'get', '198.51.100.8')[0]['dev'], 'fixturevpn2')
        self.assertEqual(runner.read_ip(4, 'route', 'get', '198.51.100.9')[0]['dev'], 'fixtureguard')

    def test_verified_routes_disconnect_reconnect_collision_and_boot_guard(self):
        self.command('link', 'set', 'lo', 'up')
        self.command('link', 'add', 'fixturewan', 'type', 'dummy')
        self.command('link', 'set', 'fixturewan', 'up')
        self.command('address', 'add', '198.18.0.2/24', 'dev', 'fixturewan')
        self.command('-6', 'address', 'add', '2001:db8:2::2/64', 'dev', 'fixturewan', 'nodad')
        self.command('route', 'add', 'default', 'dev', 'fixturewan')
        self.command('-6', 'route', 'add', 'default', 'dev', 'fixturewan')
        path4, path6 = self.tunnel()
        self.tunnel('203.0.113.2', '2001:db8:3::2', name='fixtureguard', prefix4=32)
        # A foreign VPN owns the ordinary default path and its own routing table.
        for family in (4, 6):
            self.command(f'-{family}', 'route', 'add', 'default', 'table', '880', 'dev', 'fixtureguard')
            self.command(f'-{family}', 'rule', 'add', 'priority', '30801', 'table', '880')
            self.command(f'-{family}', 'rule', 'add', 'priority', '30000', 'ipproto', 'udp', 'sport', '53', 'table', 'main')
        runner, backend = CommandRunner(), KernelBackend(CommandRunner())
        assignments = {'198.51.100.8': Assignment('fixture-vpn', path4),
                       '2001:db8::8': Assignment('fixture-vpn', path6)}
        journal = {'objects': [], 'pending_objects': [], 'known': list(assignments), 'tables': {}, 'priority': 0}
        # Characterize SR-UNDERLAY-01 before and after applying unrelated site policy.
        for endpoint in ('198.51.100.99', '203.0.113.99'):
            self.command('-4', 'route', 'add', endpoint + '/32', 'via', '198.18.0.1', 'dev', 'fixturewan')
            route = runner.read_ip(4, 'route', 'get', endpoint, 'ipproto', 'udp', 'sport', '40123', 'dport', '1194')[0]
            self.assertEqual((route['dev'], route['table']), ('fixtureguard', 880))
        manifest = backend.apply(assignments, journal, INSTALLATION)
        for endpoint in ('198.51.100.99', '203.0.113.99'):
            route = runner.read_ip(4, 'route', 'get', endpoint, 'ipproto', 'udp', 'sport', '40123', 'dport', '1194')[0]
            self.assertEqual((route['dev'], route['table']), ('fixtureguard', 880))
        for family, address in ((4, '198.51.100.8'), (6, '2001:db8::8')):
            self.assertEqual(runner.read_ip(family, 'route', 'get', address)[0]['dev'], 'fixturevpn')
            self.assertTrue(any(row.get('action', row.get('type')) == 'unreachable' for row in runner.read_ip(family, 'rule', 'show')))
        direct4 = NetworkPath('fixturewan', socket.if_nametoindex('fixturewan'), '198.18.0.2', '198.18.0.1')
        direct6 = NetworkPath('fixturewan', socket.if_nametoindex('fixturewan'), '2001:db8:2::2', '2001:db8:2::1')
        manifest = backend.apply({'198.51.100.8': Assignment('direct', direct4),
            '2001:db8::8': Assignment('direct', direct6)}, manifest, INSTALLATION)
        for family, address, gateway in ((4, '198.51.100.8', '198.18.0.1'), (6, '2001:db8::8', '2001:db8:2::1')):
            route = runner.read_ip(family, 'route', 'get', address)[0]
            self.assertEqual((route['dev'], route['gateway']), ('fixturewan', gateway))
        self.assertEqual(runner.read_ip(4, 'route', 'get', '203.0.113.10')[0]['dev'], 'fixtureguard')
        manifest = backend.apply(assignments, manifest, INSTALLATION)
        self.command('link', 'del', 'fixturevpn')
        for family, address in ((4, '198.51.100.8'), (6, '2001:db8::8')):
            with self.assertRaises(RuntimeError):
                runner.read_ip(family, 'route', 'get', address)
        # A foreign higher-priority policy cannot bypass the independent egress guard.
        for family, address, prefix, socket_family in ((4, '198.51.100.8', 32, socket.AF_INET),
                (6, '2001:db8::8', 128, socket.AF_INET6)):
            self.command(f'-{family}', 'rule', 'add', 'priority', '1', 'to', f'{address}/{prefix}', 'table', 'main')
            self.assertEqual(runner.read_ip(family, 'route', 'get', address)[0]['dev'], 'fixturewan')
            with socket.socket(socket_family, socket.SOCK_DGRAM) as outgoing:
                with self.assertRaises(OSError): outgoing.sendto(b'fixture', (address, 443))
            self.command(f'-{family}', 'rule', 'del', 'priority', '1', 'to', f'{address}/{prefix}', 'table', 'main')
        replacement4, replacement6 = self.tunnel('192.0.2.4', '2001:db8:1::4')
        self.assertNotEqual(path4.ifindex, replacement4.ifindex)
        assignments = {'198.51.100.8': Assignment('fixture-vpn', replacement4),
                       '2001:db8::8': Assignment('fixture-vpn', replacement6)}
        manifest = backend.apply(assignments, manifest, INSTALLATION)
        self.assertEqual(runner.read_ip(4, 'route', 'get', '198.51.100.8')[0]['dev'], 'fixturevpn')
        # Conflict/offline state has no working route, with both guards retained.
        blocked = {address: Assignment('fixture-vpn', None) for address in assignments}
        manifest = backend.apply(blocked, manifest, INSTALLATION)
        with self.assertRaises(RuntimeError): runner.read_ip(6, 'route', 'get', '2001:db8::8')
        # Explicit deletion releases only managed destinations and their owned objects.
        self.command('-4', 'rule', 'add', 'priority', '900', 'to', '203.0.113.9/32', 'table', 'main')
        backend.apply({}, manifest, INSTALLATION)
        self.assertTrue(any(row.get('priority') == 900 for row in runner.read_ip(4, 'rule', 'show')))
        self.assertEqual(runner.read_ip(4, 'route', 'get', '198.51.100.8')[0]['dev'], 'fixtureguard')
        self.assertTrue(any(row.get('priority') == 30801 and str(row.get('table')) == '880' for row in runner.read_ip(4, 'rule', 'show')))
        self.assertFalse(any(row.get('table', {}).get('name') == 'adguardvpn_site_routing' for row in runner.nft_json('list', 'tables')['nftables']))
        # The boot phase restores a deny-only table before any daemon/provider discovery.
        backend.block(assignments, INSTALLATION)
        for socket_family, address in ((socket.AF_INET, '198.51.100.8'), (socket.AF_INET6, '2001:db8::8')):
            with socket.socket(socket_family, socket.SOCK_DGRAM) as outgoing:
                with self.assertRaises(OSError): outgoing.sendto(b'fixture', (address, 443))

    def test_marked_auto_underlay_is_scoped_and_fails_closed(self):
        self.command('link', 'add', 'fixturewan', 'type', 'veth', 'peer', 'name', 'fixturepeer')
        peer_mac = '02:00:00:00:00:02'
        self.command('link', 'set', 'fixturepeer', 'address', peer_mac, 'up')
        self.command('link', 'set', 'fixturewan', 'up')
        self.tunnel('203.0.113.2', '2001:db8:3::2', name='fixtureguard', prefix4=32)
        runner = CommandRunner()
        change_policy(runner, remove=False)
        backend = KernelBackend(runner)
        cases = (
            (4, socket.AF_INET, 0x0800, '198.18.0.2/24', ('198.51.100.99', '203.0.113.99')),
            (6, socket.AF_INET6, 0x86DD, '2001:db8:2::2/64', ('2001:db8:4::99', '2001:db8:5::99')),
        )
        for family, _, _, address, endpoints in cases:
            flag = f'-{family}'
            self.command(flag, 'address', 'add', address, 'dev', 'fixturewan', *(['nodad'] if family == 6 else []))
            self.command(flag, 'route', 'add', 'default', 'table', '880', 'dev', 'fixtureguard')
            self.command(flag, 'rule', 'add', 'priority', '30801', 'table', '880')
            self.command(flag, 'route', 'add', 'default', 'table', str(TABLE), 'dev', 'fixturewan')
            for endpoint in endpoints:
                self.command(flag, 'neigh', 'replace', endpoint, 'lladdr', peer_mac, 'nud', 'permanent', 'dev', 'fixturewan')

        journal = {'objects': [], 'pending_objects': [], 'known': [], 'tables': {}, 'priority': 0}
        shared = '198.51.100.8'
        manifest = backend.apply({shared: Assignment('fixture-corporate', None)}, journal, INSTALLATION)
        self.assertEqual(manifest['failures'], {})
        verify_policy(runner)
        with self.assertRaises(RuntimeError):
            runner.read_ip(4, 'route', 'get', shared, 'mark', hex(MARK))

        for family, socket_family, ethertype, address, endpoints in cases:
            flag = f'-{family}'
            self.assertEqual(runner.read_ip(family, 'route', 'get', endpoints[0])[0]['dev'], 'fixtureguard')
            with socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(ethertype)) as capture:
                capture.bind(('fixturepeer', ethertype))
                capture.settimeout(2)
                for endpoint, port in zip(endpoints, (1194, 2050), strict=True):
                    with socket.socket(socket_family, socket.SOCK_DGRAM) as outgoing:
                        outgoing.setsockopt(socket.SOL_SOCKET, socket.SO_MARK, MARK)
                        outgoing.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b'fixturewan\0')
                        outgoing.connect((endpoint, port))
                        self.assertEqual(outgoing.getsockname()[0], address.split('/')[0])
                        payload = f'marked {endpoint}:{port}'.encode()
                        outgoing.send(payload)
                        while not capture.recv(2048).endswith(payload):
                            pass
                with socket.socket(socket_family, socket.SOCK_STREAM) as outgoing:
                    outgoing.setsockopt(socket.SOL_SOCKET, socket.SO_MARK, MARK)
                    outgoing.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b'fixturewan\0')
                    outgoing.setblocking(False)
                    outgoing.connect_ex((endpoints[-1], 2443))
                    while True:
                        packet = capture.recv(2048)
                        offset = (packet[0] & 15) * 4 if family == 4 else 40
                        if len(packet) >= offset + 20 and packet[9 if family == 4 else 6] == socket.IPPROTO_TCP:
                            destination_port = struct.unpack_from('!H', packet, offset + 2)[0]
                            if destination_port == 2443 and packet[offset + 13] & 2:
                                break
            self.command(flag, 'route', 'del', 'default', 'table', str(TABLE), 'dev', 'fixturewan')
            with self.assertRaises(RuntimeError):
                runner.read_ip(family, 'route', 'get', endpoints[-1], 'mark', hex(MARK))
            self.assertEqual(runner.read_ip(family, 'route', 'get', endpoints[-1])[0]['dev'], 'fixtureguard')
        change_policy(runner, remove=True)
        self.assertFalse(has_policy(runner))
        self.assertTrue(any(row.get('priority') == 30801 for row in runner.read_ip(4, 'rule', 'show')))

    def test_site_selection_with_no_adguard_default_preserves_vpn_server_egress(self):
        self.command('link', 'add', 'fixturewan', 'type', 'veth', 'peer', 'name', 'fixturepeer')
        peer_mac = '02:00:00:00:00:02'
        self.command('link', 'set', 'fixturepeer', 'address', peer_mac, 'up')
        self.command('link', 'set', 'fixturewan', 'up')
        corporate4, _corporate6 = self.tunnel()
        _adguard4, adguard6 = self.tunnel('203.0.113.2', '2001:db8:3::2', name='fixtureguard', prefix4=32)
        runner = CommandRunner()
        backend = KernelBackend(runner)
        assignments = {'198.51.100.8': Assignment('fixture-corporate', corporate4),
                       '2001:db8::8': Assignment('fixture-adguard', adguard6)}
        journal = {'objects': [], 'pending_objects': [], 'known': [], 'tables': {}, 'priority': 0}
        cases = (
            (4, socket.AF_INET, 0x0800, '198.18.0.2/24', ('198.51.100.99', '203.0.113.99')),
            (6, socket.AF_INET6, 0x86DD, '2001:db8:2::2/64', ('2001:db8:4::99', '2001:db8:5::99')),
        )
        for family, _, _, source, endpoints in cases:
            flag = f'-{family}'
            self.command(flag, 'address', 'add', source, 'dev', 'fixturewan', *(['nodad'] if family == 6 else []))
            self.command(flag, 'route', 'add', 'default', 'dev', 'fixturewan')
            self.command(flag, 'route', 'add', 'default', 'table', '880', 'dev', 'fixtureguard')
            self.command(flag, 'rule', 'add', 'priority', '30801', 'table', '880')
            self.assertEqual(runner.read_ip(family, 'route', 'get', endpoints[0])[0]['dev'], 'fixtureguard')
            for endpoint in endpoints:
                self.command(flag, 'neigh', 'replace', endpoint, 'lladdr', peer_mac, 'nud', 'permanent', 'dev', 'fixturewan')

        # Model the vendor's TUN/NONE contract: a live TUN with no vendor default policy.
        for family, *_ in cases:
            self.command(f'-{family}', 'rule', 'del', 'priority', '30801', 'table', '880')
            self.command(f'-{family}', 'route', 'del', 'default', 'table', '880', 'dev', 'fixtureguard')
        manifest = backend.apply(assignments, journal, INSTALLATION)
        self.assertEqual(manifest['failures'], {})
        self.assertEqual(runner.read_ip(4, 'route', 'get', '198.51.100.8')[0]['dev'], 'fixturevpn')
        self.assertEqual(runner.read_ip(6, 'route', 'get', '2001:db8::8')[0]['dev'], 'fixtureguard')
        self.command('link', 'del', 'fixturevpn')
        with self.assertRaises(RuntimeError): runner.read_ip(4, 'route', 'get', '198.51.100.8')

        # Capture actual packets from a first connection and a fresh socket after remote reselection.
        for family, socket_family, ethertype, source, endpoints in cases:
            with socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(ethertype)) as capture:
                capture.bind(('fixturepeer', ethertype))
                capture.settimeout(2)
                for endpoint, port in zip(endpoints, (1194, 2050), strict=True):
                    payload = f'vpn-fixture {endpoint}:{port}'.encode()
                    with socket.socket(socket_family, socket.SOCK_DGRAM) as outgoing:
                        outgoing.connect((endpoint, port))
                        self.assertEqual(outgoing.getsockname()[0], source.split('/')[0])
                        self.assertEqual(outgoing.send(payload), len(payload))
                    self.assertTrue(capture.recv(2048).endswith(payload))


if __name__ == '__main__':
    unittest.main()
