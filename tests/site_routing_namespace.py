"""Real Linux routing/nft tests. The parent network namespace must be different.

Run only via the CI wrapper or an explicitly created disposable namespace.
There are no vendor binaries, credentials, corporate networks or internet peers.
"""
import os
import socket
import subprocess
import unittest

from site_routing.commands import CommandRunner, IP
from site_routing.kernel import KernelBackend
from site_routing.models import Assignment, NetworkPath

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
