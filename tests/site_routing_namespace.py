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

    def tunnel(self, source4='192.0.2.2', source6='2001:db8:1::2'):
        self.command('link', 'add', 'fixturevpn', 'type', 'dummy')
        self.command('link', 'set', 'fixturevpn', 'up')
        self.command('address', 'add', source4 + '/24', 'dev', 'fixturevpn')
        self.command('-6', 'address', 'add', source6 + '/64', 'dev', 'fixturevpn', 'nodad')
        index = socket.if_nametoindex('fixturevpn')
        return NetworkPath('fixturevpn', index, source4), NetworkPath('fixturevpn', index, source6)

    def test_verified_routes_disconnect_reconnect_collision_and_boot_guard(self):
        self.command('link', 'set', 'lo', 'up')
        self.command('link', 'add', 'fixturewan', 'type', 'dummy')
        self.command('link', 'set', 'fixturewan', 'up')
        self.command('address', 'add', '198.18.0.2/24', 'dev', 'fixturewan')
        self.command('-6', 'address', 'add', '2001:db8:2::2/64', 'dev', 'fixturewan', 'nodad')
        self.command('route', 'add', 'default', 'dev', 'fixturewan')
        self.command('-6', 'route', 'add', 'default', 'dev', 'fixturewan')
        path4, path6 = self.tunnel()
        # A foreign VPN owns the ordinary default path and its own routing table.
        for family in (4, 6):
            self.command(f'-{family}', 'route', 'add', 'default', 'table', '880', 'dev', 'fixturevpn')
            self.command(f'-{family}', 'rule', 'add', 'priority', '1000', 'table', '880')
        runner, backend = CommandRunner(), KernelBackend(CommandRunner())
        assignments = {'198.51.100.8': Assignment('fixture-vpn', path4),
                       '2001:db8::8': Assignment('fixture-vpn', path6)}
        journal = {'objects': [], 'pending_objects': [], 'known': list(assignments), 'tables': {}, 'priority': 0}
        manifest = backend.apply(assignments, journal, INSTALLATION)
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
        self.assertEqual(runner.read_ip(4, 'route', 'get', '203.0.113.10')[0]['dev'], 'fixturevpn')
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
        for family in (4, 6):
            self.command(f'-{family}', 'route', 'add', 'default', 'table', '880', 'dev', 'fixturevpn')
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
        self.assertEqual(runner.read_ip(4, 'route', 'get', '198.51.100.8')[0]['dev'], 'fixturevpn')
        self.assertTrue(any(row.get('priority') == 1000 and str(row.get('table')) == '880' for row in runner.read_ip(4, 'rule', 'show')))
        self.assertFalse(any(row.get('table', {}).get('name') == 'adguardvpn_site_routing' for row in runner.nft_json('list', 'tables')['nftables']))
        # The boot phase restores a deny-only table before any daemon/provider discovery.
        backend.block(assignments, INSTALLATION)
        for socket_family, address in ((socket.AF_INET, '198.51.100.8'), (socket.AF_INET6, '2001:db8::8')):
            with socket.socket(socket_family, socket.SOCK_DGRAM) as outgoing:
                with self.assertRaises(OSError): outgoing.sendto(b'fixture', (address, 443))


if __name__ == '__main__':
    unittest.main()
