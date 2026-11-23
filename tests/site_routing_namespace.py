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
        runner, backend = CommandRunner(), KernelBackend(CommandRunner())
        assignments = {'198.51.100.8': Assignment('fixture-vpn', path4),
                       '2001:db8::8': Assignment('fixture-vpn', path6)}
        journal = {'objects': [], 'pending_objects': [], 'known': list(assignments), 'tables': {}, 'priority': 0}
        manifest = backend.apply(assignments, journal, INSTALLATION)
        for family, address in ((4, '198.51.100.8'), (6, '2001:db8::8')):
            self.assertEqual(runner.read_ip(family, 'route', 'get', address)[0]['dev'], 'fixturevpn')
            self.assertTrue(any(row.get('action', row.get('type')) == 'unreachable' for row in runner.read_ip(family, 'rule', 'show')))
        self.command('link', 'del', 'fixturevpn')
        for family, address in ((4, '198.51.100.8'), (6, '2001:db8::8')):
            with self.assertRaises(RuntimeError):
                runner.read_ip(family, 'route', 'get', address)
        # A foreign higher-priority policy cannot bypass the independent egress guard.
        self.command('-4', 'rule', 'add', 'priority', '1', 'to', '198.51.100.8/32', 'table', 'main')
        self.assertEqual(runner.read_ip(4, 'route', 'get', '198.51.100.8')[0]['dev'], 'fixturewan')
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as outgoing:
            with self.assertRaises(OSError):
                outgoing.sendto(b'fixture', ('198.51.100.8', 443))
        self.command('-4', 'rule', 'del', 'priority', '1', 'to', '198.51.100.8/32', 'table', 'main')
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
        self.assertEqual(runner.read_ip(4, 'route', 'get', '198.51.100.8')[0]['dev'], 'fixturewan')
        self.assertFalse(any(row.get('table', {}).get('name') == 'adguardvpn_site_routing' for row in runner.nft_json('list', 'tables')['nftables']))
        # The boot phase restores a deny-only table before any daemon/provider discovery.
        backend.block(assignments, INSTALLATION)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as outgoing:
            with self.assertRaises(OSError): outgoing.sendto(b'fixture', ('198.51.100.8', 443))


if __name__ == '__main__':
    unittest.main()
