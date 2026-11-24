"""Verify the reviewed route request and require an ACK from the kernel."""
import errno
import ipaddress
import socket
import struct
import unittest
from unittest.mock import patch

from site_routing.commands import CommandRunner


class LegacyRouteNetlinkTests(unittest.TestCase):
    def setUp(self):
        self.v4 = {'kind': 'route', 'family': 4, 'data': {'dst': '198.51.100.8/32', 'dev': 'fixturevpn'}}
        patched = patch('site_routing.route_netlink.socket.socket')
        self.socket = patched.start()
        self.addCleanup(patched.stop)
        self.channel = self.socket.return_value.__enter__.return_value
        self.channel.recvfrom.return_value = (self.ack(), (0, 0))

    @staticmethod
    def ack(error=0, *, size=20, kind=2, sequence=1):
        return struct.pack('=IHHIIi', size, kind, 0, sequence, 0, error)

    def request(self, item):
        CommandRunner().restore_legacy_route(item, 17)
        message, peer = self.channel.sendto.call_args.args
        self.assertEqual(peer, (0, 0))
        self.assertEqual(struct.unpack_from('=IHHII', message), (len(message), 24, 0x605, 1, 0))
        route = struct.unpack_from('=8BI', message, 16)
        attributes = {}
        offset = 28
        while offset < len(message):
            size, kind = struct.unpack_from('=HH', message, offset)
            attributes[kind] = message[offset+4:offset+size]
            offset += (size + 3) & ~3
        return route, attributes

    def test_ipv4_request_uses_only_the_verified_index_for_the_output_interface(self):
        route, attributes = self.request(self.v4)
        self.assertEqual(route, (socket.AF_INET, 32, 0, 0, 254, 4, 253, 1, 0))
        self.assertEqual(attributes, {1: ipaddress.ip_address('198.51.100.8').packed, 4: struct.pack('=I', 17)})

    def test_ipv6_request_preserves_table_gateway_source_metric_and_preference(self):
        row = {'dst': '2001:db8::8/128', 'dev': 'fixturevpn', 'table': 777, 'protocol': 4,
               'gateway': '2001:db8:1::1', 'prefsrc': '2001:db8:1::2', 'metric': 20,
               'scope': 'global', 'pref': 'high'}
        route, attributes = self.request({'kind': 'route', 'family': 6, 'data': row})
        self.assertEqual(route, (socket.AF_INET6, 128, 0, 0, 0, 4, 0, 1, 0))
        self.assertEqual(attributes, {1: ipaddress.ip_address('2001:db8::8').packed, 4: struct.pack('=I', 17),
                                      5: ipaddress.ip_address(row['gateway']).packed, 7: ipaddress.ip_address(row['prefsrc']).packed,
                                      6: struct.pack('=I', 20), 15: struct.pack('=I', 777), 20: b'\x01'})

    def test_invalid_route_or_index_is_rejected_before_opening_a_socket(self):
        rule = {'kind': 'rule', 'family': 4, 'data': {'dst': '198.51.100.8/32', 'priority': 100, 'table': 777}}
        for item, index in ((rule, 17), (self.v4, True), (self.v4, 0), (self.v4, 2**31)):
            with self.subTest(item=item, index=index), self.assertRaisesRegex(ValueError, 'kernel output interface'):
                CommandRunner().restore_legacy_route(item, index)
        self.socket.assert_not_called()

    def test_rejected_or_unrelated_ack_cannot_confirm_restoration(self):
        for data, sender in ((b'', (0, 0)), (self.ack(), (123, 0)), (self.ack(kind=24), (0, 0)),
                             (self.ack(sequence=3), (0, 0)), (self.ack(size=19), (0, 0)), (self.ack(size=21), (0, 0))):
            self.channel.recvfrom.return_value = (data, sender)
            with self.assertRaisesRegex(RuntimeError, 'did not confirm'):
                CommandRunner().restore_legacy_route(self.v4, 17)
        self.channel.recvfrom.return_value = (self.ack(-errno.ENODEV), (0, 0))
        with self.assertRaisesRegex(RuntimeError, 'kernel refused'):
            CommandRunner().restore_legacy_route(self.v4, 17)
