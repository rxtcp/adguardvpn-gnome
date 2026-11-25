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

    @staticmethod
    def frame(kind, payload, *, flags=2, sequence=1):
        size = 16 + len(payload)
        return struct.pack('=IHHII', size, kind, flags, sequence, 0) + payload + bytes(-size % 4)

    def route_record(self, index=17, *, table=254, prefix=32, extra=b''):
        destination = ipaddress.ip_address('198.51.100.8').packed
        attributes = struct.pack('=HH4s', 8, 1, destination)
        attributes += struct.pack('=HHI', 8, 4, index)
        header = struct.pack('=8BI', socket.AF_INET, prefix, 0, 0, table, 4, 253, 1, 0)
        return self.frame(24, header + attributes + extra)

    def received_dump(self, records):
        done = self.frame(3, struct.pack('=i', 0))
        self.channel.recvmsg.side_effect = [(record, [], 0, (0, 0)) for record in [*records, done]]

    def request(self, item, action='add'):
        CommandRunner().change_legacy_route(item, action, 17)
        message, peer = self.channel.sendto.call_args.args
        self.assertEqual(peer, (0, 0))
        message_type, flags = (24, 0x605) if action == 'add' else (25, 0x005)
        self.assertEqual(struct.unpack_from('=IHHII', message), (len(message), message_type, flags, 1, 0))
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

    def test_ipv4_deletion_matches_output_index_and_does_not_request_creation(self):
        route, attributes = self.request(self.v4, 'del')
        self.assertEqual(route, (socket.AF_INET, 32, 0, 0, 254, 4, 255, 1, 0))
        self.assertEqual(attributes, {1: ipaddress.ip_address('198.51.100.8').packed, 4: struct.pack('=I', 17)})

    def test_ipv4_gateway_defaults_to_global_scope(self):
        route, _ = self.request({**self.v4, 'data': {**self.v4['data'], 'gateway': '192.0.2.1'}})
        self.assertEqual(route[6], 0)

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
                CommandRunner().change_legacy_route(item, 'add', index)
        self.socket.assert_not_called()

    def test_rejected_or_unrelated_ack_cannot_confirm_restoration(self):
        for data, sender in ((b'', (0, 0)), (self.ack(), (123, 0)), (self.ack(kind=24), (0, 0)),
                             (self.ack(sequence=3), (0, 0)), (self.ack(size=19), (0, 0)), (self.ack(size=21), (0, 0))):
            self.channel.recvfrom.return_value = (data, sender)
            with self.assertRaisesRegex(RuntimeError, 'did not confirm'):
                CommandRunner().change_legacy_route(self.v4, 'add', 17)
        self.channel.recvfrom.return_value = (self.ack(-errno.ENODEV), (0, 0))
        with self.assertRaisesRegex(RuntimeError, 'kernel refused'):
            CommandRunner().change_legacy_route(self.v4, 'del', 17)

    def test_output_index_comes_from_the_exact_route_record(self):
        different_metric = self.route_record(27, extra=struct.pack('=HHI', 8, 6, 100))
        cache_info = struct.pack('=HHI', 8, 12, 0)
        self.received_dump([self.route_record(25, table=253) + self.route_record(26, prefix=24),
                            different_metric + self.route_record(extra=cache_info)])
        with patch('site_routing.route_netlink.socket.if_indextoname', return_value='fixturevpn') as name:
            self.assertEqual(CommandRunner().legacy_route_index(self.v4), 17)
        name.assert_called_once_with(17)
        message, peer = self.channel.sendto.call_args.args
        self.assertEqual(peer, (0, 0))
        self.assertEqual(struct.unpack_from('=IHHII', message), (28, 26, 0x301, 1, 0))

    def test_missing_ambiguous_or_renamed_route_cannot_be_selected_by_the_old_name(self):
        self.received_dump([])
        self.assertIsNone(CommandRunner().legacy_route_index(self.v4))
        self.received_dump([self.route_record(), self.route_record(27)])
        with self.assertRaisesRegex(RuntimeError, 'multiple kernel output interfaces'):
            CommandRunner().legacy_route_index(self.v4)
        self.received_dump([self.route_record()])
        with patch('site_routing.route_netlink.socket.if_indextoname', return_value='renamedvpn') as name:
            with self.assertRaisesRegex(RuntimeError, 'interface identity changed'):
                CommandRunner().legacy_route_index(self.v4)
        name.assert_called_once_with(17)

    def test_malformed_route_records_cannot_supply_an_output_index(self):
        malformed_size = bytearray(self.route_record())
        struct.pack_into('=H', malformed_size, 36, 3)
        for record in (self.route_record(0), self.route_record(2**31), self.route_record()[:-4],
                       bytes(malformed_size), self.route_record(extra=struct.pack('=HHI', 8, 4, 27))):
            with self.subTest(record=record), self.assertRaises(RuntimeError):
                self.received_dump([record])
                CommandRunner().legacy_route_index(self.v4)
        missing_output = bytearray(self.route_record())
        struct.pack_into('=H', missing_output, 38, 12)
        self.received_dump([bytes(missing_output)])
        with self.assertRaisesRegex(RuntimeError, 'no verifiable output interface'):
            CommandRunner().legacy_route_index(self.v4)

    def test_invalid_or_incomplete_netlink_dump_cannot_authorize_a_route_change(self):
        invalid = ((b'', (0, 0)), (self.route_record(), (123, 0)), (b'\0', (0, 0)),
                   (self.frame(24, b'x'), (0, 0)), (self.frame(3, struct.pack('=i', -errno.EINTR)), (0, 0)),
                   (self.frame(3, bytes(4), sequence=3), (0, 0)), (self.frame(3, bytes(4), flags=0x10), (0, 0)))
        for data, sender in invalid:
            with self.subTest(data=data, sender=sender), self.assertRaisesRegex(RuntimeError, 'route dump'):
                self.channel.recvmsg.side_effect = [(data, [], 0, sender)]
                CommandRunner().legacy_route_index(self.v4)
        self.channel.recvmsg.side_effect = [(self.route_record(), [], socket.MSG_TRUNC, (0, 0))]
        with self.assertRaisesRegex(RuntimeError, 'oversized'):
            CommandRunner().legacy_route_index(self.v4)
        with patch('site_routing.route_netlink.MAX_DUMP_BYTES', 4):
            self.received_dump([self.route_record()])
            with self.assertRaisesRegex(RuntimeError, 'oversized'):
                CommandRunner().legacy_route_index(self.v4)
