"""Read and change reviewed host routes by numeric output interface."""
import ipaddress
import os
import socket
import struct

from .kernel_objects import table_number
from .legacy_objects import legacy_arguments

# Linux UAPI values from linux/netlink.h and linux/rtnetlink.h.
NLMSG_ERROR, NLMSG_DONE = 2, 3
RTM_NEWROUTE, RTM_DELROUTE, RTM_GETROUTE = 24, 25, 26
NLM_F_REQUEST, NLM_F_ACK, NLM_F_EXCL, NLM_F_CREATE = 1, 4, 0x200, 0x400
NLM_F_DUMP_INTR, NLM_F_DUMP = 0x10, 0x300
RTA_DST, RTA_OIF, RTA_GATEWAY, RTA_PRIORITY, RTA_PREFSRC, RTA_TABLE, RTA_PREF = 1, 4, 5, 6, 7, 15, 20
RTA_CACHEINFO = 12
HEADER = struct.Struct('=IHHII')  # nlmsghdr
ROUTE = struct.Struct('=8BI')  # rtmsg
ATTRIBUTE = struct.Struct('=HH')  # rtattr
U32 = struct.Struct('=I')
S32 = struct.Struct('=i')
MAX_DUMP_BYTES = 2 * 1024 * 1024
SEQUENCE = 1  # One request per private socket.


def _attribute(kind: int, payload: bytes) -> bytes:
    return ATTRIBUTE.pack(ATTRIBUTE.size + len(payload), kind) + payload + bytes(-len(payload) % 4)


def _route_fields(item: dict, action: str) -> tuple[tuple, dict[int, bytes]]:
    legacy_arguments(item, action)
    if item['kind'] != 'route':
        raise ValueError('A reviewed route and a kernel output interface are required.')
    row = item['data']
    network = ipaddress.ip_network(row['dst'], strict=False)
    family = socket.AF_INET if network.version == 4 else socket.AF_INET6
    table = table_number(row.get('table', 254))
    protocol = str(row.get('protocol', 'static'))
    protocol_number = int(protocol) if protocol.isdecimal() else {'kernel': 2, 'boot': 3, 'static': 4}[protocol]
    default_scope = 0
    if network.version == 4:
        if action == 'del':
            default_scope = 255  # Match IPv4 deletions without an explicit scope, as iproute2 does.
        elif not row.get('gateway'):
            default_scope = 253
    scope = {'global': 0, 'universe': 0, 'link': 253, 'host': 254}.get(row.get('scope'), default_scope)
    fields = (family, network.prefixlen, 0, 0, table, protocol_number, scope, 1, 0)
    attributes = {RTA_DST: network.network_address.packed}
    for field, attribute in (('gateway', RTA_GATEWAY), ('prefsrc', RTA_PREFSRC)):
        if row.get(field):
            attributes[attribute] = ipaddress.ip_address(row[field]).packed
    if 'metric' in row:
        attributes[RTA_PRIORITY] = U32.pack(row['metric'])
    if row.get('pref') in ('low', 'medium', 'high'):
        attributes[RTA_PREF] = bytes([{'low': 3, 'medium': 0, 'high': 1}[row['pref']]])
    return fields, attributes


def _message(kind: int, flags: int, body: bytes) -> bytes:
    return HEADER.pack(HEADER.size + len(body), kind, flags, SEQUENCE, 0) + body


def change_legacy_route(item: dict, action: str, ifindex: int) -> None:
    fields, attributes = _route_fields(item, action)
    if type(ifindex) is not int or not 1 <= ifindex <= 0x7fffffff:
        raise ValueError('A reviewed route and a kernel output interface are required.')
    table = fields[4]
    if table > 255:
        fields = (*fields[:4], 0, *fields[5:])
        attributes[RTA_TABLE] = U32.pack(table)
    attributes[RTA_OIF] = U32.pack(ifindex)
    body = ROUTE.pack(*fields) + b''.join(_attribute(kind, data) for kind, data in attributes.items())

    flags = NLM_F_REQUEST | NLM_F_ACK
    message_type = RTM_DELROUTE
    if action == 'add':
        flags |= NLM_F_EXCL | NLM_F_CREATE
        message_type = RTM_NEWROUTE
    message = _message(message_type, flags, body)
    with socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, socket.NETLINK_ROUTE) as channel:
        channel.settimeout(12)
        channel.bind((0, 0))
        channel.sendto(message, (0, 0))
        reply, sender = channel.recvfrom(65536)
    if sender != (0, 0) or len(reply) < HEADER.size + S32.size:
        raise RuntimeError('The kernel did not confirm the legacy route change.')
    length, kind, _, reply_sequence, _ = HEADER.unpack_from(reply)
    if kind != NLMSG_ERROR or reply_sequence != SEQUENCE or not HEADER.size + S32.size <= length <= len(reply):
        raise RuntimeError('The kernel did not confirm the legacy route change.')
    error = S32.unpack_from(reply, HEADER.size)[0]
    if error:
        raise RuntimeError(f'The kernel refused the legacy route change. {os.strerror(-error)}')


def _frames(data: bytes, layout: struct.Struct):
    offset = 0
    while offset < len(data):
        if len(data) - offset < layout.size:
            raise RuntimeError('Invalid kernel route dump.')
        fields = layout.unpack_from(data, offset)
        length = fields[0]
        if not layout.size <= length <= len(data) - offset:
            raise RuntimeError('Invalid kernel route dump.')
        yield fields, data[offset + layout.size:offset + length]
        offset += (length + 3) & ~3


def _dump_routes(family: int):
    total = 0
    with socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, socket.NETLINK_ROUTE) as channel:
        channel.settimeout(12)
        channel.bind((0, 0))
        channel.sendto(_message(RTM_GETROUTE, NLM_F_REQUEST | NLM_F_DUMP, ROUTE.pack(family, 0, 0, 0, 0, 0, 0, 0, 0)), (0, 0))
        while True:
            packet, _, packet_flags, sender = channel.recvmsg(65536)
            total += len(packet)
            if sender != (0, 0) or packet_flags & socket.MSG_TRUNC or not packet or total > MAX_DUMP_BYTES:
                raise RuntimeError('Invalid or oversized kernel route dump.')
            for (_, kind, flags, sequence, _), data in _frames(packet, HEADER):
                if sequence != SEQUENCE or flags & NLM_F_DUMP_INTR:
                    raise RuntimeError('The kernel route dump was interrupted.')
                if kind == NLMSG_DONE and data[:S32.size] == S32.pack(0):
                    return
                if kind != RTM_NEWROUTE or len(data) < ROUTE.size:
                    raise RuntimeError('Invalid kernel route dump.')
                yield data


def legacy_route_index(item: dict) -> int | None:
    expected, attributes = _route_fields(item, 'add')
    attributes.setdefault(RTA_PREF, b'\0')
    attributes.setdefault(RTA_PRIORITY, U32.pack(0))
    indices = set()
    for data in _dump_routes(expected[0]):
        fields = ROUTE.unpack_from(data)
        if fields[:4] != expected[:4] or fields[5:] != expected[5:]:
            continue
        actual = {}
        for (_, kind), payload in _frames(data[ROUTE.size:], ATTRIBUTE):
            if kind in actual:
                raise RuntimeError('Invalid duplicate kernel route attribute.')
            actual[kind] = payload
        table = actual.pop(RTA_TABLE, U32.pack(fields[4]))
        if table != U32.pack(expected[4]):
            continue
        output = actual.pop(RTA_OIF, b'')
        actual.pop(RTA_CACHEINFO, None)
        actual.setdefault(RTA_PREF, b'\0')
        actual.setdefault(RTA_PRIORITY, U32.pack(0))
        if actual == attributes:
            if len(output) != U32.size or not 1 <= U32.unpack(output)[0] <= 0x7fffffff:
                raise RuntimeError('The kernel route has no verifiable output interface.')
            indices.add(U32.unpack(output)[0])
    if not indices:
        return None
    if len(indices) != 1:
        raise RuntimeError('The reviewed route matches multiple kernel output interfaces.')
    index = indices.pop()
    # Resolve the name from this record's index. Never look up an index by the saved name.
    if socket.if_indextoname(index) != item['data']['dev']:
        raise RuntimeError('The legacy route interface identity changed.')
    return index
