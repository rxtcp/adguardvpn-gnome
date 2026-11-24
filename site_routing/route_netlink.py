"""Restore a reviewed host route with a numeric output interface in one write."""
import ipaddress
import os
import socket
import struct

from .kernel_objects import table_number
from .legacy_objects import legacy_arguments

# Linux UAPI values from linux/netlink.h and linux/rtnetlink.h.
NLMSG_ERROR = 2
RTM_NEWROUTE = 24
NLM_F_REQUEST, NLM_F_ACK, NLM_F_EXCL, NLM_F_CREATE = 1, 4, 0x200, 0x400
RTA_DST, RTA_OIF, RTA_GATEWAY, RTA_PRIORITY, RTA_PREFSRC, RTA_TABLE, RTA_PREF = 1, 4, 5, 6, 7, 15, 20
HEADER = struct.Struct('=IHHII')  # nlmsghdr
ROUTE = struct.Struct('=8BI')  # rtmsg
U32 = struct.Struct('=I')
S32 = struct.Struct('=i')


def _attribute(kind: int, payload: bytes) -> bytes:
    return struct.pack('=HH', 4 + len(payload), kind) + payload + bytes(-len(payload) % 4)


def restore_legacy_route(item: dict, ifindex: int) -> None:
    legacy_arguments(item, 'add')
    if item['kind'] != 'route' or type(ifindex) is not int or not 1 <= ifindex <= 0x7fffffff:
        raise ValueError('A reviewed route and a kernel output interface are required.')
    row = item['data']
    network = ipaddress.ip_network(row['dst'], strict=False)
    family = socket.AF_INET if network.version == 4 else socket.AF_INET6
    table = table_number(row.get('table', 254))
    protocol = str(row.get('protocol', 'static'))
    protocol_number = int(protocol) if protocol.isdecimal() else {'kernel': 2, 'boot': 3, 'static': 4}[protocol]
    default_scope = 253 if network.version == 4 and not row.get('gateway') else 0
    scope = {'global': 0, 'universe': 0, 'link': 253, 'host': 254}.get(row.get('scope'), default_scope)
    body = ROUTE.pack(family, network.prefixlen, 0, 0, table if table <= 255 else 0, protocol_number, scope, 1, 0)
    body += _attribute(RTA_DST, network.network_address.packed) + _attribute(RTA_OIF, U32.pack(ifindex))
    if table > 255:
        body += _attribute(RTA_TABLE, U32.pack(table))
    for field, attribute in (('gateway', RTA_GATEWAY), ('prefsrc', RTA_PREFSRC)):
        if row.get(field):
            body += _attribute(attribute, ipaddress.ip_address(row[field]).packed)
    if 'metric' in row:
        body += _attribute(RTA_PRIORITY, U32.pack(row['metric']))
    if row.get('pref') in ('low', 'medium', 'high'):
        body += _attribute(RTA_PREF, bytes([{'low': 3, 'medium': 0, 'high': 1}[row['pref']]]))

    flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_EXCL | NLM_F_CREATE
    sequence = 1  # One request on a private socket.
    message = HEADER.pack(HEADER.size + len(body), RTM_NEWROUTE, flags, sequence, 0) + body
    with socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, socket.NETLINK_ROUTE) as channel:
        channel.settimeout(12)
        channel.bind((0, 0))
        channel.sendto(message, (0, 0))
        reply, sender = channel.recvfrom(65536)
    if sender != (0, 0) or len(reply) < HEADER.size + S32.size:
        raise RuntimeError('The kernel did not confirm legacy route restoration.')
    length, kind, _, reply_sequence, _ = HEADER.unpack_from(reply)
    if kind != NLMSG_ERROR or reply_sequence != sequence or not HEADER.size + S32.size <= length <= len(reply):
        raise RuntimeError('The kernel did not confirm legacy route restoration.')
    error = S32.unpack_from(reply, HEADER.size)[0]
    if error:
        raise RuntimeError(f'The kernel refused legacy route restoration. {os.strerror(-error)}')
