"""Match each saved NM host entry to a specific live legacy policy."""
import ipaddress
import socket
import struct

from .kernel_objects import table_number
from .migration_fields import entry_address

RULE_FIELDS = {'to', 'to-len', 'priority', 'table', 'family', 'from', 'from-len', 'action'}
ROUTE_FIELDS = {'dest', 'prefix', 'next-hop', 'metric', 'table', 'src', 'type'}


def matches_entry(item: dict, profile: dict, field: str, row) -> bool:
    family, kind, live = item['family'], item['kind'], item['data']
    if (kind == 'rule') != (field == 'routing-rules') or str(live.get('protocol')) not in ('static', '4'):
        return False
    network = ipaddress.ip_network(live.get('dst', live.get('to')), strict=False)
    if network.prefixlen != network.max_prefixlen or entry_address(family, field, row) != str(network.network_address):
        return False
    if kind == 'rule':
        address_family = socket.AF_INET if family == 4 else socket.AF_INET6
        unspecified = '0.0.0.0' if family == 4 else '::'
        return (set(row) <= RULE_FIELDS and row.get('family', address_family) == address_family
                and row.get('to-len', network.max_prefixlen) == network.max_prefixlen
                and row.get('from', 'all') in ('all', unspecified) and row.get('from-len', 0) == 0
                and row.get('action', 1) == 1 and row.get('priority') == live.get('priority')
                and table_number(row.get('table')) == table_number(live.get('table')))
    if field == 'route-data':
        if set(row) - ROUTE_FIELDS or row.get('type', 'unicast') != 'unicast':
            return False
        saved = row
    else:
        if len(row) != 4:
            return False
        try:
            gateway = (socket.inet_ntop(socket.AF_INET, struct.pack('=I', row[2])) if family == 4
                       else str(ipaddress.IPv6Address(bytes(row[2]))))
        except (ValueError, TypeError, struct.error):
            return False
        saved = {'next-hop': gateway, 'metric': row[3] or -1}
    interfaces = profile.get('interfaces', []) or [profile['settings'].get('connection', {}).get('interface-name')]
    setting = profile['settings'].get(f'ipv{family}', {})
    gateway = saved.get('next-hop', '')
    gateway = '' if gateway in ('0.0.0.0', '::') else gateway
    table = saved.get('table') or setting.get('route-table') or 254
    metric = saved.get('metric', setting.get('route-metric', -1))
    scope = 'global' if gateway or family == 6 else 'link'
    return (live.get('dev') in interfaces and table_number(live.get('table', 254)) == table
            and live.get('gateway', '') == gateway and live.get('prefsrc', '') == saved.get('src', '')
            and live.get('metric', -1) == metric and live.get('scope', scope) == scope
            and live.get('pref', 'medium') == 'medium')
