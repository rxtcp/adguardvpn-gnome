"""Match live legacy policies to explicit saved NM selectors, never just an IP."""
import ipaddress
import socket
import struct

from .kernel_objects import table_number
from .migration_fields import entry_address


def matches_profile(item: dict, profile: dict) -> bool:
    family, kind, live = item['family'], item['kind'], item['data']
    if str(live.get('protocol')) not in ('static', '4'):
        return False
    address = str(ipaddress.ip_network(live.get('dst', live.get('to')), strict=False).network_address)
    setting = profile['settings'].get(f'ipv{family}', {})
    fields = ('routing-rules',) if kind == 'rule' else ('route-data', 'routes')
    for field in fields:
        for row in setting.get(field, []):
            if entry_address(family, field, row) != address:
                continue
            if kind == 'rule':
                simple = {'to', 'to-len', 'priority', 'table', 'family', 'from', 'from-len', 'action'}
                if set(row) <= simple and row.get('from', 'all') in ('all', '0.0.0.0', '::') and row.get('from-len', 0) == 0 and row.get('action', 1) == 1 and row.get('priority') == live.get('priority') and table_number(row.get('table')) == table_number(live.get('table')):
                    return True
            else:
                interfaces = profile.get('interfaces', []) or [profile['settings'].get('connection', {}).get('interface-name')]
                if live.get('dev') not in interfaces:
                    continue
                if field == 'route-data':
                    saved = row
                else:
                    gateway = socket.inet_ntop(socket.AF_INET, struct.pack('=I', row[2])) if family == 4 else str(ipaddress.IPv6Address(bytes(row[2])))
                    saved = {'next-hop': gateway, 'metric': row[3] or -1}
                gateway = saved.get('next-hop', '')
                gateway = '' if gateway in ('0.0.0.0', '::') else gateway
                table = saved.get('table') or setting.get('route-table') or 254
                metric = saved.get('metric', setting.get('route-metric', -1))
                if table_number(live.get('table', 254)) == table and live.get('gateway', '') == gateway and live.get('prefsrc', '') == saved.get('src', '') and live.get('metric', -1) == metric:
                    return True
    return False
