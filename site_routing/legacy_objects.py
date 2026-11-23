"""Exact legacy-object arguments, used only after a separately confirmed NM diff."""
import ipaddress
import re

from .kernel_objects import table_number


def legacy_arguments(item: dict, action: str) -> tuple[str, ...]:
    kind, family, row = item['kind'], item['family'], item['data']
    if kind not in ('rule', 'route') or family not in (4, 6) or action not in ('add', 'del'):
        raise ValueError('Unsupported legacy object.')
    network = ipaddress.ip_network(row.get('dst', row.get('to', '')), strict=False)
    if network.version != family or network.prefixlen != network.max_prefixlen:
        raise ValueError('Only exactly matched host policies can be migrated.')
    table = table_number(row.get('table', 254))
    if not 1 <= table <= 2147483647 or table == 255:
        raise ValueError('Unsupported legacy table.')
    protocol = str(row.get('protocol', 'static'))
    if protocol not in ('kernel', 'boot', 'static') and not (protocol.isdigit() and 0 <= int(protocol) <= 255):
        raise ValueError('Unsupported legacy protocol.')
    if kind == 'rule':
        allowed = {'priority', 'src', 'dst', 'to', 'table', 'protocol', 'flags', 'action'}
        if set(row) - allowed or row.get('src', 'all') != 'all' or row.get('flags') or row.get('action', 'lookup') != 'lookup':
            raise ValueError('Complex legacy selectors require manual migration.')
        priority = row.get('priority')
        if type(priority) is not int or not 1 <= priority <= 32765:
            raise ValueError('Unsupported legacy priority.')
        return ('rule', action, 'priority', str(priority), 'to', str(network), 'table', str(table), 'protocol', protocol)
    allowed = {'dst', 'table', 'protocol', 'scope', 'dev', 'prefsrc', 'gateway', 'flags', 'type', 'metric', 'pref'}
    interface = row.get('dev', '')
    if set(row) - allowed or not re.fullmatch(r'[A-Za-z0-9_.][A-Za-z0-9_.:@-]{0,14}', interface) or row.get('type', 'unicast') != 'unicast' or row.get('flags'):
        raise ValueError('Complex legacy routes require manual migration.')
    result = ['route', action, 'table', str(table), str(network), 'dev', interface, 'proto', protocol]
    for key, argument in (('gateway', 'via'), ('prefsrc', 'src')):
        if row.get(key):
            address = ipaddress.ip_address(row[key])
            if address.version != family:
                raise ValueError('Invalid legacy address family.')
            result += [argument, str(address)]
    if 'metric' in row:
        if type(row['metric']) is not int or not 0 <= row['metric'] <= 4294967295:
            raise ValueError('Invalid legacy metric.')
        result += ['metric', str(row['metric'])]
    if row.get('scope') in ('link', 'host', 'global', 'universe'):
        result += ['scope', row['scope']]
    if row.get('pref') in ('low', 'medium', 'high'):
        result += ['pref', row['pref']]
    return tuple(result)
