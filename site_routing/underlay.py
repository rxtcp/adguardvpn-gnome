"""Opt-in policy for the marked transport sockets of an approved NM OpenVPN profile."""
from dataclasses import dataclass
from functools import partial
import ipaddress
import json
import os
from pathlib import Path
import sys

from .commands import CommandRunner
from .dbus_transport import NM, SystemBus, bindings
from .kernel_objects import OwnedObject, table_number
from .models import canonical_uuid
from .networkmanager import ROOT
from .providers import PHYSICAL_TYPES, paths_from_active
from .security import verified_open, verify_path

CONFIG = Path('/etc/adguardvpn-site-routing/openvpn-underlay.json')
MARK = 0x53495445
TABLE = 39990
LOOKUP = 10
DENY = 11
PROTOCOL = '197'
FAMILIES = (4, 6)


@dataclass(frozen=True)
class Configuration:
    vpn: str
    uplink: str


def read_config(path: Path = CONFIG) -> Configuration | None:
    try:
        verify_path(path, private=True)
        fd = verified_open(path, os.O_RDONLY)
    except FileNotFoundError:
        return None
    try:
        raw = os.read(fd, 4097)
    finally:
        os.close(fd)
    if len(raw) > 4096:
        raise ValueError('OpenVPN underlay configuration is too large.')
    data = json.loads(raw)
    if not isinstance(data, dict) or set(data) != {'vpn', 'uplink'}:
        raise ValueError('OpenVPN underlay requires a VPN UUID and an uplink UUID.')
    vpn, uplink = canonical_uuid(data['vpn']), canonical_uuid(data['uplink'])
    if vpn == uplink:
        raise ValueError('OpenVPN and its uplink must have different profile UUIDs.')
    return Configuration(vpn, uplink)


def matches_rule(row: dict, priority: int) -> bool:
    fields = {'priority', 'src', 'fwmark', 'fwmask', 'table', 'protocol', 'flags', 'action', 'type'}
    if (set(row) - fields or row.get('priority') != priority or row.get('src', 'all') != 'all'
            or row.get('flags') or str(row.get('protocol')) != PROTOCOL):
        return False
    if str(row.get('fwmark')) not in (hex(MARK), str(MARK)):
        return False
    if str(row.get('fwmask', '0xffffffff')) not in ('0xffffffff', '4294967295'):
        return False
    action = row.get('action', row.get('type', 'lookup'))
    if priority == LOOKUP:
        return action == 'lookup' and table_number(row.get('table')) == TABLE
    return action == 'unreachable' and row.get('table', 0) in (0, '0', 'unspec')


def _rule_rows(runner) -> dict:
    return {family: runner.read_ip(family, 'rule', 'show') for family in FAMILIES}


def _site_rule(row: dict) -> bool:
    destination = ipaddress.ip_network(row.get('dst', row.get('to', '')), strict=False)
    if destination.prefixlen != destination.max_prefixlen:
        return False
    action = row.get('action', row.get('type', 'lookup'))
    if action == 'unreachable':
        return OwnedObject('block', str(destination.network_address), row['priority']).matches(row)
    table = table_number(row.get('table'))
    return 40000 <= table <= 49999 and OwnedObject(
        'lookup', str(destination.network_address), row['priority'], table).matches(row)


def verify_policy(runner) -> None:
    for rows in _rule_rows(runner).values():
        for priority in (LOOKUP, DENY):
            slot = [row for row in rows if row.get('priority') == priority]
            if len(slot) != 1 or not matches_rule(slot[0], priority):
                raise RuntimeError('The marked OpenVPN lookup and terminal guard must be installed in both families.')
        for row in rows:
            priority = row.get('priority', 32766)
            if priority >= LOOKUP or (priority == 0 and row.get('table') == 255):
                continue
            if priority > 0 and str(row.get('protocol')) == '196' and _site_rule(row):
                continue
            raise RuntimeError('An earlier routing rule can take precedence over the marked OpenVPN policy.')


def change_policy(runner, *, remove: bool) -> None:
    snapshot = _rule_rows(runner)
    if not remove:
        for rows in snapshot.values():
            for priority in (LOOKUP, DENY):
                slot = [row for row in rows if row.get('priority') == priority]
                if len(slot) > 1 or (slot and not matches_rule(slot[0], priority)):
                    raise RuntimeError('An OpenVPN underlay rule priority is already occupied.')
    action = 'del' if remove else 'add'
    for priority in ((LOOKUP, DENY) if remove else (DENY, LOOKUP)):
        for family, rows in snapshot.items():
            present = any(matches_rule(row, priority) for row in rows)
            if present == remove:
                kind = ('unreachable',) if priority == DENY else ()
                table = ('table', str(TABLE)) if priority == LOOKUP else ()
                runner.write_ip(family, 'rule', action, *kind, 'priority', str(priority),
                                'fwmark', hex(MARK), *table, 'protocol', PROTOCOL)
    if not remove:
        verify_policy(runner)


def has_policy(runner) -> bool:
    return any(matches_rule(row, priority) for rows in _rule_rows(runner).values()
               for row in rows for priority in (LOOKUP, DENY))


def _approved_base(configuration: Configuration, bus) -> dict:
    properties = partial(bus.properties, NM)
    paths = properties(ROOT, NM)['ActiveConnections']
    if len(paths) > 1024:
        raise RuntimeError('NetworkManager activation limit exceeded.')
    active = {path: properties(path, NM + '.Connection.Active') for path in paths}
    vpn = [item for item in active.values()
           if item.get('Uuid') == configuration.vpn and item.get('Vpn') and item.get('State') == 1]
    if len(vpn) != 1:
        raise RuntimeError('A unique activating OpenVPN profile is required.')
    base = vpn[0].get('SpecificObject', '/')
    uplink = active.get(base, {})
    if uplink.get('Uuid') != configuration.uplink:
        raise RuntimeError('The selected base connection is not the approved OpenVPN uplink.')
    devices = uplink.get('Devices', [])
    if uplink.get('Type') not in PHYSICAL_TYPES or uplink.get('State') != 2 or len(devices) != 1:
        raise RuntimeError('An activated physical uplink with a single device is required.')
    device = properties(devices[0], NM + '.Device')
    interface = device.get('IpInterface') or device.get('Interface')
    if device.get('ActiveConnection') != base or not interface:
        raise RuntimeError('The approved uplink device is not bound to that activation.')
    result = {'state': uplink['State'], 'interfaces': [interface]}
    for family in FAMILIES:
        path = uplink.get(f'Ip{family}Config', '/')
        result[f'ip{family}'] = properties(path, NM + f'.IP{family}Config') if path != '/' else {}
    return result


def verify_activation(configuration: Configuration, bus, runner) -> str:
    uplink = _approved_base(configuration, bus)
    interface = uplink['interfaces'][0]
    paths = paths_from_active(uplink, runner.read_links(), tunnel=False)
    verified = False
    for family in FAMILIES:
        rows = [row for row in runner.read_ip(family, 'route', 'show', 'table', 'all') if row.get('table') == TABLE]
        if any(row.get('dev') != interface or row.get('type', 'unicast') != 'unicast'
               or 'nexthops' in row or 'nhid' in row for row in rows):
            raise RuntimeError('The dedicated OpenVPN table contains a route outside its approved uplink.')
        defaults = [row for row in rows if row.get('dst') == 'default']
        if not defaults:
            continue
        path = paths.get(family)
        if not path or len(defaults) != 1 or defaults[0].get('gateway') != path.gateway or 'linkdown' in defaults[0].get('flags', []):
            raise RuntimeError('The dedicated OpenVPN table has no unique usable default on its approved uplink.')
        verified = True
    if not verified:
        raise RuntimeError('The dedicated OpenVPN table has no verified default route.')
    verify_policy(runner)
    return interface


def launch_mark(identity: str) -> int:
    try:
        vpn = canonical_uuid(identity)
        config = read_config()
        if config and config.vpn == vpn:
            interface = verify_activation(config, SystemBus(*bindings()), CommandRunner())
            print(MARK, interface)
        return 0
    except RuntimeError as error:
        print(f'OpenVPN underlay refused: {error}', file=sys.stderr)
    except (OSError, ValueError, KeyError):
        print('OpenVPN underlay refused: invalid configuration or unavailable kernel or NetworkManager data.', file=sys.stderr)
    return 1
