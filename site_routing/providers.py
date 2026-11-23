"""Stable provider identities, verified kernel interfaces and explicit physical paths."""
import ipaddress

from .models import NetworkPath, Provider, Target

TUNNEL_KINDS = frozenset(('tun', 'wireguard', 'ppp', 'gre', 'ip6gre', 'ipip', 'vti', 'vti6', 'sit'))
PHYSICAL_TYPES = frozenset(('802-3-ethernet', '802-11-wireless'))


def paths_from_active(active: dict, links: list[dict], tunnel: bool = True) -> dict[int, NetworkPath]:
    if active.get('state') != 2:
        return {}
    result = {}
    for family in (4, 6):
        configuration = active.get(f'ip{family}', {})
        configured = {row['address'] for row in configuration.get('AddressData', []) if 'address' in row}
        candidates = []
        for link in links:
            kind = link.get('linkinfo', {}).get('info_kind', '')
            if 'UP' not in link.get('flags', []) or link.get('operstate') == 'DOWN':
                continue
            if tunnel and kind not in TUNNEL_KINDS and 'POINTOPOINT' not in link.get('flags', []):
                continue
            if not tunnel and (link['ifname'] not in active.get('interfaces', []) or kind in TUNNEL_KINDS):
                continue
            for address in link.get('addr_info', []):
                value = address.get('local', '')
                if value in configured and not address.get('tentative') and not address.get('dadfailed') and not {'tentative', 'dadfailed'} & set(address.get('flags', [])):
                    parsed = ipaddress.ip_address(value)
                    if parsed.version == family and not parsed.is_link_local and not parsed.is_loopback:
                        candidates.append((link, str(parsed)))
        interfaces = {link['ifindex'] for link, _source in candidates}
        if len(interfaces) != 1:
            continue
        link, source = candidates[0]
        gateway = configuration.get('Gateway', '')
        if not tunnel and not gateway:
            continue
        result[family] = NetworkPath(link['ifname'], link['ifindex'], source, gateway)
    return result


def nameservers(active: dict) -> tuple[str, ...]:
    addresses = []
    for family in (4, 6):
        for row in active.get(f'ip{family}', {}).get('NameserverData', []):
            value = row.get('address')
            if value:
                addresses.append(str(ipaddress.ip_address(value)))
    return tuple(dict.fromkeys(addresses))


class ProviderRegistry:
    def __init__(self, networkmanager, adguard):
        self.networkmanager, self.adguard = networkmanager, adguard

    def discover(self) -> dict[str, Provider]:
        snapshot = self.networkmanager.snapshot()
        links, active = snapshot['links'], snapshot['active']
        result = {}
        for profile in snapshot['profiles']:
            if profile['type'] not in ('vpn', 'wireguard'):
                continue
            target = Target.parse({'kind': 'networkmanager', 'id': profile['uuid']})
            current = next((row for row in active if row.get('uuid') == target.id), {})
            paths = paths_from_active(current, links)
            result[target.key] = Provider(target, profile['name'], paths, nameservers(current), tuple(profile.get('users', ())))
        physical = sorted((row for row in active if row.get('type') in PHYSICAL_TYPES),
                          key=lambda row: min((entry.get('metric', 600) for entry in row.get('ip4', {}).get('RouteData', []) if entry.get('prefix') == 0), default=600))
        direct = next(((row, paths_from_active(row, links, tunnel=False)) for row in physical if paths_from_active(row, links, tunnel=False)), ({}, {}))
        target = Target('direct', 'direct')
        result[target.key] = Provider(target, 'Direct physical connection', direct[1], nameservers(direct[0]), detail='' if direct[1] else 'No verified physical gateway.')
        adguard = self.adguard()
        if adguard.get('installed'):
            target = Target('adguard', 'adguardvpn-gnome')
            service_links = [link for link in links if link['ifname'] in adguard.get('interfaces', [])]
            current = {'state': 2 if adguard.get('connected') else 0,
                       **{f'ip{family}': {'AddressData': [{'address': entry['local']} for link in service_links for entry in link.get('addr_info', []) if entry.get('local') and ipaddress.ip_address(entry['local']).version == family]} for family in (4, 6)}}
            result[target.key] = Provider(target, 'AdGuard VPN (protected)', paths_from_active(current, service_links))
        return result
