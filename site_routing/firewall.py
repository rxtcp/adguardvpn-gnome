"""Atomic destination/interface-index guard; independent of dynamic VPN routes."""
import ipaddress

from .models import canonical_uuid

TABLE = 'adguardvpn_site_routing'


def guard_script(installation_id: str, addresses, allowed: dict[str, int], exists: bool) -> str:
    identity = canonical_uuid(installation_id)
    values = {4: [], 6: []}
    pairs = {4: [], 6: []}
    for address in sorted(set(addresses)):
        parsed = ipaddress.ip_address(address)
        values[parsed.version].append(str(parsed))
        if address in allowed:
            index = allowed[address]
            if type(index) is not int or index < 1:
                raise ValueError('Invalid verified interface index.')
            pairs[parsed.version].append(f'{parsed} . {index}')
    lines = [f'delete table inet {TABLE}'] if exists else []
    lines += [f'table inet {TABLE} {{', f'comment "adguardvpn-site-routing:{identity}";']
    for family in (4, 6):
        selector = 'ip' if family == 4 else 'ip6'
        address_type = 'ipv4_addr' if family == 4 else 'ipv6_addr'
        known_elements = f'elements = {{ {", ".join(values[family])} }};' if values[family] else ''
        allowed_elements = f'elements = {{ {", ".join(pairs[family])} }};' if pairs[family] else ''
        lines += [f'set known{family} {{ type {address_type}; {known_elements} }}',
                  f'set allowed{family} {{ typeof {selector} daddr . meta oif; {allowed_elements} }}']
    for hook in ('output', 'forward', 'postrouting'):
        lines += [f'chain {hook} {{ type filter hook {hook} priority 300; policy accept;']
        verdict = 'drop' if hook == 'postrouting' else 'reject with icmpx type admin-prohibited'
        for family, selector in ((4, 'ip'), (6, 'ip6')):
            lines.append(f'{selector} daddr @known{family} {selector} daddr . meta oif != @allowed{family} counter {verdict}')
        lines.append('}')
    return '\n'.join([*lines, '}'])


class Firewall:
    def __init__(self, runner):
        self.runner = runner
        self._fingerprint = None

    def exists(self, installation_id: str) -> bool:
        tables = self.runner.nft_json('list', 'tables')['nftables']
        present = any(item.get('table', {}).get('family') == 'inet' and item['table'].get('name') == TABLE for item in tables)
        if present:
            contents = self.runner.nft_json('list', 'table', 'inet', TABLE)['nftables']
            owned = any(item.get('table', {}).get('comment') == f'adguardvpn-site-routing:{installation_id}' for item in contents)
            if not owned:
                raise RuntimeError('A foreign firewall table uses the Site Routing name; it was not modified.')
        return present

    def apply(self, addresses, allowed: dict[str, int], installation_id: str) -> None:
        addresses = tuple(sorted(set(addresses)))
        present = self.exists(installation_id)
        fingerprint = (addresses, tuple(sorted(allowed.items())), installation_id)
        if not addresses:
            if present:
                self.runner.nft_apply(f'delete table inet {TABLE}')
            self._fingerprint = None
        elif fingerprint != self._fingerprint or not present:
            self.runner.nft_apply(guard_script(installation_id, addresses, allowed, present))
            self._fingerprint = fingerprint
