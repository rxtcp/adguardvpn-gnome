"""Exact NM host entries only; broader networks and unrelated fields are retained."""
import hashlib
import ipaddress
import json
import socket
import struct


def settings_hash(settings: dict) -> str:
    return hashlib.sha256(json.dumps(settings, sort_keys=True, separators=(',', ':'),
                                    default=lambda value: list(value)).encode()).hexdigest()


def entry_address(family: int, field: str, row) -> str | None:
    try:
        if field == 'route-data':
            address, prefix = row['dest'], row['prefix']
        elif field == 'routing-rules':
            network = ipaddress.ip_network(row.get('to', ''), strict=False)
            address, prefix = str(network.network_address), network.prefixlen
        elif family == 4:
            address, prefix = socket.inet_ntop(socket.AF_INET, struct.pack('=I', row[0])), row[1]
        else:
            address, prefix = str(ipaddress.IPv6Address(bytes(row[0]))), row[1]
        parsed = ipaddress.ip_address(address)
        return str(parsed) if parsed.version == family and prefix == parsed.max_prefixlen else None
    except (ValueError, TypeError, KeyError, IndexError, struct.error):
        return None


def settings_removals(settings: dict, addresses) -> list[dict]:
    addresses = set(addresses)
    patches = []
    for family in (4, 6):
        setting = f'ipv{family}'
        for field in ('route-data', 'routing-rules', 'routes'):
            rows = settings.get(setting, {}).get(field, [])
            indices = [index for index, row in enumerate(rows) if entry_address(family, field, row) in addresses]
            if indices:
                patches.append({'setting': setting, 'field': field, 'indices': indices,
                                'addresses': [entry_address(family, field, rows[index]) for index in indices]})
    return patches
