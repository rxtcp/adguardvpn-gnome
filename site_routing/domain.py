"""Canonical exact hostnames and bounded, unicast destination sets."""
import ipaddress
import re
from urllib.parse import urlsplit

import idna

MAX_RULES = 128
MAX_ADDRESSES = 256
MAX_REQUEST_BYTES = 16384


def normalize_domain(value: object) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= 8192:
        raise ValueError('Enter an exact domain or an HTTP(S) URL.')
    text = value.strip()
    if not text or re.search(r'[\s\\\x00-\x1f\x7f]', text):
        raise ValueError('Whitespace and control characters are not allowed in a host.')
    if '://' in text:
        try:
            url = urlsplit(text)
            if url.scheme.lower() not in ('http', 'https') or url.username is not None or url.password is not None:
                raise ValueError('Only HTTP(S) URLs without credentials are supported.')
            if url.port is not None and not 1 <= url.port <= 65535:
                raise ValueError('Invalid URL port.')
            host = url.hostname or ''
        except ValueError as error:
            raise ValueError('Invalid HTTP(S) URL.') from error
    else:
        host = text
    host = host.removesuffix('.')
    try:
        canonical = idna.encode(host, uts46=True, std3_rules=True).decode('ascii').lower()
    except (idna.IDNAError, UnicodeError) as error:
        raise ValueError('Invalid exact domain name.') from error
    labels = canonical.split('.')
    if len(canonical) > 253 or len(labels) < 2 or labels[-1].isdigit():
        raise ValueError('Use a fully qualified domain, not an IP address or wildcard.')
    return canonical


def normalize_addresses(values: object) -> tuple[str, ...]:
    if not isinstance(values, (list, tuple)) or len(values) > MAX_ADDRESSES * 2:
        raise ValueError('DNS returned too many addresses.')
    result = []
    for value in values:
        try:
            address = ipaddress.ip_address(value)
        except (ValueError, TypeError) as error:
            raise ValueError('DNS returned an invalid address.') from error
        if address.is_loopback or address.is_link_local or address.is_multicast or address.is_unspecified or str(address) == '255.255.255.255':
            raise ValueError('Only unicast, non-localhost destination addresses are supported.')
        canonical = str(address)
        if canonical not in result:
            result.append(canonical)
    if len(result) > MAX_ADDRESSES:
        raise ValueError('DNS returned too many addresses.')
    return tuple(result)
