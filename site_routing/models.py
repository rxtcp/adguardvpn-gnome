"""Typed identities and verified network paths; display names are never IDs."""
from dataclasses import asdict, dataclass, field
import ipaddress
import re
import uuid


def canonical_uuid(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError('A UUID is required.')
    try:
        return str(uuid.UUID(value))
    except ValueError as error:
        raise ValueError('Invalid UUID.') from error


@dataclass(frozen=True)
class Target:
    kind: str
    id: str

    @property
    def key(self) -> str:
        return f'{self.kind}:{self.id}'

    @classmethod
    def parse(cls, value: object) -> 'Target':
        if not isinstance(value, dict) or set(value) != {'kind', 'id'}:
            raise ValueError('A provider kind and stable ID are required.')
        kind, identity = value['kind'], value['id']
        if kind == 'networkmanager':
            return cls(kind, canonical_uuid(identity))
        if (kind, identity) not in (('direct', 'direct'), ('adguard', 'adguardvpn-gnome')):
            raise ValueError('Unsupported provider identity.')
        return cls(kind, identity)

    def public(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class NetworkPath:
    interface: str
    ifindex: int
    source: str
    gateway: str = ''

    def __post_init__(self):
        if not re.fullmatch(r'[A-Za-z0-9_.][A-Za-z0-9_.:@-]{0,14}', self.interface) or type(self.ifindex) is not int or self.ifindex < 1:
            raise ValueError('Unverified network interface.')
        address = ipaddress.ip_address(self.source)
        if self.gateway and ipaddress.ip_address(self.gateway).version != address.version:
            raise ValueError('Gateway and source families differ.')


@dataclass(frozen=True)
class Provider:
    target: Target
    name: str
    paths: dict[int, NetworkPath] = field(default_factory=dict)
    dns: tuple[str, ...] = ()
    users: tuple[str, ...] = ()
    detail: str = ''

    def public(self) -> dict:
        return {'target': self.target.public(), 'name': self.name, 'active': bool(self.paths),
                'detail': self.detail, 'ipv4': 4 in self.paths, 'ipv6': 6 in self.paths}


@dataclass(frozen=True)
class Assignment:
    target_key: str
    path: NetworkPath | None
