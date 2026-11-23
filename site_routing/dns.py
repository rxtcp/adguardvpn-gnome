"""A/AAAA and CNAME TTL tracking; configured target DNS never silently falls back."""
import dns.exception
import dns.resolver

from .domain import normalize_addresses


class DnsResolver:
    def __init__(self, factory=dns.resolver.Resolver):
        self.factory = factory

    def resolve(self, domain: str, provider) -> tuple[tuple[str, ...], int]:
        selected_dns = provider.dns if provider and provider.paths else ()
        resolver = self.factory(configure=not bool(selected_dns))
        if selected_dns:
            resolver.nameservers = list(selected_dns)
        addresses, ttls = [], []
        try:
            for family in ('A', 'AAAA'):
                try:
                    answer = resolver.resolve(domain, family, lifetime=4, search=False)
                except dns.resolver.NoAnswer:
                    continue
                addresses.extend(str(record.address) for record in answer)
                ttls.extend(int(rrset.ttl) for rrset in answer.response.answer)
        except dns.exception.DNSException as error:
            raise ValueError('DNS resolution failed; last known addresses remain tracked.') from error
        return normalize_addresses(addresses), min(ttls, default=30)
