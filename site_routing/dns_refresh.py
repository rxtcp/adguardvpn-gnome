"""Bounded TTL refresh. Old answers remain guarded until explicit rule removal."""
from .domain import normalize_addresses
from .models import Target
from .planning import visible_providers


def refresh_answers(rules: list[dict], providers: dict, resolver, now: float, force: bool,
                    publish) -> None:
    for rule in rules:
        provider = visible_providers(providers, rule['owner_name']).get(Target.parse(rule['target']).key)
        if provider is None or (not force and rule['dns_expires'] > now) or now - rule.get('last_dns_attempt', -10) < 5:
            continue
        rule['last_dns_attempt'] = now
        rule['status'], rule['detail'] = 'resolving', 'Resolving A and AAAA records.'
        publish()
        try:
            addresses, ttl = resolver.resolve(rule['domain'], provider)
            current = normalize_addresses(addresses)
            if not current:
                raise ValueError('DNS returned no A or AAAA records.')
            rule['addresses'] = list(normalize_addresses([*rule['addresses'], *current]))
            rule['dns_expires'] = now + max(5, min(3600, int(ttl)))
            rule['dns_error'] = ''
            rule['updated_at'] = now
        except (OSError, RuntimeError, ValueError) as error:
            rule['dns_error'] = str(error)
            rule['dns_expires'] = now + 30
