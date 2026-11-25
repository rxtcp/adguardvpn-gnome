"""Bounded TTL refresh. Old answers remain guarded until explicit rule removal."""
from .domain import MAX_TRACKED_ADDRESSES, normalize_addresses
from .models import Target
from .planning import visible_providers


def due_provider(rule: dict, providers: dict, now: float, force: bool):
    if (not force and rule['dns_expires'] > now) or now - rule.get('last_dns_attempt', -10) < 5:
        return None
    return visible_providers(providers, rule['owner_name']).get(Target.parse(rule['target']).key)


def resolve_answer(resolver, domain: str, provider) -> tuple[tuple[str, ...], int, str | None]:
    try:
        addresses, ttl = resolver.resolve(domain, provider)
        addresses = normalize_addresses(addresses)
        if not addresses:
            raise ValueError('DNS returned no A or AAAA records.')
        return addresses, max(5, min(3600, int(ttl))), None
    except (OSError, RuntimeError, ValueError) as error:
        return (), 30, str(error)


def retain_answer(rule: dict, answer: tuple[tuple[str, ...], int, str | None],
                  tracked: set[str], started: float, finished: float) -> None:
    addresses, ttl, error = answer
    if error is None:
        try:
            if len(tracked.union(addresses)) > MAX_TRACKED_ADDRESSES:
                # Still account for shared IPs so the planner can detect conflicts.
                addresses = tuple(address for address in addresses if address in tracked)
                error = 'The total tracked-address limit has been reached. New IPs are outside protection.'
                ttl = 30
            retained = normalize_addresses([*rule['addresses'], *addresses])
            rule['addresses'] = list(retained)
            tracked.update(retained)
            if error is None:
                rule['updated_at'] = finished
        except ValueError as limit:
            error, ttl = str(limit), 30
    rule['last_dns_attempt'] = started
    rule['dns_expires'] = finished + ttl
    rule['dns_error'] = error or ''
