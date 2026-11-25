"""Bounded TTL refresh. Old answers remain guarded until explicit rule removal."""
from typing import NamedTuple

from .domain import MAX_ADDRESSES, MAX_TRACKED_ADDRESSES, normalize_addresses
from .models import Target
from .planning import visible_providers


class DnsAnswer(NamedTuple):
    addresses: tuple[str, ...]
    ttl: int
    error: str | None


class DnsResponse(NamedTuple):
    revision: int
    started: float
    finished: float
    answer: DnsAnswer


def due_provider(rule: dict, providers: dict, now: float, force: bool):
    if (not force and rule['dns_expires'] > now) or now - rule.get('last_dns_attempt', -10) < 5:
        return None
    return visible_providers(providers, rule['owner_name']).get(Target.parse(rule['target']).key)


def resolve_answer(resolver, domain: str, provider) -> DnsAnswer:
    try:
        addresses, ttl = resolver.resolve(domain, provider)
        addresses = normalize_addresses(addresses)
        if not addresses:
            raise ValueError('DNS returned no A or AAAA records.')
        return DnsAnswer(addresses, max(5, min(3600, int(ttl))), None)
    except (OSError, RuntimeError, ValueError) as error:
        return DnsAnswer((), 30, str(error))


def retain_answers(rules: list[dict], responses: dict[str, DnsResponse], known: set[str]) -> bool:
    updates = []
    for rule in rules:
        known.update(rule['addresses'])
        response = responses.get(rule['id'])
        if response is not None and response.revision == rule.get('dns_revision', 0):
            updates.append((rule, response))

    tracked = known.copy()
    for rule, response in updates:
        candidates = set(response.answer.addresses)
        if len(candidates.union(rule['addresses'])) <= MAX_ADDRESSES and len(tracked | candidates) <= MAX_TRACKED_ADDRESSES:
            tracked.update(candidates)

    # A new address must fit every rule claiming it, even if admitted by a later answer.
    unretained = set()
    for rule, response in updates:
        claimed = tracked.intersection(response.answer.addresses)
        if len(claimed.union(rule['addresses'])) > MAX_ADDRESSES:
            unretained.update(claimed - known)
    tracked.difference_update(unretained)

    for rule, response in updates:
        _retain_answer(rule, response, tracked, unretained)
    return bool(updates)


def _retain_answer(rule: dict, response: DnsResponse, tracked: set[str], unretained: set[str]) -> None:
    addresses, ttl, error = response.answer
    if error is None:
        previous = rule['addresses']
        retained = list(dict.fromkeys([*previous, *(address for address in addresses if address in tracked)]))
        if len(retained) <= MAX_ADDRESSES:
            rule['addresses'] = retained
        missing = set(addresses) - tracked
        if len(set(previous).union(addresses)) > MAX_ADDRESSES:
            error = 'DNS returned too many addresses.'
        elif missing:
            if missing & unretained:
                error = 'New IPs could not be retained for every matching rule.'
            else:
                error = 'The total tracked-address limit has been reached. New IPs are outside protection.'
        else:
            rule['updated_at'] = response.finished
    rule['last_dns_attempt'] = response.started
    rule['dns_expires'] = response.finished + (ttl if error is None else 30)
    rule['dns_error'] = error or ''
