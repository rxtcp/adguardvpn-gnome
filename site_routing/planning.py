"""Pure reconciliation plan: conflicting/offline destinations have no allow path."""
import ipaddress

from .models import Assignment, Target


def visible_providers(providers: dict, username: str) -> dict:
    return {key: provider for key, provider in providers.items() if not provider.users or username in provider.users}


def migration_blocks(state: dict) -> dict[str, str]:
    blocked = {rule['id']: rule['migration_error'] for rule in state['rules'] if rule.get('migration_error')}
    for plan in state['migrations'].values():
        if plan.get('pending_overlap') is not None:
            blocked.setdefault(plan['rule_id'], 'A legacy deletion is unresolved. Known IPs stay blocked until recovery.')
        elif plan['stage'] in ('retiring', 'rolling-back', 'failed'):
            blocked.setdefault(plan['rule_id'], 'Migration is incomplete. Known IPs stay blocked until recovery.')
    return blocked


def plan_rules(rules: list[dict], providers: dict, blocked_migrations: dict[str, str]) -> dict[str, Assignment]:
    targets = {}
    for rule in rules:
        for address in rule['addresses']:
            targets.setdefault(address, set()).add(Target.parse(rule['target']).key)
    conflicts = {address for address, choices in targets.items() if len(choices) > 1}
    assignments = {}
    for rule in rules:
        target = Target.parse(rule['target'])
        provider = visible_providers(providers, rule['owner_name']).get(target.key)
        migration_error = blocked_migrations.get(rule['id'])
        families = {ipaddress.ip_address(address).version for address in rule['addresses']}
        usable = provider is not None and bool(families) and families <= set(provider.paths)
        if usable and provider.allowed_networks is not None:
            usable = all(any(ipaddress.ip_address(address) in ipaddress.ip_network(network)
                for network in provider.allowed_networks) for address in rule['addresses'])
        if any(address in conflicts for address in rule['addresses']):
            rule['status'], rule['detail'] = 'conflict', 'An IP is assigned to different targets. Affected IPs are blocked.'
        elif provider is None:
            rule['status'], rule['detail'] = 'provider-missing', 'Provider is missing or no longer accessible; known IPs stay blocked.'
        elif migration_error:
            rule['status'], rule['detail'] = 'apply-error', migration_error
        elif rule.get('dns_error'):
            rule['status'], rule['detail'] = 'dns-error', rule['dns_error']
        elif not usable:
            reason = provider.detail if not provider.paths else 'No verified path for every required address family or WireGuard peer AllowedIPs.'
            rule['status'], rule['detail'] = 'blocked-offline', (reason or 'Target connection is unavailable.') + ' Known IPs stay blocked.'
        else:
            rule['status'], rule['detail'] = 'active', 'Verified route for every known address.'
        for address in rule['addresses']:
            path = provider.paths[ipaddress.ip_address(address).version] if usable and address not in conflicts else None
            previous = assignments.get(address)
            if previous is not None and previous.path is None:
                path = None
            blocked = bool(migration_error) or (previous is not None and previous.blocked)
            assignments[address] = Assignment(target.key, path, blocked)
    for rule in rules:
        if rule['status'] == 'active' and any(assignments[address].blocked or assignments[address].path is None
                                              for address in rule['addresses']):
            rule['status'] = 'conflict'
            rule['detail'] = 'A shared IP is blocked by another rule. Review its target access and required address families.'
    return assignments


def public_rule(rule: dict) -> dict:
    return {key: rule[key] for key in ('id', 'domain', 'target', 'status', 'detail', 'updated_at')} | {
        'ipv4_count': sum(ipaddress.ip_address(address).version == 4 for address in rule['addresses']),
        'ipv6_count': sum(ipaddress.ip_address(address).version == 6 for address in rule['addresses'])}
