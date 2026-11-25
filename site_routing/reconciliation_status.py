"""Destination outcomes and migration context without changing independent rules."""


def apply_destination_failures(state: dict) -> None:
    failures = state['kernel'].get('failures', {})
    for rule in state['rules']:
        affected = [failures[address] for address in rule['addresses'] if address in failures]
        if affected:
            rule['status'] = 'apply-error' if any(item['status'] == 'apply-error' for item in affected) else 'conflict'
            rule['detail'] = ' '.join(dict.fromkeys(item['detail'] for item in affected))[:4096]


def migration_context(state: dict, rule: dict) -> tuple[str, str]:
    plans = [plan for plan in state['migrations'].values() if plan['rule_id'] == rule['id']]
    if not plans:
        return 'none', ''
    plan = plans[-1]
    return plan['stage'], plan.get('last_error', '')


def append_migration_details(state: dict) -> None:
    for rule in state['rules']:
        stage, error = migration_context(state, rule)
        if stage != 'none':
            rule['detail'] = f'{rule["detail"]} Migration: {stage}. {error}'.strip()[:4096]
