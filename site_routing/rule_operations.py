"""Owned configuration changes; input never supplies kernel objects or owner IDs."""
import uuid

from .domain import MAX_RULES
from .models import Target
from .planning import visible_providers


def owned_rule(state: dict, identity: str, uid: int) -> dict:
    for rule in state['rules']:
        if rule['id'] == identity:
            if rule['owner_uid'] != uid:
                raise PermissionError('This rule belongs to a different user.')
            return rule
    raise ValueError('Rule not found.')


def change_rule(state: dict, request: dict, providers: dict, uid: int, username: str, now: float) -> dict | None:
    operation = request['operation']
    if operation == 'remove-rule':
        rule = owned_rule(state, request['id'], uid)
        state['rules'].remove(rule)
        return None
    target = Target.parse(request['target'])
    if target.key not in visible_providers(providers, username):
        raise ValueError('The selected provider is missing or not accessible.')
    if operation == 'add-rule':
        if len(state['rules']) >= MAX_RULES or any(rule['owner_uid'] == uid and rule['domain'] == request['domain'] for rule in state['rules']):
            raise ValueError('Rule already exists or the rule limit has been reached.')
        rule = {'id': str(uuid.uuid4()), 'owner_uid': uid, 'owner_name': username,
                'domain': request['domain'], 'target': target.public(), 'fallback': 'block',
                'enabled': True, 'addresses': [], 'dns_expires': 0, 'dns_error': '',
                'updated_at': now, 'status': 'resolving', 'detail': 'Resolving DNS.'}
        state['rules'].append(rule)
        return rule
    rule = owned_rule(state, request['id'], uid)
    if request['domain'] != rule['domain']:
        raise ValueError('Create a new rule to change the hostname, then explicitly remove the old rule.')
    rule['target'], rule['owner_name'] = target.public(), username
    rule['dns_expires'] = 0
    return rule
