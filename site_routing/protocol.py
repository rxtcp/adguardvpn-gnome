"""Strict, versioned operations. Clients cannot choose commands or kernel IDs."""
from .domain import normalize_domain
from .models import Target, canonical_uuid

READ_OPERATIONS = frozenset(('list-providers', 'list-rules', 'diagnose-rule'))
WRITE_OPERATIONS = frozenset(('add-rule', 'update-rule', 'remove-rule'))


def validate_request(value: object) -> dict:
    if not isinstance(value, dict) or not isinstance(value.get('operation'), str):
        raise ValueError('A structured operation is required.')
    request = dict(value)
    operation = request['operation']
    if operation in ('list-providers', 'list-rules'):
        allowed = {'operation'}
    elif operation in ('remove-rule', 'diagnose-rule'):
        allowed = {'operation', 'id'}
        request['id'] = canonical_uuid(request.get('id'))
    elif operation in ('add-rule', 'update-rule'):
        allowed = {'operation', 'domain', 'target'}
        request['domain'] = normalize_domain(request.get('domain'))
        request['target'] = Target.parse(request.get('target')).public()
        if operation == 'update-rule':
            allowed |= {'id', 'migration'}
            request['id'] = canonical_uuid(request.get('id'))
            if 'migration' in request:
                migration = request['migration']
                if not isinstance(migration, dict) or set(migration) != {'id', 'stage'} or migration['stage'] not in ('protect', 'retire', 'rollback'):
                    raise ValueError('Invalid migration operation.')
                request['migration'] = {'id': canonical_uuid(migration['id']), 'stage': migration['stage']}
    else:
        raise ValueError('Unsupported Site Routing operation.')
    if set(value) - allowed:
        raise ValueError('Unsupported request fields.')
    return request
