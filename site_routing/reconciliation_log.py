"""Root-journal transitions: identities and bounded reasons, never settings/diffs."""
import logging

from .reconciliation_status import migration_context

LOGGER = logging.getLogger('site_routing.reconciliation')


class TransitionLog:
    def __init__(self):
        self.previous = {}

    def publish(self, state: dict) -> None:
        identities = {rule['id'] for rule in state['rules']}
        self.previous = {identity: value for identity, value in self.previous.items() if identity in identities}
        for rule in state['rules']:
            if rule['status'] == 'resolving' and rule['id'] in self.previous:
                continue
            stage, _error = migration_context(state, rule)
            target = rule['target']
            bindings = tuple(sorted((row['address'], row['path']['interface'], row['path']['ifindex'],
                row['path']['source'], row['path']['gateway'], row['table']) for row in state['kernel']['objects']
                if row['kind'] == 'route' and row['address'] in rule['addresses']))
            signature = (rule['status'], rule['detail'], target['kind'], target['id'], stage, bindings)
            previous = self.previous.get(rule['id'])
            if previous == signature:
                continue
            self.previous[rule['id']] = signature
            level = logging.WARNING if rule['status'] in ('conflict', 'apply-error', 'dns-error') else logging.INFO
            LOGGER.log(level, 'Site Routing domain=%s target=%s:%s state=%s migration=%s routes_changed=%s reason=%s',
                rule['domain'], target['kind'], target['id'], rule['status'], stage,
                previous is None or previous[-1] != bindings,
                rule['detail'].replace('\n', ' ')[:4096])
