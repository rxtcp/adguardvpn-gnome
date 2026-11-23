"""Serialized root intent and reconciliation, independent of any GNOME window."""
import copy
import threading
import time

from .dns_refresh import refresh_answers
from .planning import plan_rules, public_rule, visible_providers
from .protocol import validate_request
from .rule_operations import change_rule, owned_rule


class RoutingManager:
    def __init__(self, store, registry, resolver, kernel, clock=time.time, migrations=None):
        self.store, self.registry, self.resolver, self.kernel = store, registry, resolver, kernel
        self.clock, self.migrations = clock, migrations
        self._state = store.load()
        self._mutex = threading.RLock()

    def rules(self, uid: int) -> list[dict]:
        return [public_rule(rule) for rule in self._state['rules'] if rule['owner_uid'] == uid]

    def handle(self, value: object, uid: int, username: str) -> dict:
        request = validate_request(value)
        operation = request['operation']
        if operation == 'list-rules':
            return {'rules': self.rules(uid)}
        if operation == 'list-providers':
            return {'providers': [provider.public() for provider in visible_providers(self.registry.discover(), username).values()]}
        if operation == 'diagnose-rule':
            return self.diagnose(request['id'], uid)
        with self._mutex, self.store.lock():
            state = self.store.load()
            providers = self.registry.discover()
            rule = change_rule(state, request, providers, uid, username, self.clock())
            if 'migration' in request:
                if self.migrations is None:
                    raise ValueError('Migration adapter is unavailable.')
                try:
                    self.migrations.apply(state, rule, request['migration'])
                except (OSError, RuntimeError, ValueError):
                    for affected in state['rules']:
                        affected['status'], affected['detail'] = 'apply-error', 'Migration did not complete; review the retained backup and guards.'
                    self.store.save(state)
                    self._publish(state)
                    raise
            state['revision'] += 1
            self.store.save(state)
            self._state = copy.deepcopy(state)
            self.refresh(force_dns=True)
            return {'rules': self.rules(uid)} if rule is None or rule not in state['rules'] else {'rule': public_rule(owned_rule(self._state, rule['id'], uid))}

    def refresh(self, force_dns: bool = False) -> None:
        with self._mutex, self.store.lock():
            state = self.store.load()
            if not state['rules'] and not state['kernel']['known'] and not state['kernel']['objects']:
                self._state = state
                return
            providers = self.registry.discover()
            refresh_answers(state['rules'], providers, self.resolver, self.clock(), force_dns,
                            lambda: self._publish(state))
            assignments = plan_rules(state['rules'], providers)
            known = sorted(set(state['kernel']['known']) | set(assignments))
            if len(known) > 4096:
                raise ValueError('The total tracked-address limit has been reached.')
            state['kernel']['known'] = known
            self.store.save(state)  # Persist guard intent before the first network write.
            try:
                approved = self.migrations.approved(state) if self.migrations else ()
                state['kernel'] = self.kernel.apply(assignments, state['kernel'], state['installation_id'], approved,
                    checkpoint=lambda journal: self._checkpoint(state, journal))
            except (OSError, RuntimeError, ValueError) as error:
                detail = str(error)
                try:
                    self.kernel.block(known, state['installation_id'])
                except (OSError, RuntimeError, ValueError):
                    detail = 'Guard installation failed; protection is not confirmed.'
                for rule in state['rules']:
                    rule['status'] = 'conflict' if getattr(error, 'conflict', False) else 'apply-error'
                    rule['detail'] = detail
            self.store.save(state)
            self._publish(state)

    def _publish(self, state: dict) -> None:
        self._state = copy.deepcopy(state)

    def _checkpoint(self, state: dict, journal: dict) -> None:
        state['kernel'] = journal
        self.store.save(state)

    def emergency_block(self) -> None:
        with self._mutex, self.store.lock():
            state = self.store.load()
            known = sorted(set(state['kernel']['known']) | {address for rule in state['rules'] for address in rule['addresses']})
            confirmed = False
            try:
                if known:
                    self.kernel.block(known, state['installation_id'])
                confirmed = True
            finally:
                for rule in state['rules']:
                    rule['status'] = 'apply-error'
                    rule['detail'] = 'Reconciliation failed; known IPs have been blocked.' if confirmed else 'Guard installation failed; protection is not confirmed.'
                self._publish(state)
                self.store.save(state)

    def diagnose(self, identity: str, uid: int) -> dict:
        with self._mutex, self.store.lock():
            state = self.store.load()
            rule = owned_rule(state, identity, uid)
            migration = self.migrations.preview(state, rule) if self.migrations else None
            self.store.save(state)
            return {'rule': public_rule(rule), 'addresses': list(rule['addresses']),
                    'routes': self.kernel.diagnostics(rule['addresses']),
                    'protection': 'Known IP addresses only; unknown cached answers and application DoH/DoT are outside the guarantee.',
                    'migration': migration}
