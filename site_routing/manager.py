"""Serialized root intent and reconciliation, independent of any GNOME window."""
import copy
import threading
import time

from .dns_refresh import refresh_answers
from .planning import plan_rules, public_rule, visible_providers
from .protocol import validate_request
from .rule_operations import change_rule, owned_rule, restore_failed_removal
from .models import Target
from .reconciliation_log import TransitionLog
from .reconciliation_status import apply_destination_failures, append_migration_details


class RoutingManager:
    def __init__(self, store, registry, resolver, kernel, clock=time.time, migrations=None):
        self.store, self.registry, self.resolver, self.kernel = store, registry, resolver, kernel
        self.clock, self.migrations = clock, migrations
        self._state = store.load()
        for rule in self._state['rules']:
            rule['status'], rule['detail'] = 'resolving', 'Restoring protection; provider and kernel routes have not yet been verified.'
        self._providers = {}
        self._transitions = TransitionLog()
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
            removed = copy.deepcopy(owned_rule(state, request['id'], uid)) if operation == 'remove-rule' else None
            providers = self.registry.discover()
            rule = change_rule(state, request, providers, uid, username, self.clock())
            if 'migration' in request:
                if self.migrations is None:
                    raise ValueError('Migration adapter is unavailable.')
                try:
                    self.migrations.apply(state, rule, request['migration'])
                except (OSError, RuntimeError, ValueError) as error:
                    rule['status'] = 'apply-error'
                    rule['detail'] = f'Migration {request["migration"]["stage"]} did not complete: {error}'[:4096]
                    self.store.save(state)
                    self._publish(state)
                    raise
            state['revision'] += 1
            self.store.save(state)
            self._state = copy.deepcopy(state)
            self.refresh(force_dns=True)
            if removed is not None:
                state = self.store.load()
                failure = restore_failed_removal(state, removed)
                if failure:
                    self.store.save(state)
                    self._publish(state)
                    raise ValueError(failure)
            return {'rules': self.rules(uid)} if rule is None or rule not in state['rules'] else {'rule': public_rule(owned_rule(self._state, rule['id'], uid))}

    def refresh(self, force_dns: bool = False, resolve_dns: bool = True) -> None:
        with self._mutex, self.store.lock():
            state = self.store.load()
            if not state['rules'] and not state['kernel']['known'] and not state['kernel']['objects']:
                self._publish(state)
                return
            providers = self.registry.discover()
            self._providers = providers
            if resolve_dns:
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
                apply_destination_failures(state)
            except (OSError, RuntimeError, ValueError) as error:
                detail = str(error)
                try:
                    self.kernel.block(known, state['installation_id'])
                except (OSError, RuntimeError, ValueError):
                    detail = 'Guard installation failed; protection is not confirmed.'
                for rule in state['rules']:
                    rule['status'] = 'conflict' if getattr(error, 'conflict', False) else 'apply-error'
                    rule['detail'] = detail
                state['kernel']['global_error'] = detail
            append_migration_details(state)
            self.store.save(state)
            self._publish(state)

    def _publish(self, state: dict) -> None:
        self._state = copy.deepcopy(state)
        self._transitions.publish(state)

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
            owned_rule(state, identity, uid)
            self.refresh(resolve_dns=False)
            state = self.store.load()
            rule = owned_rule(state, identity, uid)
            provider = visible_providers(self._providers, rule['owner_name']).get(Target.parse(rule['target']).key)
            public = public_rule(rule)
            try:
                migration = self.migrations.preview(state, rule) if self.migrations else None
            except (OSError, RuntimeError, ValueError) as error:
                migration = None
                public['detail'] = f'{public["detail"]} Migration preview unavailable: {error}'[:4096]
            self.store.save(state)
            return {'rule': public, 'addresses': list(rule['addresses']),
                    'checked_at': self.clock(), 'provider': provider.public() if provider else None,
                    'routes': self.kernel.diagnostics(rule['addresses']),
                    'protection': 'Known IP addresses only; unknown cached answers and application DoH/DoT are outside the guarantee. '
                                  'VPN server/control-plane routing is a separate prerequisite and is not managed by site rules.',
                    'migration': migration}
