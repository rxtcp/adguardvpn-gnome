"""Serialized root intent and reconciliation, independent of any GNOME window."""
import copy
import threading
import time

from .dns_refresh import DnsResponse, due_provider, resolve_answer, retain_answers
from .domain import MAX_TRACKED_ADDRESSES
from .planning import migration_blocks, plan_rules, public_rule, visible_providers
from .protocol import validate_request
from .rule_operations import change_rule, owned_rule, restore_failed_removal
from .models import Target
from .migrations import StaleMigrationConfirmation
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
        self._dns_pending: set[str] = set()

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
        jobs = []
        with self._mutex, self.store.lock():
            state = self.store.load()
            removed = copy.deepcopy(owned_rule(state, request['id'], uid)) if operation == 'remove-rule' else None
            if 'migration' in request:
                rule = owned_rule(state, request['id'], uid)
                if rule['target'] != request['target'] or rule['domain'] != request['domain']:
                    raise ValueError('A migration request must keep the saved hostname and target.')
                if self.migrations is None:
                    raise ValueError('Migration adapter is unavailable.')
                try:
                    self.migrations.apply(state, rule, request['migration'])
                except StaleMigrationConfirmation:
                    raise
                except (OSError, RuntimeError, ValueError) as error:
                    rule['status'] = 'apply-error'
                    rule['detail'] = f'Migration {request["migration"]["stage"]} did not complete: {error}'[:4096]
                    self.store.save(state)
                    self._publish(state)
                    raise
            else:
                providers = self.registry.discover()
                rule = change_rule(state, request, providers, uid, username, self.clock())
            state['revision'] += 1
            self.store.save(state)
            self._state = copy.deepcopy(state)
            if operation != 'add-rule':
                self.refresh(resolve_dns=False)
            if removed is not None:
                state = self.store.load()
                failure = restore_failed_removal(state, removed)
                if failure:
                    self.store.save(state)
                    self._publish(state)
                    raise ValueError(failure)
            if rule is not None and 'migration' not in request:
                jobs = self._dns_jobs([rule], providers, force=False)
        self._resolve_dns(jobs)
        identity = rule['id'] if rule is not None else None
        rules = self.rules(uid)
        return next(({'rule': current} for current in rules if current['id'] == identity), {'rules': rules})

    def refresh(self, force_dns: bool = False, resolve_dns: bool = True) -> None:
        with self._mutex, self.store.lock():
            state = self.store.load()
            if not state['rules'] and not state['kernel']['known'] and not state['kernel']['objects']:
                self._publish(state)
                return
            self._reconcile(state, self.registry.discover())
        if resolve_dns:
            self.refresh_dns(force_dns)

    def refresh_dns(self, force_dns: bool = False) -> None:
        with self._mutex, self.store.lock():
            jobs = self._dns_jobs(self.store.load()['rules'], self._providers, force_dns)
        self._resolve_dns(jobs)

    def _dns_jobs(self, rules: list[dict], providers: dict, force: bool) -> list:
        now = self.clock()
        jobs = []
        for rule in rules:
            identity = rule['id']
            provider = due_provider(rule, providers, now, force)
            if provider is not None and identity not in self._dns_pending:
                self._dns_pending.add(identity)
                jobs.append((identity, rule.get('dns_revision', 0), rule['domain'], provider))
        return jobs

    def _resolve_dns(self, jobs: list) -> None:
        if not jobs:
            return
        try:
            answers = {}
            for identity, revision, domain, provider in jobs:
                started = self.clock()
                answer = resolve_answer(self.resolver, domain, provider)
                answers[identity] = DnsResponse(revision, started, self.clock(), answer)
            with self._mutex, self.store.lock():
                state = self.store.load()
                if retain_answers(state['rules'], answers, set(state['kernel']['known'])):
                    self._reconcile(state, self.registry.discover())
        finally:
            with self._mutex:
                self._dns_pending.difference_update(identity for identity, *_ in jobs)

    def _reconcile(self, state: dict, providers: dict) -> None:
        self._providers = providers
        assignments = plan_rules(state['rules'], providers, migration_blocks(state))
        known = sorted(set(state['kernel']['known']) | set(assignments))
        if len(known) > MAX_TRACKED_ADDRESSES:
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
