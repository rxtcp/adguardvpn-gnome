"""Reviewed diff, private backup, separate protect/retire confirmations and rollback."""
import uuid
import json

from .migration_fields import settings_hash, settings_removals
from .migration_matching import matches_entry
from .models import Target
from .planning import migration_blocks
from .protocol import ROLLBACK_STAGES


class StaleMigrationConfirmation(ValueError):
    pass


def needs_new_review(plan: dict) -> bool:
    return (plan.get('exact_entries') is not True or bool(plan.get('route_bindings_stale')) or
            any(item['kind'] == 'route' and not item.get('route_binding') for item in plan['overlaps']))


def public_plan(plan: dict, *, detail: str | None = None) -> dict:
    return {'id': plan['id'], 'stage': plan['stage'], 'changes': list(plan['changes']),
            'detail': plan.get('last_error', '') if detail is None else detail[:2048],
            'rollback_only': needs_new_review(plan)}


def can_refresh_preview(plan: dict) -> bool:
    return plan['stage'] == 'preview' or (plan['stage'] == 'protected' and needs_new_review(plan))


class MigrationManager:
    def __init__(self, store, reader, kernel):
        self.store, self.reader, self.kernel = store, reader, kernel

    def preview(self, state: dict, rule: dict) -> dict | None:
        plans = [plan for plan in state['migrations'].values() if plan['rule_id'] == rule['id']]
        existing = [plan for plan in plans if plan['stage'] != 'rolled-back' and not can_refresh_preview(plan)]
        if existing:
            return public_plan(existing[-1])
        previous = next((plan for plan in reversed(plans) if plan['stage'] == 'protected'), None)
        try:
            preview = self._create_preview(state, rule)
        except (OSError, RuntimeError, ValueError) as error:
            if previous is None:
                raise
            return public_plan(previous, detail=f'Migration preview unavailable. {error}')
        if preview is None and previous is not None:
            return public_plan(previous, detail='No eligible legacy NetworkManager entries were found for a new preview.')
        return preview

    def _create_preview(self, state: dict, rule: dict) -> dict | None:
        profiles, changes, matched = [], [], {}
        overlaps = self.kernel.overlaps(rule['addresses'], state['kernel'])
        for profile in self.reader.migration_profiles():
            if profile['users'] and rule['owner_name'] not in profile['users']:
                continue
            patches = settings_removals(profile['settings'], rule['addresses'])
            if not patches:
                continue
            for patch in patches:
                setting, field = patch['setting'], patch['field']
                for index in patch['indices']:
                    row = profile['settings'][setting][field][index]
                    matches = [i for i, item in enumerate(overlaps) if setting == f'ipv{item["family"]}'
                               and matches_entry(item, profile, field, row)]
                    if len(matches) != 1 or matched.setdefault(matches[0], profile['uuid']) != profile['uuid']:
                        raise ValueError('A saved policy entry cannot be matched exactly to a live NM policy; no automatic deletion is allowed.')
                    item = overlaps[matches[0]]
                    binding_detail = ''
                    if item['kind'] == 'route':
                        if 'route_binding' not in item:
                            binding = self.kernel.legacy_route_binding(item)
                            if binding is None:
                                raise ValueError('The reviewed legacy route disappeared. Use Check to review a new diff.')
                            item['route_binding'] = binding
                        binding_detail = f' [interface {item["data"]["dev"]}, kernel index {item["route_binding"]["ifindex"]}]'
                    changes.append(f'{profile["name"]} ({profile["uuid"]}): remove {setting}.{field}[{index}] '
                                   + json.dumps(row, sort_keys=True, default=list) + binding_detail)
            after, after_settings = self.reader.render_without(profile['serialized'], patches)
            profiles.append({'uuid': profile['uuid'], 'before': profile['serialized'], 'after': after,
                             'addresses': sorted({address for patch in patches for address in patch['addresses']}),
                             'before_hash': settings_hash(profile['settings']), 'after_hash': settings_hash(after_settings)})
        if not profiles:
            return None
        if len(matched) != len(overlaps):
            raise ValueError('Some overlapping policies cannot be matched exactly to NM settings; no automatic deletion is allowed.')
        identity = str(uuid.uuid4())
        state['migrations'] = {key: plan for key, plan in state['migrations'].items()
                               if plan['rule_id'] != rule['id'] or not can_refresh_preview(plan)}
        plan = {'id': identity, 'rule_id': rule['id'], 'owner_uid': rule['owner_uid'],
                'target': rule['target'], 'stage': 'preview', 'profiles': profiles,
                'overlaps': overlaps, 'changes': changes, 'exact_entries': True}
        state['migrations'][identity] = plan
        return public_plan(plan)

    def approved(self, state: dict) -> list[dict]:
        rules = {rule['id']: rule for rule in state['rules']}
        return [item for plan in state['migrations'].values()
                if plan.get('exact_entries') is True and plan['stage'] in ('protected', 'retiring', 'retired', 'failed')
                and (rule := rules.get(plan['rule_id'])) is not None
                and rule['owner_uid'] == plan['owner_uid'] and rule['target'] == plan['target']
                for item in plan['overlaps']]

    def _profiles(self, plan: dict) -> dict:
        profiles = {profile['uuid']: profile for profile in self.reader.profiles()}
        if any(backup['uuid'] not in profiles for backup in plan['profiles']):
            raise ValueError('A migration profile was removed; protections are retained.')
        return profiles

    def apply(self, state: dict, rule: dict, request: dict) -> None:
        plan = state['migrations'].get(request['id'])
        if not plan or plan['rule_id'] != rule['id'] or plan['owner_uid'] != rule['owner_uid'] or (request['stage'] != 'rollback' and plan['target'] != rule['target']):
            raise ValueError('This migration plan is stale or belongs to another rule.')
        if request['stage'] == 'rollback' and request.get('expected_stage') != plan['stage']:
            raise StaleMigrationConfirmation('The migration stage changed. Use Check and confirm rollback again.')
        try:
            self._apply(state, rule, plan, request['stage'])
        except (OSError, RuntimeError, ValueError) as error:
            plan['last_error'] = str(error)[:2048]
            self.store.save(state)
            raise
        plan.pop('last_error', None)

    def _apply(self, state: dict, rule: dict, plan: dict, stage: str) -> None:
        if stage != 'rollback' and plan.get('exact_entries') is not True:
            raise ValueError('This plan predates exact saved-entry verification. Review a new diff or roll back the old plan.')
        if stage != 'rollback' and needs_new_review(plan):
            raise ValueError('This plan needs a verified route interface binding. Use Check to review a new diff or roll back.')
        if stage == 'rollback':
            if plan['stage'] not in ROLLBACK_STAGES:
                raise ValueError('There is no applied migration to roll back.')
            if plan['stage'] == 'protected':
                # Protect only recorded approval. No legacy settings or policies were changed.
                self._finish_rollback(state, rule, plan)
                return
        profiles = self._profiles(plan)
        target_key = Target.parse(rule['target']).key
        if stage == 'protect':
            if plan['stage'] not in ('preview', 'protected') or any(settings_hash(profiles[backup['uuid']]['settings']) != backup['before_hash'] for backup in plan['profiles']):
                raise ValueError('NM settings changed; review a new diff before proceeding.')
            plan['stage'] = 'protected'
            return
        if stage == 'retire' and (plan['stage'] not in ('protected', 'retiring', 'failed', 'retired') or
                not self.kernel.verify_replacement(rule['addresses'], state['kernel'], target_key)):
            raise ValueError('Replacement is not verified for every known IP. Restore the target tunnel and use Check before retrying legacy removal.')
        if stage == 'retire':
            self._verify_route_bindings(plan)
        blocked_migrations = migration_blocks(state)
        blocked = set(rule['addresses']) | {address for other in state['rules'] if other['id'] in blocked_migrations
                                            for address in other['addresses']}
        self.kernel.protect_subset(blocked, state['kernel'], state['installation_id'])
        if plan['stage'] == 'protected':
            plan['pending_overlap'] = None
        plan['stage'] = 'retiring' if stage == 'retire' else 'rolling-back'
        rule['migration_error'] = 'Migration is incomplete. Protection and the verified backup are retained. Use Check to review recovery.'
        self.store.save(state)  # Backups and transition intent survive a mid-update crash.
        try:
            for backup in plan['profiles']:
                profile = profiles[backup['uuid']]
                current = settings_hash(profile['settings'])
                if current not in (backup['before_hash'], backup['after_hash']):
                    raise ValueError('NM settings changed after preview; automatic overwrite was refused.')
                expected = backup['after_hash'] if stage == 'retire' else backup['before_hash']
                if current != expected:
                    self.reader.update(profile, backup['after'] if stage == 'retire' else backup['before'])
            self._apply_legacy_changes(state, plan, stage)
            if stage == 'retire' and not self.kernel.verify_replacement(rule['addresses'], state['kernel'], target_key):
                raise ValueError('Replacement disappeared during legacy removal; guards and backup are retained. Retry or roll back.')
        except (OSError, RuntimeError, ValueError):
            plan['stage'] = 'failed'
            rule['migration_error'] = 'Migration failed; guards and the verified backup are retained. Retry or roll back.'
            self.store.save(state)
            raise
        if stage == 'rollback':
            self._finish_rollback(state, rule, plan)
        else:
            rule.pop('migration_error', None)
            plan['stage'] = 'retired'

    @staticmethod
    def _finish_rollback(state: dict, rule: dict, plan: dict) -> None:
        rule.pop('migration_error', None)
        plan['stage'] = 'rolled-back'
        state['rules'].remove(rule)

    def _verify_route_bindings(self, plan: dict) -> None:
        plan['route_bindings_stale'] = True
        removed = plan.get('removed_overlaps', {})
        for index, item in enumerate(plan['overlaps']):
            if item['kind'] != 'route':
                continue
            expected = item['route_binding']
            current = self.kernel.legacy_route_binding(item)
            if current is None and removed.get(str(index)) == expected:
                continue
            if current != expected:
                raise ValueError('The reviewed legacy route interface binding changed or disappeared. Use Check to review a new diff.')
        plan.pop('route_bindings_stale')

    def _apply_legacy_changes(self, state: dict, plan: dict, stage: str) -> None:
        removed = plan.setdefault('removed_overlaps', {})
        overlaps = plan['overlaps']
        self._resolve_pending_overlap(state, plan)
        if stage == 'retire':
            def record_intent(binding):
                plan['pending_overlap'] = {'index': index, 'binding': binding}
                self.store.save(state)

            for index, item in enumerate(overlaps):
                binding = self.kernel.change_legacy(item, 'del', binding=item.get('route_binding'), before_delete=record_intent)
                if binding is not None:
                    removed[str(index)] = binding
                    plan['pending_overlap'] = None
                    self.store.save(state)
            return
        # Restore routes before the rules that can select them.
        for index in sorted(removed, key=lambda index: overlaps[int(index)]['kind']):
            self.kernel.change_legacy(overlaps[int(index)], 'add', binding=removed[index])
            del removed[index]
            self.store.save(state)

    def _resolve_pending_overlap(self, state: dict, plan: dict) -> None:
        if 'pending_overlap' not in plan:
            # Older journals lack an intent marker. An unrecorded, missing item is ambiguous.
            for index, item in enumerate(plan['overlaps']):
                if str(index) not in plan['removed_overlaps'] and not self.kernel.legacy_present(item):
                    raise RuntimeError('The old migration journal cannot verify an absent legacy policy. Restore it through NetworkManager and retry rollback. Protection is retained.')
        else:
            pending = plan['pending_overlap']
            if pending is None:
                return
            if not self.kernel.legacy_present(plan['overlaps'][pending['index']], binding=pending['binding']):
                raise RuntimeError('The outcome of an interrupted kernel deletion is unknown. Restore the reviewed NetworkManager policy and retry rollback. Protection is retained.')
        plan['pending_overlap'] = None
        self.store.save(state)
