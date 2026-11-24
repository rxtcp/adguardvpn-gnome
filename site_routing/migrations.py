"""Reviewed diff, private backup, separate protect/retire confirmations and rollback."""
import uuid
import json

from .migration_fields import settings_hash, settings_removals
from .migration_matching import matches_entry
from .models import Target


def public_plan(plan: dict) -> dict:
    return {'id': plan['id'], 'stage': plan['stage'], 'changes': list(plan['changes']), 'detail': plan.get('last_error', '')}


def can_refresh_preview(plan: dict) -> bool:
    return plan['stage'] == 'preview' or (plan['stage'] == 'protected' and plan.get('exact_entries') is not True)


class MigrationManager:
    def __init__(self, store, reader, kernel):
        self.store, self.reader, self.kernel = store, reader, kernel

    def preview(self, state: dict, rule: dict) -> dict | None:
        existing = [plan for plan in state['migrations'].values() if plan['rule_id'] == rule['id']
                    and plan['stage'] != 'rolled-back' and not can_refresh_preview(plan)]
        if existing:
            return public_plan(existing[-1])
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
            after, after_settings = self.reader.render_without(profile['serialized'], patches)
            profiles.append({'uuid': profile['uuid'], 'before': profile['serialized'], 'after': after,
                             'addresses': sorted({address for patch in patches for address in patch['addresses']}),
                             'before_hash': settings_hash(profile['settings']), 'after_hash': settings_hash(after_settings)})
            changes += [f'{profile["name"]} ({profile["uuid"]}): remove {patch["setting"]}.{patch["field"]}[{index}] '
                        + json.dumps(profile['settings'][patch['setting']][patch['field']][index], sort_keys=True, default=list)
                        for patch in patches for index in patch['indices']]
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
        if stage == 'rollback' and plan['stage'] not in ('protected', 'retired', 'failed', 'retiring', 'rolling-back'):
            raise ValueError('There is no applied migration to roll back.')
        self.kernel.protect_subset(rule['addresses'], state['kernel'], state['installation_id'])
        plan['stage'] = 'retiring' if stage == 'retire' else 'rolling-back'
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
            self.kernel.change_legacy(plan['overlaps'], 'del' if stage == 'retire' else 'add')
            if stage == 'retire' and not self.kernel.verify_replacement(rule['addresses'], state['kernel'], target_key):
                raise ValueError('Replacement disappeared during legacy removal; guards and backup are retained. Retry or roll back.')
        except (OSError, RuntimeError, ValueError):
            plan['stage'] = 'failed'
            rule['migration_error'] = 'Migration failed; guards and the verified backup are retained. Retry or roll back.'
            self.store.save(state)
            raise
        rule.pop('migration_error', None)
        plan['stage'] = 'retired' if stage == 'retire' else 'rolled-back'
        if stage == 'rollback':
            state['rules'].remove(rule)
