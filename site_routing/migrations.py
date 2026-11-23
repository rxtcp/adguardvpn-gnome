"""Reviewed diff, private backup, separate protect/retire confirmations and rollback."""
import uuid

from .migration_fields import settings_hash, settings_removals


def public_plan(plan: dict) -> dict:
    return {'id': plan['id'], 'stage': plan['stage'], 'changes': list(plan['changes'])}


class MigrationManager:
    def __init__(self, store, reader, kernel):
        self.store, self.reader, self.kernel = store, reader, kernel

    def preview(self, state: dict, rule: dict) -> dict | None:
        existing = [plan for plan in state['migrations'].values() if plan['rule_id'] == rule['id'] and plan['stage'] not in ('preview', 'rolled-back')]
        if existing:
            return public_plan(existing[-1])
        profiles, changes = [], []
        for profile in self.reader.profiles():
            if profile['users'] and rule['owner_name'] not in profile['users']:
                continue
            patches = settings_removals(profile['settings'], rule['addresses'])
            if not patches:
                continue
            after, after_settings = self.reader.render_without(profile['serialized'], patches)
            profiles.append({'uuid': profile['uuid'], 'before': profile['serialized'], 'after': after,
                             'addresses': sorted({address for patch in patches for address in patch['addresses']}),
                             'before_hash': settings_hash(profile['settings']), 'after_hash': settings_hash(after_settings)})
            changes += [f'{profile["name"]} ({profile["uuid"]}): remove {patch["setting"]}.{patch["field"]} host {address}'
                        for patch in patches for address in patch['addresses']]
        overlaps = self.kernel.overlaps(rule['addresses'], state['kernel'])
        if not profiles:
            return None
        represented = {address for backup in profiles for address in backup['addresses']}
        import ipaddress
        if any(str(ipaddress.ip_network(item['data'].get('dst', item['data'].get('to')), strict=False).network_address) not in represented for item in overlaps):
            raise ValueError('Some overlapping policies cannot be matched exactly to NM settings; no automatic deletion is allowed.')
        identity = str(uuid.uuid4())
        state['migrations'] = {key: plan for key, plan in state['migrations'].items() if plan['rule_id'] != rule['id'] or plan['stage'] != 'preview'}
        plan = {'id': identity, 'rule_id': rule['id'], 'owner_uid': rule['owner_uid'],
                'target': rule['target'], 'stage': 'preview', 'profiles': profiles,
                'overlaps': overlaps, 'changes': changes}
        state['migrations'][identity] = plan
        return public_plan(plan)

    def approved(self, state: dict) -> list[dict]:
        return [item for plan in state['migrations'].values() if plan['stage'] in ('protected', 'retiring', 'retired', 'failed') for item in plan['overlaps']]

    def _profiles(self, plan: dict) -> dict:
        profiles = {profile['uuid']: profile for profile in self.reader.profiles()}
        if any(backup['uuid'] not in profiles for backup in plan['profiles']):
            raise ValueError('A migration profile was removed; protections are retained.')
        return profiles

    def apply(self, state: dict, rule: dict, request: dict) -> None:
        plan = state['migrations'].get(request['id'])
        if not plan or plan['rule_id'] != rule['id'] or plan['owner_uid'] != rule['owner_uid'] or plan['target'] != rule['target']:
            raise ValueError('This migration plan is stale or belongs to another rule.')
        stage, profiles = request['stage'], self._profiles(plan)
        if stage == 'protect':
            if plan['stage'] not in ('preview', 'protected') or any(settings_hash(profiles[backup['uuid']]['settings']) != backup['before_hash'] for backup in plan['profiles']):
                raise ValueError('NM settings changed; review a new diff before proceeding.')
            plan['stage'] = 'protected'
            return
        if stage == 'retire' and (plan['stage'] not in ('protected', 'retiring', 'failed', 'retired') or
                (rule['status'] != 'active' and not self.kernel.verify_replacement(rule['addresses'], state['kernel']))):
            raise ValueError('Verify an active protected replacement before separately confirming legacy removal.')
        if stage == 'rollback' and plan['stage'] not in ('protected', 'retired', 'failed', 'retiring', 'rolling-back'):
            raise ValueError('There is no applied migration to roll back.')
        self.kernel.block(state['kernel']['known'], state['installation_id'])
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
        except (OSError, RuntimeError, ValueError):
            plan['stage'] = 'failed'
            rule['migration_error'] = 'Migration failed; guards and the verified backup are retained. Retry or roll back.'
            self.store.save(state)
            raise
        rule.pop('migration_error', None)
        plan['stage'] = 'retired' if stage == 'retire' else 'rolled-back'
        if stage == 'rollback':
            state['rules'].remove(rule)
