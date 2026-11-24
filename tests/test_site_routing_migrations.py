import copy
import json
import unittest
from unittest.mock import Mock, patch

from site_routing.migrations import MigrationManager, settings_removals
from site_routing_fakes import MemoryStore, NM_ID, RULE_ID, TARGET


class MigrationTests(unittest.TestCase):
    def setUp(self):
        self.store = MemoryStore()
        self.rule = {'id': RULE_ID, 'owner_uid': 1000, 'owner_name': 'fixtureuser', 'domain': 'one.example',
                     'target': TARGET, 'addresses': ['198.51.100.8'], 'status': 'active'}
        self.state = self.store.state
        self.state['rules'] = [self.rule]
        self.profile = {'uuid': NM_ID, 'name': 'Fixture VPN', 'path': '/fixture/profile', 'users': (), 'interfaces': ['fixturevpn'],
                        'settings': {'connection': {'id': 'Fixture VPN', 'uuid': NM_ID},
                                     'ipv4': {'route-data': [{'dest': '198.51.100.8', 'prefix': 32},
                                                             {'dest': '203.0.113.0', 'prefix': 24}],
                                              'routing-rules': [{'to': '198.51.100.8/32', 'table': 777, 'priority': 900}]}}}
        self.profile['serialized'] = json.dumps(self.profile['settings'])
        profile = self.profile
        class Reader:
            def profiles(self): return [profile]
            def migration_profiles(self): return [profile]
            def render_without(self, serialized, patches):
                settings = json.loads(serialized)
                for patch in patches:
                    values = settings[patch['setting']][patch['field']]
                    settings[patch['setting']][patch['field']] = [value for index, value in enumerate(values) if index not in patch['indices']]
                return json.dumps(settings), settings
            def update(self, current, serialized):
                current['serialized'], current['settings'] = serialized, json.loads(serialized)
        class Kernel:
            def __init__(self): self.events = []
            def overlaps(self, addresses, journal):
                return [{'kind': 'rule', 'family': 4, 'data': {
                    'priority': 900, 'dst': '198.51.100.8/32', 'table': 777, 'protocol': 'static'}},
                    {'kind': 'route', 'family': 4, 'data': {'dst': '198.51.100.8/32', 'dev': 'fixturevpn', 'protocol': 'static'}}]
            def block(self, addresses, installation): self.events.append('block')
            def protect_subset(self, addresses, journal, installation): self.events.append('block')
            def verify_replacement(self, addresses, journal, target_key): return True
            def change_legacy(self, entries, action): self.events.append(action)
        self.kernel, self.reader = Kernel(), Reader()
        self.manager = MigrationManager(self.store, self.reader, self.kernel)

    def test_preview_creates_verified_backup_and_exact_diff_without_network_changes(self):
        plan = self.manager.preview(self.state, self.rule)
        self.assertEqual(plan['stage'], 'preview')
        self.assertTrue(plan['changes'])
        self.assertEqual(self.kernel.events, [])
        backup = self.state['migrations'][plan['id']]['profiles'][0]
        self.assertEqual(json.loads(backup['before']), self.profile['settings'])
        self.assertNotIn('203.0.113.0/24', '\n'.join(plan['changes']))

    def test_migration_requires_distinct_protect_and_retire_confirmations_then_supports_rollback(self):
        original = copy.deepcopy(self.profile['settings'])
        plan = self.manager.preview(self.state, self.rule)
        with self.assertRaises(ValueError):
            self.manager.apply(self.state, self.rule, {'id': plan['id'], 'stage': 'retire'})
        self.manager.apply(self.state, self.rule, {'id': plan['id'], 'stage': 'protect'})
        self.assertEqual(self.profile['settings'], original)
        self.assertEqual(len(self.manager.approved(self.state)), 2)
        self.manager.apply(self.state, self.rule, {'id': plan['id'], 'stage': 'retire'})
        self.assertEqual(self.kernel.events, ['block', 'del'])
        self.assertEqual(self.profile['settings']['ipv4']['route-data'], [{'dest': '203.0.113.0', 'prefix': 24}])
        self.manager.apply(self.state, self.rule, {'id': plan['id'], 'stage': 'rollback'})
        self.assertEqual(self.profile['settings'], original)
        self.assertEqual(self.state['rules'], [])
        self.assertEqual(self.kernel.events[-2:], ['block', 'add'])

    def test_changed_nm_settings_are_not_overwritten_by_a_stale_plan(self):
        plan = self.manager.preview(self.state, self.rule)
        self.profile['settings']['connection']['id'] = 'User changed this'
        with self.assertRaises(ValueError):
            self.manager.apply(self.state, self.rule, {'id': plan['id'], 'stage': 'protect'})
        self.assertEqual(self.kernel.events, [])

    def test_retirement_rechecks_the_kernel_even_if_the_previous_public_status_was_active(self):
        plan = self.manager.preview(self.state, self.rule)
        self.manager.apply(self.state, self.rule, {'id': plan['id'], 'stage': 'protect'})
        original = copy.deepcopy(self.profile['settings'])
        self.kernel.verify_replacement = Mock(return_value=False)
        with self.assertRaisesRegex(ValueError, 'verified'):
            self.manager.apply(self.state, self.rule, {'id': plan['id'], 'stage': 'retire'})
        self.assertEqual(self.profile['settings'], original)
        self.assertEqual(self.manager.preview(self.state, self.rule)['stage'], 'protected')
        self.assertIn('verified', self.manager.preview(self.state, self.rule)['detail'])
        self.assertEqual(self.kernel.events, [])

    def test_tunnel_loss_during_retirement_records_failure_and_keeps_rollback_available(self):
        plan = self.manager.preview(self.state, self.rule)
        self.manager.apply(self.state, self.rule, {'id': plan['id'], 'stage': 'protect'})
        self.kernel.verify_replacement = Mock(side_effect=[True, False])
        with self.assertRaisesRegex(ValueError, 'disappeared during legacy removal'):
            self.manager.apply(self.state, self.rule, {'id': plan['id'], 'stage': 'retire'})
        self.assertEqual(self.manager.preview(self.state, self.rule)['stage'], 'failed')
        self.assertIn('disappeared', self.manager.preview(self.state, self.rule)['detail'])
        self.manager.apply(self.state, self.rule, {'id': plan['id'], 'stage': 'rollback'})
        self.assertEqual(self.state['rules'], [])

    def test_only_exact_host_entries_are_eligible(self):
        patches = settings_removals(self.profile['settings'], ['198.51.100.8'])
        self.assertEqual(len(patches), 2)
        self.assertEqual(patches[0]['indices'], [0])

    def test_preview_refuses_an_unmatched_saved_selector_even_with_a_live_match_for_the_same_ip(self):
        settings = self.profile['settings']
        settings['ipv4']['routing-rules'].append({
            'to': '198.51.100.8/32', 'from': '192.0.2.5', 'from-len': 32, 'table': 777, 'priority': 901})
        self.profile['serialized'] = json.dumps(settings)
        with self.assertRaisesRegex(ValueError, 'matched exactly'):
            self.manager.preview(self.state, self.rule)
        self.assertFalse(self.state['migrations'])
        self.assertFalse(self.kernel.events)

    def test_preview_refuses_ambiguous_profile_ownership_and_foreign_overlaps(self):
        other_profile = {**self.profile, 'uuid': '00000000-0000-4000-8000-000000000003'}
        with patch.object(self.reader, 'migration_profiles', return_value=[self.profile, other_profile]):
            with self.assertRaisesRegex(ValueError, 'matched exactly'):
                self.manager.preview(self.state, self.rule)
        extra = {'kind': 'rule', 'family': 4, 'data': {
            'priority': 901, 'dst': '198.51.100.8/32', 'table': 777, 'protocol': 'static'}}
        with patch.object(self.kernel, 'overlaps', return_value=[*self.kernel.overlaps([], {}), extra]):
            with self.assertRaisesRegex(ValueError, 'matched exactly'):
                self.manager.preview(self.state, self.rule)

    def test_preexisting_unverified_plan_cannot_authorize_or_retire_but_can_roll_back(self):
        plan = self.manager.preview(self.state, self.rule)
        saved = self.state['migrations'][plan['id']]
        del saved['exact_entries']
        saved['stage'] = 'protected'
        self.assertEqual(self.manager.approved(self.state), [])
        for stage in ('protect', 'retire'):
            with self.assertRaisesRegex(ValueError, 'predates'):
                self.manager.apply(self.state, self.rule, {'id': plan['id'], 'stage': stage})
        self.manager.apply(self.state, self.rule, {'id': plan['id'], 'stage': 'rollback'})
        self.assertEqual(saved['stage'], 'rolled-back')

    def test_modern_nm_rule_uses_separate_to_length_and_diff_contains_exact_fields(self):
        self.profile['settings']['ipv4']['routing-rules'] = [{'to': '198.51.100.8', 'to-len': 32, 'table': 777, 'priority': 900}]
        self.profile['serialized'] = json.dumps(self.profile['settings'])
        patches = settings_removals(self.profile['settings'], self.rule['addresses'])
        self.assertEqual(len(patches), 2)
        plan = self.manager.preview(self.state, self.rule)
        self.assertIn('"priority": 900', '\n'.join(plan['changes']))
        self.assertIn('"table": 777', '\n'.join(plan['changes']))

    def test_same_ip_but_different_saved_table_is_not_permission_to_delete_foreign_policy(self):
        self.profile['settings']['ipv4']['routing-rules'][0]['table'] = 778
        self.profile['serialized'] = json.dumps(self.profile['settings'])
        with self.assertRaisesRegex(ValueError, 'matched exactly'):
            self.manager.preview(self.state, self.rule)
        self.assertEqual(self.kernel.events, [])

    def test_existing_applied_plan_is_stable_and_unrelated_private_profiles_are_not_backed_up(self):
        with patch.object(self.reader, 'migration_profiles', return_value=[{**self.profile, 'users': ('anotheruser',)},
                {**self.profile, 'settings': {}}]):
            self.assertIsNone(self.manager.preview(self.state, self.rule))
        first = self.manager.preview(self.state, self.rule)
        other = {**self.rule, 'id': '00000000-0000-4000-8000-000000000003'}
        self.manager.preview(self.state, other)
        second = self.manager.preview(self.state, self.rule)
        self.assertNotIn(first['id'], self.state['migrations'])
        self.assertEqual(len(self.state['migrations']), 2)
        self.manager.apply(self.state, self.rule, {'id': second['id'], 'stage': 'protect'})
        self.assertEqual(self.manager.preview(self.state, self.rule)['id'], second['id'])

    def test_stale_rule_identity_removed_profile_and_unapplied_rollback_are_refused(self):
        plan = self.manager.preview(self.state, self.rule)
        with self.assertRaisesRegex(ValueError, 'stale'):
            self.manager.apply(self.state, self.rule, {'id': 'missing', 'stage': 'protect'})
        with patch.object(self.reader, 'profiles', return_value=[]):
            with self.assertRaisesRegex(ValueError, 'profile was removed'):
                self.manager.apply(self.state, self.rule, {'id': plan['id'], 'stage': 'protect'})
        with self.assertRaisesRegex(ValueError, 'no applied migration'):
            self.manager.apply(self.state, self.rule, {'id': plan['id'], 'stage': 'rollback'})

    def test_failed_retirement_retains_backup_and_guard_then_can_retry_or_rollback(self):
        from site_routing.planning import plan_rules
        from site_routing_fakes import Registry
        plan = self.manager.preview(self.state, self.rule)
        self.manager.apply(self.state, self.rule, {'id': plan['id'], 'stage': 'protect'})
        self.rule['status'] = 'blocked-offline'
        self.kernel.verify_replacement = Mock(return_value=False)
        with self.assertRaisesRegex(ValueError, 'not verified'):
            self.manager.apply(self.state, self.rule, {'id': plan['id'], 'stage': 'retire'})
        self.kernel.verify_replacement.return_value = True
        self.profile['settings']['connection']['id'] = 'User changed after protect'
        with self.assertRaisesRegex(ValueError, 'overwrite was refused'):
            self.manager.apply(self.state, self.rule, {'id': plan['id'], 'stage': 'retire'})
        self.assertEqual(self.state['migrations'][plan['id']]['stage'], 'failed')
        plan_rules([self.rule], Registry().discover())
        self.assertEqual(self.rule['status'], 'apply-error')
        self.assertEqual(self.kernel.events, ['block'])
        backup = self.state['migrations'][plan['id']]['profiles'][0]
        self.profile['settings'] = json.loads(backup['before'])
        self.manager.apply(self.state, self.rule, {'id': plan['id'], 'stage': 'retire'})
        self.manager.apply(self.state, self.rule, {'id': plan['id'], 'stage': 'retire'})
        self.assertNotIn('migration_error', self.rule)
        self.manager.apply(self.state, self.rule, {'id': plan['id'], 'stage': 'rollback'})
        self.assertEqual(self.state['migrations'][plan['id']]['stage'], 'rolled-back')

    def test_reassignment_cannot_reuse_an_old_protection_plan_but_can_restore_its_backup(self):
        plan = self.manager.preview(self.state, self.rule)
        self.manager.apply(self.state, self.rule, {'id': plan['id'], 'stage': 'protect'})
        self.rule['target'] = {'kind': 'direct', 'id': 'direct'}
        for stage in ('protect', 'retire'):
            with self.assertRaisesRegex(ValueError, 'stale'):
                self.manager.apply(self.state, self.rule, {'id': plan['id'], 'stage': stage})
        self.manager.apply(self.state, self.rule, {'id': plan['id'], 'stage': 'rollback'})
        self.assertEqual(self.state['rules'], [])
        self.assertEqual(self.state['migrations'][plan['id']]['stage'], 'rolled-back')

    def test_approval_ends_when_the_bound_assignment_changes_or_is_removed(self):
        plan = self.manager.preview(self.state, self.rule)
        self.manager.apply(self.state, self.rule, {'id': plan['id'], 'stage': 'protect'})
        self.assertTrue(self.manager.approved(self.state))
        self.rule['target'] = {'kind': 'direct', 'id': 'direct'}
        self.assertEqual(self.manager.approved(self.state), [])
        self.rule['target'] = TARGET
        self.state['rules'] = [{**self.rule, 'owner_uid': 1001}]
        self.assertEqual(self.manager.approved(self.state), [])
        self.state['rules'] = []
        self.assertEqual(self.manager.approved(self.state), [])
