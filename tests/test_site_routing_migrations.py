import copy
import json
import unittest

from site_routing.migrations import MigrationManager, settings_removals
from site_routing_fakes import MemoryStore, NM_ID, RULE_ID, TARGET


class MigrationTests(unittest.TestCase):
    def setUp(self):
        self.store = MemoryStore()
        self.rule = {'id': RULE_ID, 'owner_uid': 1000, 'owner_name': 'fixtureuser', 'domain': 'one.example',
                     'target': TARGET, 'addresses': ['198.51.100.8'], 'status': 'active'}
        self.state = self.store.state
        self.state['rules'] = [self.rule]
        self.profile = {'uuid': NM_ID, 'name': 'Fixture VPN', 'path': '/fixture/profile', 'users': (),
                        'settings': {'connection': {'id': 'Fixture VPN', 'uuid': NM_ID},
                                     'ipv4': {'route-data': [{'dest': '198.51.100.8', 'prefix': 32},
                                                             {'dest': '203.0.113.0', 'prefix': 24}],
                                              'routing-rules': [{'to': '198.51.100.8/32', 'table': 777, 'priority': 900}]}}}
        self.profile['serialized'] = json.dumps(self.profile['settings'])
        profile = self.profile
        class Reader:
            def profiles(self): return [profile]
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
            def overlaps(self, addresses, journal): return [{'kind': 'rule', 'family': 4,
                'data': {'priority': 900, 'dst': '198.51.100.8/32', 'table': 777, 'protocol': 'static'}}]
            def block(self, addresses, installation): self.events.append('block')
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
        self.assertEqual(len(self.manager.approved(self.state)), 1)
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

    def test_only_exact_host_entries_are_eligible(self):
        patches = settings_removals(self.profile['settings'], ['198.51.100.8'])
        self.assertEqual(len(patches), 2)
        self.assertEqual(patches[0]['indices'], [0])
