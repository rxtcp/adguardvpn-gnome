"""Replay independent destinations and a disappearing NM tunnel without host I/O."""
import unittest
import json
from unittest.mock import Mock

from site_routing.kernel import KernelBackend
from site_routing.manager import RoutingManager
from site_routing.models import NetworkPath, Provider, Target
from site_routing.migrations import MigrationManager
from site_routing_fakes import MemoryStore, Registry, Resolver, TARGET, PATH4
from test_site_routing_kernel import KernelFixture, INSTALLATION


class RecoveringKernel(KernelFixture):
    def __init__(self):
        super().__init__()
        self.path = PATH4
        self.failed_address = None

    def read_ip(self, family, *arguments):
        if arguments[:2] == ('address', 'show'):
            return [] if self.path is None else [{'ifindex': self.path.ifindex, 'flags': ['UP'],
                'addr_info': [{'local': self.path.source}]}]
        if arguments[:2] == ('route', 'get') and not any(row['dst'].split('/')[0] == arguments[2] for row in self.current[family]['route']):
            raise RuntimeError('IPv4 route lookup is unreachable.')
        return super().read_ip(family, *arguments)

    def write_ip(self, family, *arguments):
        if arguments[:2] == ('route', 'add') and self.failed_address and self.failed_address + '/32' in arguments:
            raise RuntimeError('kernel interface disappeared.')
        super().write_ip(family, *arguments)


class RoutingRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.store, self.registry, self.resolver = MemoryStore(), Registry(), Resolver()
        self.store.state['installation_id'] = INSTALLATION
        self.resolver.answers = {'one.example': (('198.51.100.8',), 60), 'two.example': (('198.51.100.9',), 60)}
        self.runner = RecoveringKernel()
        self.kernel = KernelBackend(self.runner)
        self.manager = RoutingManager(self.store, self.registry, self.resolver, self.kernel, clock=lambda: 1000)

    def add(self, domain):
        return self.manager.handle({'operation': 'add-rule', 'domain': domain, 'target': TARGET}, 1000, 'fixtureuser')['rule']

    def statuses(self):
        return {rule['domain']: rule['status'] for rule in self.manager.rules(1000)}

    def test_one_legacy_conflict_does_not_block_an_independent_destination(self):
        legacy = {'dst': '198.51.100.8/32', 'table': 777, 'priority': 900, 'protocol': 'static'}
        self.runner.current[4]['rule'].append(legacy)
        self.add('one.example'); self.add('two.example')
        self.assertEqual(self.statuses(), {'one.example': 'conflict', 'two.example': 'active'})
        self.assertIn(legacy, self.runner.current[4]['rule'])
        self.assertEqual([row['dst'] for row in self.runner.current[4]['route']], ['198.51.100.9/32'])
        self.assertEqual(self.store.state['kernel']['known'], ['198.51.100.8', '198.51.100.9'])

    def test_a_route_write_failure_is_isolated_and_retried_from_the_pending_journal(self):
        self.runner.failed_address = '198.51.100.8'
        self.add('one.example'); self.add('two.example')
        self.assertEqual(self.statuses(), {'one.example': 'apply-error', 'two.example': 'active'})
        self.assertIn('route add', self.manager.rules(1000)[0]['detail'])
        self.assertTrue(self.store.state['kernel']['pending_objects'])
        self.runner.failed_address = None
        self.manager.refresh()
        self.assertEqual(set(self.statuses().values()), {'active'})
        self.assertEqual(self.store.state['kernel']['pending_objects'], [])

    def test_recreated_tun_restores_routes_without_restarting_the_manager(self):
        self.add('one.example'); self.add('two.example')
        self.registry.providers[0] = Provider(Target.parse(TARGET), 'Fixture VPN', detail='NetworkManager activated, but no verified kernel tunnel.')
        self.runner.path = None
        self.runner.current[4]['route'] = []  # Kernel removes device routes with the interface.
        self.manager.refresh()
        self.assertEqual(set(self.statuses().values()), {'blocked-offline'})
        replacement = NetworkPath('fixturevpn2', 27, '192.0.2.4')
        self.runner.path = replacement
        self.registry.providers[0] = Provider(Target.parse(TARGET), 'Renamed fixture VPN', {4: replacement})
        self.manager.refresh()
        self.assertEqual(set(self.statuses().values()), {'active'})
        self.assertTrue(all(row['dev'] == 'fixturevpn2' and row['prefsrc'] == '192.0.2.4' for row in self.runner.current[4]['route']))

    def test_failed_migration_does_not_mark_other_rules_as_failed(self):
        rule = self.add('one.example'); self.add('two.example')
        migrations = Mock()
        migrations.approved.return_value = []
        migrations.apply.side_effect = ValueError('Replacement is not verified; migration remains protected.')
        self.manager.migrations = migrations
        with self.assertRaisesRegex(ValueError, 'not verified'):
            self.manager.handle({'operation': 'update-rule', 'id': rule['id'], 'domain': rule['domain'], 'target': TARGET,
                'migration': {'id': '00000000-0000-4000-8000-000000000009', 'stage': 'retire'}}, 1000, 'fixtureuser')
        self.assertEqual(self.statuses()['two.example'], 'active')
        self.assertIn('not verified', self.manager.rules(1000)[0]['detail'])

    def test_migration_guard_preserves_a_verified_independent_allow_path(self):
        self.add('one.example'); self.add('two.example')
        self.kernel.protect_subset(['198.51.100.8'], self.store.state['kernel'], self.store.state['installation_id'])
        allowed = [line for line in self.runner.events[-1][1].splitlines() if line.startswith('set allowed4')][0]
        self.assertIn('198.51.100.9 . 17', allowed)
        self.assertNotIn('198.51.100.8 .', allowed)

    def test_check_reconciles_live_state_and_restart_does_not_publish_a_stale_active_status(self):
        rule = self.add('one.example')
        restarted = RoutingManager(self.store, self.registry, self.resolver, self.kernel, clock=lambda: 1005)
        self.assertEqual(restarted.rules(1000)[0]['status'], 'resolving')
        self.registry.providers[0] = Provider(Target.parse(TARGET), 'Fixture VPN', detail='NetworkManager activated, but no verified kernel tunnel.')
        self.runner.path = None; self.runner.current[4]['route'] = []
        diagnosis = self.manager.diagnose(rule['id'], 1000)
        self.assertEqual(diagnosis['rule']['status'], 'blocked-offline')
        self.assertEqual(diagnosis['checked_at'], 1000)
        self.assertIn('no verified kernel tunnel', diagnosis['provider']['detail'])

    def test_protected_migration_and_independent_rule_recover_then_retire_only_after_fresh_verification(self):
        legacy = {'dst': '198.51.100.8/32', 'table': 777, 'priority': 900, 'protocol': 'static'}
        self.runner.current[4]['rule'].append(legacy)
        profile = {'uuid': TARGET['id'], 'name': 'Fixture VPN', 'users': (), 'settings': {
            'ipv4': {'routing-rules': [{'to': '198.51.100.8', 'to-len': 32, 'table': 777, 'priority': 900}]}}}
        profile['serialized'] = json.dumps(profile['settings'])
        class Reader:
            def profiles(self): return [profile]
            def migration_profiles(self): return [profile]
            def render_without(self, serialized, patches):
                settings = json.loads(serialized)
                for patch in patches:
                    setting, field = patch['setting'], patch['field']
                    settings[setting][field] = [row for index, row in enumerate(settings[setting][field]) if index not in patch['indices']]
                return json.dumps(settings), settings
            def update(self, current, serialized):
                current['serialized'], current['settings'] = serialized, json.loads(serialized)
        self.manager.migrations = MigrationManager(self.store, Reader(), self.kernel)
        first = self.add('one.example'); self.add('two.example')
        plan = self.manager.diagnose(first['id'], 1000)['migration']
        request = {'operation': 'update-rule', 'id': first['id'], 'domain': first['domain'], 'target': TARGET,
                   'migration': {'id': plan['id'], 'stage': 'protect'}}
        self.manager.handle(request, 1000, 'fixtureuser')
        self.assertEqual(set(self.statuses().values()), {'active'})
        self.assertEqual(self.store.state['migrations'][plan['id']]['stage'], 'protected')
        self.runner.path = None; self.runner.current[4]['route'] = []
        request['migration']['stage'] = 'retire'
        with self.assertRaisesRegex(ValueError, 'not verified'): self.manager.handle(request, 1000, 'fixtureuser')
        self.assertIn(legacy, self.runner.current[4]['rule'])
        replacement = NetworkPath('fixturevpn2', 27, '192.0.2.4')
        self.runner.path = replacement
        self.registry.providers[0] = Provider(Target.parse(TARGET), 'Fixture VPN', {4: replacement})
        self.manager.refresh()
        self.assertEqual(set(self.statuses().values()), {'active'})
        diagnosis = self.manager.diagnose(first['id'], 1000)
        self.assertIn('not verified', diagnosis['migration']['detail'])
        self.assertIn('Migration: protected', diagnosis['rule']['detail'])
        self.manager.handle(request, 1000, 'fixtureuser')
        self.assertEqual(self.store.state['migrations'][plan['id']]['stage'], 'retired')
        self.assertEqual(profile['settings']['ipv4']['routing-rules'], [])
        self.assertNotIn(legacy, self.runner.current[4]['rule'])
        self.assertEqual(set(self.statuses().values()), {'active'})

    def test_transitions_include_domain_target_and_stage_without_logging_each_unchanged_poll(self):
        self.add('one.example')
        self.registry.providers[0] = Provider(Target.parse(TARGET), 'Fixture VPN', detail='NetworkManager activated, but no verified kernel tunnel.')
        with self.assertLogs('site_routing.reconciliation', level='INFO') as captured:
            self.manager.refresh()
        message = ' '.join(captured.output)
        self.assertIn('domain=one.example', message)
        self.assertIn('target=networkmanager:' + TARGET['id'], message)
        self.assertIn('state=blocked-offline', message)
        self.assertIn('migration=none', message)
        with self.assertNoLogs('site_routing.reconciliation', level='INFO'):
            self.manager.refresh()

    def test_policy_priority_change_keeps_an_independent_verified_lookup_installed(self):
        self.add('one.example'); self.add('two.example')
        self.runner.current[4]['rule'].append({'priority': 900, 'dst': '203.0.113.20/32', 'table': 777, 'protocol': 'static'})
        table = self.store.state['kernel']['tables']['networkmanager:' + TARGET['id']]
        original = self.runner.write_ip
        def write(family, *arguments):
            original(family, *arguments)
            self.assertTrue(any(row.get('dst') == '198.51.100.9/32' and row.get('table') == table
                                for row in self.runner.current[4]['rule']), 'independent lookup disappeared during priority change')
        self.runner.write_ip = write
        self.manager.refresh()
        self.assertEqual(self.statuses()['two.example'], 'active')

    def test_failed_rule_cleanup_keeps_the_rule_visible_and_the_independent_rule_active(self):
        rule = self.add('one.example'); self.add('two.example')
        original = self.runner.write_ip
        def write(family, *arguments):
            if arguments[:2] == ('route', 'del') and '198.51.100.8/32' in arguments:
                raise RuntimeError('kernel refused route cleanup')
            original(family, *arguments)
        self.runner.write_ip = write
        with self.assertRaisesRegex(ValueError, 'removal did not complete'):
            self.manager.handle({'operation': 'remove-rule', 'id': rule['id']}, 1000, 'fixtureuser')
        self.assertEqual(self.statuses(), {'one.example': 'apply-error', 'two.example': 'active'})
        self.assertIn('198.51.100.8', self.store.state['kernel']['known'])

    def test_unavailable_migration_preview_does_not_hide_current_route_diagnostics(self):
        rule = self.add('one.example')
        self.manager.migrations = Mock()
        self.manager.migrations.approved.return_value = []
        self.manager.migrations.preview.side_effect = ValueError('A legacy selector cannot be matched safely.')
        diagnosis = self.manager.diagnose(rule['id'], 1000)
        self.assertEqual(diagnosis['rule']['status'], 'active')
        self.assertIn('cannot be matched safely', diagnosis['rule']['detail'])
        self.assertIsNone(diagnosis['migration'])
        self.assertEqual(diagnosis['checked_at'], 1000)
        self.assertTrue(diagnosis['routes'])

    def test_tun_binding_change_is_logged_even_when_both_samples_are_active(self):
        self.add('one.example')
        replacement = NetworkPath('fixturevpn2', 27, '192.0.2.4')
        self.runner.path = replacement; self.runner.current[4]['route'] = []
        self.registry.providers[0] = Provider(Target.parse(TARGET), 'Fixture VPN', {4: replacement})
        with self.assertLogs('site_routing.reconciliation', level='INFO') as captured: self.manager.refresh()
        message = ' '.join(captured.output)
        self.assertIn('state=active', message)
        self.assertIn('routes_changed=True', message)
        self.assertNotIn('192.0.2.4', message)

