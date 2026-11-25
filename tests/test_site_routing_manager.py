from concurrent.futures import ThreadPoolExecutor
from threading import Event
import unittest
from unittest.mock import Mock

from site_routing.manager import RoutingManager
from site_routing.models import NetworkPath, Provider, Target
from site_routing_fakes import Kernel, MemoryStore, Registry, Resolver, TARGET, PATH4, PATH6


class RoutingManagerTests(unittest.TestCase):
    def setUp(self):
        self.store, self.registry, self.resolver = MemoryStore(), Registry(), Resolver()
        self.kernel = Kernel(self.store)
        self.now = 1000
        self.manager = RoutingManager(self.store, self.registry, self.resolver, self.kernel, clock=lambda: self.now)

    def add(self, domain='one.example', target=TARGET, uid=1000):
        return self.manager.handle({'operation': 'add-rule', 'domain': domain, 'target': target}, uid, 'fixtureuser')['rule']

    def test_empty_configuration_never_changes_the_network(self):
        self.manager.refresh()
        self.assertEqual(self.kernel.calls, [])
        self.assertEqual(self.resolver.calls, [])

    def test_add_journals_intent_before_applying_and_tracks_both_address_families(self):
        rule = self.add()
        self.assertEqual(rule['domain'], 'one.example')
        self.assertEqual(rule['status'], 'active')
        self.assertEqual((rule['ipv4_count'], rule['ipv6_count']), (1, 1))
        self.assertEqual(self.kernel.calls[-1][1]['198.51.100.8'].path, PATH4)
        self.assertEqual(self.kernel.calls[-1][1]['2001:db8::8'].path, PATH6)
        self.assertEqual(self.store.state['rules'][0]['fallback'], 'block')

    def test_disconnect_missing_profile_and_reconnect_use_uuid_and_actual_new_interface(self):
        rule = self.add()
        self.registry.providers[0] = Provider(Target.parse(TARGET), 'Renamed VPN')
        self.manager.refresh()
        self.assertEqual(self.manager.rules(1000)[0]['status'], 'blocked-offline')
        self.assertIsNone(self.kernel.calls[-1][1]['198.51.100.8'].path)
        self.registry.providers = self.registry.providers[1:]
        self.manager.refresh()
        self.assertEqual(self.manager.rules(1000)[0]['status'], 'provider-missing')
        renamed = NetworkPath('fixturevpn2', 25, '192.0.2.4')
        self.registry.providers.append(Provider(Target.parse(TARGET), 'Renamed VPN', {4: renamed, 6: PATH6}))
        self.manager.refresh()
        self.assertEqual(self.manager.rules(1000)[0]['id'], rule['id'])
        self.assertEqual(self.kernel.calls[-1][1]['198.51.100.8'].path, renamed)

    def test_dns_ttl_changes_and_errors_retain_old_addresses_without_fallback(self):
        self.add()
        self.resolver.answers['one.example'] = (('198.51.100.9',), 60)
        self.now += 59
        self.manager.refresh()
        self.assertEqual(len(self.resolver.calls), 1)
        self.now += 1
        self.manager.refresh()
        self.assertEqual(set(self.store.state['rules'][0]['addresses']), {'198.51.100.8', '198.51.100.9', '2001:db8::8'})
        self.resolver.answers['one.example'] = ValueError('DNS lookup failed')
        self.now += 5
        self.manager.refresh(force_dns=True)
        self.assertEqual(self.manager.rules(1000)[0]['status'], 'dns-error')
        self.assertIn('198.51.100.8', self.kernel.calls[-1][1])

    def test_adding_a_rule_does_not_refresh_other_rules_with_valid_dns(self):
        for index in range(32):
            domain = f'cached-{index}.example'
            self.resolver.answers[domain] = (('198.51.100.9',), 60)
            self.add(domain)
        self.now += 5
        self.resolver.calls.clear()
        original = self.resolver.resolve

        def slow_lookup(domain, provider):
            self.now += 4
            return original(domain, provider)

        self.resolver.resolve = slow_lookup
        started = self.now
        self.add('two.example')
        self.assertEqual([domain for domain, _ in self.resolver.calls], ['two.example'])
        self.assertEqual(self.now - started, 4)

    def test_cached_reassignment_applies_while_background_dns_is_blocked(self):
        rule = self.add()
        self.now += 60
        started, finish = Event(), Event()

        def slow_lookup(_domain, _provider):
            started.set()
            finish.wait(5)
            return ('198.51.100.99',), 60

        self.resolver.resolve = slow_lookup
        with ThreadPoolExecutor(max_workers=2) as executor:
            background = executor.submit(self.manager.refresh)
            try:
                self.assertTrue(started.wait(2))
                edit = executor.submit(self.manager.handle, {'operation': 'update-rule', 'id': rule['id'],
                    'domain': rule['domain'], 'target': {'kind': 'direct', 'id': 'direct'}}, 1000, 'fixtureuser')
                self.assertEqual(edit.result(timeout=2)['rule']['target']['kind'], 'direct')
                self.assertIsNone(self.kernel.calls[-1][1]['198.51.100.8'].path)
                self.assertFalse(background.done())
            finally:
                finish.set()
            background.result(timeout=2)
        self.assertNotIn('198.51.100.99', self.store.state['rules'][0]['addresses'])

    def test_exceeding_total_address_capacity_only_reports_dns_error_for_that_rule(self):
        for index in range(16):
            domain = f'capacity-{index}.example'
            addresses = tuple(f'2001:db8::{value:x}' for value in range(256 * index + 1, 256 * (index + 1) + 1))
            self.resolver.answers[domain] = (addresses, 60)
            self.add(domain)
        self.resolver.answers['two.example'] = (('198.51.100.99',), 60)
        result = self.add('two.example')
        self.assertEqual(result['status'], 'dns-error')
        self.assertIn('total tracked-address limit', result['detail'])
        self.assertEqual(len(self.store.state['kernel']['known']), 4096)
        self.assertTrue(all(rule['status'] == 'active' for rule in self.manager.rules(1000) if rule['id'] != result['id']))
        self.assertTrue(all(call[0] != 'block' for call in self.kernel.calls))

        self.resolver.answers['two.example'] = (('198.51.100.99', '2001:db8::1'), 60)
        self.now += 30
        self.manager.refresh()
        checked = self.manager.diagnose(result['id'], 1000)
        self.assertEqual(checked['addresses'], ['2001:db8::1'])
        self.assertIn('total tracked-address limit', checked['rule']['detail'])

    def test_dns_failure_at_the_per_rule_limit_keeps_every_cached_address(self):
        addresses = tuple(f'2001:db8::{value:x}' for value in range(1, 257))
        self.resolver.answers['one.example'] = (addresses, 60)
        self.add()
        self.now += 60
        self.resolver.answers['one.example'] = (('198.51.100.99',), 60)
        self.manager.refresh()
        rule = self.manager.rules(1000)[0]
        self.assertEqual(rule['status'], 'dns-error')
        self.assertIn('too many addresses', rule['detail'])
        self.assertEqual(set(self.store.state['kernel']['known']), set(addresses))

    def test_shared_ip_with_different_target_blocks_all_affected_rules(self):
        first = self.add()
        second = self.add('two.example', {'kind': 'direct', 'id': 'direct'})
        self.assertTrue(all(rule['status'] == 'conflict' for rule in self.manager.rules(1000)))
        self.assertIsNone(self.kernel.calls[-1][1]['198.51.100.8'].path)
        self.manager.handle({'operation': 'remove-rule', 'id': second['id']}, 1000, 'fixtureuser')
        self.assertEqual(self.manager.rules(1000)[0]['id'], first['id'])
        self.assertIsNotNone(self.kernel.calls[-1][1]['198.51.100.8'].path)

    def test_no_ipv6_path_never_reports_active_or_leaves_ipv4_half_active(self):
        self.registry.providers[0] = Provider(Target.parse(TARGET), 'IPv4-only VPN', {4: PATH4})
        self.assertEqual(self.add()['status'], 'blocked-offline')
        self.assertTrue(all(item.path is None for item in self.kernel.calls[-1][1].values()))

    def test_another_hostname_cannot_report_active_for_an_ip_held_blocked_by_a_shared_rule(self):
        self.registry.providers[0] = Provider(Target.parse(TARGET), 'IPv4-only VPN', {4: PATH4})
        self.add()
        second = self.add('two.example')
        self.assertIsNone(self.kernel.calls[-1][1]['198.51.100.8'].path)
        self.assertEqual(second['status'], 'conflict')
        self.assertIn('shared IP', second['detail'])

    def test_provider_uuid_and_owner_are_validated_before_dns_or_kernel_mutation(self):
        for request in ({'operation': 'add-rule', 'domain': 'one.example', 'target': {'kind': 'networkmanager', 'id': '00000000-0000-4000-8000-000000000099'}},
                        {'operation': 'add-rule', 'domain': '*.example', 'target': TARGET}):
            with self.assertRaises(ValueError):
                self.manager.handle(request, 1000, 'fixtureuser')
        self.assertEqual(self.kernel.calls, [])
        self.assertEqual(self.resolver.calls, [])
        rule = self.add()
        self.assertEqual(self.manager.rules(2000), [])
        with self.assertRaises(PermissionError):
            self.manager.handle({'operation': 'remove-rule', 'id': rule['id']}, 2000, 'otheruser')

    def test_apply_failure_is_explicit_and_reasserts_guard_for_every_known_address(self):
        self.kernel.error = RuntimeError('cannot apply')
        self.assertEqual(self.add()['status'], 'apply-error')
        self.assertEqual(self.kernel.calls[-1], ('block', {'198.51.100.8', '2001:db8::8'}))

    def test_diagnosis_is_owned_and_deletion_explicitly_releases_last_known_addresses(self):
        rule = self.add()
        diagnosis = self.manager.handle({'operation': 'diagnose-rule', 'id': rule['id']}, 1000, 'fixtureuser')
        self.assertEqual(diagnosis['rule']['id'], rule['id'])
        self.assertEqual(len(diagnosis['addresses']), 2)
        self.manager.handle({'operation': 'remove-rule', 'id': rule['id']}, 1000, 'fixtureuser')
        self.assertEqual(self.manager.rules(1000), [])
        self.assertEqual(self.kernel.calls[-1], ('apply', {}))

    def test_emergency_guard_failure_is_not_reported_as_active(self):
        self.add()
        self.kernel.block = Mock(side_effect=RuntimeError('firewall rejected transaction'))
        with self.assertRaises(RuntimeError): self.manager.emergency_block()
        self.assertEqual(self.manager.rules(1000)[0]['status'], 'apply-error')
        self.assertIn('not confirmed', self.manager.rules(1000)[0]['detail'])

    def test_update_changes_target_only_and_rule_ownership_and_limits_are_enforced(self):
        rule = self.add()
        for request in ({'operation': 'add-rule', 'domain': 'one.example', 'target': TARGET},
                        {'operation': 'update-rule', 'id': rule['id'], 'domain': 'other.example', 'target': TARGET},
                        {'operation': 'remove-rule', 'id': '00000000-0000-4000-8000-000000000099'}):
            with self.assertRaises(ValueError): self.manager.handle(request, 1000, 'fixtureuser')
        result = self.manager.handle({'operation': 'update-rule', 'id': rule['id'], 'domain': rule['domain'],
            'target': {'kind': 'direct', 'id': 'direct'}}, 1000, 'fixtureuser')
        self.assertEqual(result['rule']['target']['kind'], 'direct')
        self.assertEqual(result['rule']['status'], 'blocked-offline')
        self.store.state['rules'] *= 128
        with self.assertRaises(ValueError): self.add('two.example')

    def test_provider_reads_filter_private_profiles_and_dns_refresh_is_rate_limited(self):
        self.registry.providers.append(Provider(Target('adguard', 'adguardvpn-gnome'), 'Private fixture', users=('anotheruser',)))
        self.assertEqual(len(self.manager.handle({'operation': 'list-providers'}, 1000, 'fixtureuser')['providers']), 2)
        self.add()
        self.manager.refresh(force_dns=True)
        self.assertEqual(len(self.resolver.calls), 1)
        self.now += 5
        self.resolver.answers['one.example'] = ((), 5)
        self.manager.refresh(force_dns=True)
        self.assertEqual(self.manager.rules(1000)[0]['status'], 'dns-error')
        self.assertEqual(self.store.state['rules'][0]['addresses'], ['198.51.100.8', '2001:db8::8'])
        self.assertEqual(self.manager.handle({'operation': 'list-rules'}, 1000, 'fixtureuser')['rules'], self.manager.rules(1000))

    def test_checkpoint_recovery_and_guard_failure_never_report_success(self):
        def apply(assignments, journal, installation, approved, checkpoint):
            checkpoint({**journal, 'pending_objects': [{'fixture': 'intent'}]})
            raise RuntimeError('interrupted after intent checkpoint')
        self.kernel.apply = apply
        self.kernel.block = Mock(side_effect=RuntimeError('fixture guard failure'))
        result = self.add()
        self.assertEqual(result['status'], 'apply-error')
        self.assertIn('not confirmed', result['detail'])
        self.assertTrue(self.store.state['kernel']['pending_objects'])

    def test_reconciliation_global_capacity_and_emergency_without_known_addresses(self):
        self.manager.emergency_block(); self.assertEqual(self.kernel.calls, [])
        self.add()
        self.manager.emergency_block()
        self.assertIn('have been blocked', self.manager.rules(1000)[0]['detail'])
        self.store.state['kernel']['known'] = [f'2001:db8::{index:x}' for index in range(1, 4098)]
        with self.assertRaisesRegex(ValueError, 'total tracked-address'): self.manager.refresh()

    def test_migration_adapters_are_separately_invoked_and_failures_remain_visible(self):
        rule = self.add()
        request = {'operation': 'update-rule', 'id': rule['id'], 'domain': rule['domain'], 'target': TARGET,
            'migration': {'id': '00000000-0000-4000-8000-000000000009', 'stage': 'protect'}}
        with self.assertRaisesRegex(ValueError, 'adapter is unavailable'): self.manager.handle(request, 1000, 'fixtureuser')
        migrations = Mock()
        migrations.approved.return_value = []
        migrations.preview.return_value = {'fixture': 'preview'}
        self.manager.migrations = migrations
        self.manager.handle(request, 1000, 'fixtureuser')
        migrations.apply.assert_called_once()
        self.assertEqual(self.manager.diagnose(rule['id'], 1000)['migration'], {'fixture': 'preview'})
        migrations.apply.side_effect = ValueError('stale migration plan')
        with self.assertRaisesRegex(ValueError, 'stale migration'): self.manager.handle(request, 1000, 'fixtureuser')
        self.assertEqual(self.manager.rules(1000)[0]['status'], 'apply-error')
