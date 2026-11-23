import unittest

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
