import unittest
from types import SimpleNamespace

import dns.resolver

from site_routing.dns import DnsResolver
from site_routing.models import Provider, Target
from site_routing_fakes import PATH4


class DnsTests(unittest.TestCase):
    def test_resolves_both_families_and_uses_minimum_cname_and_answer_ttl(self):
        calls = []
        class Resolver:
            nameservers = []
            def resolve(self, name, family, **kwargs):
                calls.append((name, family, kwargs))
                text = '198.51.100.8' if family == 'A' else '2001:db8::8'
                return SimpleNamespace(__iter__=None, response=SimpleNamespace(answer=[SimpleNamespace(ttl=120), SimpleNamespace(ttl=20)]),
                                       rrset=SimpleNamespace(ttl=60), addresses=[text])
        class AnswerAdapter:
            def __init__(self, resolver): self.resolver = resolver
            @property
            def nameservers(self): return self.resolver.nameservers
            @nameservers.setter
            def nameservers(self, value): self.resolver.nameservers = value
            def resolve(self, *args, **kwargs):
                answer = self.resolver.resolve(*args, **kwargs)
                class Answer(list): pass
                result = Answer([SimpleNamespace(address=text) for text in answer.addresses])
                result.response, result.rrset = answer.response, answer.rrset
                return result
        resolver = Resolver()
        backend = DnsResolver(factory=lambda configure: AnswerAdapter(resolver))
        provider = Provider(Target('direct', 'direct'), 'Direct', {4: PATH4}, ('192.0.2.53',))
        addresses, ttl = backend.resolve('one.example', provider)
        self.assertEqual(addresses, ('198.51.100.8', '2001:db8::8'))
        self.assertEqual(ttl, 20)
        self.assertEqual(resolver.nameservers, ['192.0.2.53'])
        self.assertEqual([call[1] for call in calls], ['A', 'AAAA'])
        self.assertTrue(all(call[2]['search'] is False for call in calls))

    def test_target_dns_failure_never_silently_falls_back_to_system_dns(self):
        factories = []
        class Resolver:
            def resolve(self, *args, **kwargs): raise dns.resolver.NoNameservers
        def factory(configure):
            factories.append(configure)
            return Resolver()
        provider = Provider(Target('direct', 'direct'), 'Direct', {4: PATH4}, ('192.0.2.53',))
        with self.assertRaisesRegex(ValueError, 'DNS'):
            DnsResolver(factory=factory).resolve('one.example', provider)
        self.assertEqual(factories, [False])
