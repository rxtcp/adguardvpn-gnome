import json
from types import SimpleNamespace
import unittest

from site_routing.authorization import PolkitAuthorizer
from site_routing.rpc import RequestDispatcher


class RoutingRpcTests(unittest.TestCase):
    def test_polkit_uses_authenticated_unique_bus_sender_and_interaction_only_for_changes(self):
        class Bus:
            def __init__(self):
                self.calls = []
                self.glib = SimpleNamespace(Variant=lambda signature, value: (signature, value))
            def call(self, *args, **kwargs):
                self.calls.append((args, kwargs))
                return (1000,) if args[3] == 'GetConnectionUnixUser' else ((True, False, {}),)
        bus = Bus()
        authorizer = PolkitAuthorizer(bus, account=lambda uid: SimpleNamespace(pw_name='fixtureuser'))
        self.assertEqual(authorizer.identity(':1.42', 'list-rules'), (1000, 'fixtureuser'))
        first = bus.calls[1][0]
        self.assertEqual(first[5][0], ('system-bus-name', {'name': ('s', ':1.42')}))
        self.assertEqual(first[5][3], 0)
        authorizer.identity(':1.42', 'add-rule')
        self.assertEqual(bus.calls[3][0][5][3], 1)
        self.assertTrue(bus.calls[3][0][5][1].endswith('.modify'))
        with self.assertRaises(PermissionError):
            authorizer.identity('org.fake.client', 'add-rule')

    def test_invalid_input_never_reaches_authorization_or_manager(self):
        class Forbidden:
            def identity(self, *args): raise AssertionError('should validate first')
            def handle(self, *args): raise AssertionError('should validate first')
        dispatcher = RequestDispatcher(Forbidden(), Forbidden())
        for value in ('{bad', '[]', '{"operation":"list-rules","uid":0}', 'x' * 16385):
            response = json.loads(dispatcher.dispatch(':1.2', value))
            self.assertFalse(response['ok'])
            self.assertEqual(response['error']['code'], 'invalid-request')

    def test_caller_ownership_is_derived_from_bus_and_errors_are_bounded(self):
        class Authorizer:
            def identity(self, sender, operation): return 1000, 'fixtureuser'
        class Manager:
            def handle(self, request, uid, username):
                return {'uid': uid, 'username': username}
        response = json.loads(RequestDispatcher(Manager(), Authorizer()).dispatch(':1.2', '{"operation":"list-rules"}'))
        self.assertTrue(response['ok'])
        self.assertEqual(response['schema_version'], 1)
        self.assertEqual(response['data']['uid'], 1000)

    def test_denied_authorization_does_not_mutate_state(self):
        class Authorizer:
            def identity(self, *args): raise PermissionError('denied')
        class Manager:
            def handle(self, *args): raise AssertionError('must not mutate')
        response = json.loads(RequestDispatcher(Manager(), Authorizer()).dispatch(':1.2', '{"operation":"list-rules"}'))
        self.assertEqual(response['error']['code'], 'not-authorized')
