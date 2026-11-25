import json
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

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

    def test_auth_result_account_lookup_and_caller_uid_are_verified(self):
        uid, authorized = 1000, True
        def call(*args, **kwargs): return (uid,) if args[3] == 'GetConnectionUnixUser' else ((authorized, False, {}),)
        bus = SimpleNamespace(call=call, glib=SimpleNamespace(Variant=lambda *args: args))
        authorizer = PolkitAuthorizer(bus, account=Mock(side_effect=KeyError('account deleted')))
        with self.assertRaisesRegex(PermissionError, 'no longer available'): authorizer.identity(':1.42', 'list-rules')
        for uid, authorized in [(1000, False), (1000, 1), (True, True), (-1, True), (4294967296, True)]:
            with self.subTest(uid=uid, authorized=authorized), self.assertRaisesRegex(PermissionError, 'not granted'):
                authorizer.identity(':1.42', 'list-rules')

    def test_expected_and_unexpected_service_errors_do_not_return_private_command_details(self):
        authorizer = SimpleNamespace(identity=lambda *args: (1000, 'fixtureuser'))
        manager = Mock()
        dispatcher = RequestDispatcher(manager, authorizer)
        for error, code in ((ValueError('invalid state'), 'invalid-operation'),
                            (OSError('private subprocess details'), 'apply-error'),
                            (RuntimeError('private subprocess details'), 'apply-error'),
                            (KeyError('private bug details'), 'internal-error')):
            manager.handle.side_effect = error
            response = json.loads(dispatcher.dispatch(':1.42', '{"operation":"list-rules"}'))
            self.assertEqual(response['error']['code'], code)
            self.assertNotIn('private', response['error']['message'])
        manager.emergency_block.assert_called_once()
