"""Public input contracts; synthetic names and documentation-only IP addresses."""
import unittest

from site_routing.domain import normalize_domain, normalize_addresses
from site_routing.models import Target
from site_routing.protocol import validate_request


class SiteRoutingModelTests(unittest.TestCase):
    def test_exact_host_normalization_discards_only_url_components(self):
        for text, expected in (
            (' HTTPS://Packages.Corp.Example:8443/repository?q=x#part ', 'packages.corp.example'),
            ('Packages.Corp.Example.', 'packages.corp.example'),
            ('https://ПРИМЕР.рф/path', 'xn--e1afmkfd.xn--p1ai'),
            ('faß.example', 'xn--fa-hia.example'),
        ):
            with self.subTest(text=text):
                self.assertEqual(normalize_domain(text), expected)

    def test_rejects_wildcards_addresses_credentials_shell_input_and_bad_labels(self):
        for text in ('', None, 4, '*.example.com', '.example.com', 'localhost',
                     'https://user:password@example.com', 'ftp://example.com',
                     'example.com;id', 'example.com\n--help', 'a..example',
                     '-a.example', 'a-.example', '198.51.100.1', '2001:db8::1',
                     '198.51.100.0/24', 'example.com/path', 'https://example.com:99999',
                     'https://example.com\\evil', 'a' * 64 + '.example', 'a.' * 130 + 'example'):
            with self.subTest(text=text), self.assertRaises(ValueError):
                normalize_domain(text)

    def test_targets_are_fixed_kinds_and_uuid_identity_not_interface_names(self):
        self.assertEqual(Target.parse({'kind': 'direct', 'id': 'direct'}).key, 'direct:direct')
        target = Target.parse({'kind': 'networkmanager', 'id': '00000000-0000-4000-8000-000000000001'})
        self.assertEqual(target.id, '00000000-0000-4000-8000-000000000001')
        self.assertEqual(Target.parse({'kind': 'adguard', 'id': 'adguardvpn-gnome'}).kind, 'adguard')
        for value in ({}, [], {'kind': 'networkmanager', 'id': 'tun0'},
                      {'kind': 'direct', 'id': 'main'}, {'kind': 'adguard', 'id': '/bin/sh'},
                      {'kind': 'direct', 'id': 'direct', 'table': 880}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                Target.parse(value)

    def test_addresses_include_both_families_and_are_bounded_unicast_values(self):
        self.assertEqual(normalize_addresses(['198.51.100.8', '2001:db8:0::8', '198.51.100.8']),
                         ('198.51.100.8', '2001:db8::8'))
        for value in (['127.0.0.1'], ['::1'], ['fe80::1'], ['224.0.0.1'],
                      ['0.0.0.0'], ['::'], ['255.255.255.255'], ['bad'], '198.51.100.8',
                      ['198.51.100.1'] * 513):
            with self.subTest(value=value), self.assertRaises(ValueError):
                normalize_addresses(value)

    def test_protocol_rejects_unrecognized_fields_and_limits_input_before_privileged_work(self):
        self.assertEqual(validate_request({'operation': 'list-providers'})['operation'], 'list-providers')
        request = validate_request({'operation': 'add-rule', 'domain': 'https://EXAMPLE.com/a',
                                   'target': {'kind': 'direct', 'id': 'direct'}})
        self.assertEqual(request['domain'], 'example.com')
        for value in ({'operation': 'shell', 'command': 'id'},
                      {'operation': 'list-rules', 'uid': 0},
                      {'operation': 'add-rule', 'domain': '*.example',
                       'target': {'kind': 'direct', 'id': 'direct'}},
                      {'operation': 'remove-rule', 'id': '../../state'},
                      {'operation': 'add-rule', 'domain': 'example.com',
                       'target': {'kind': 'direct', 'id': 'direct'}, 'interface': 'tun0'}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate_request(value)
