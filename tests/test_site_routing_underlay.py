from contextlib import nullcontext, redirect_stderr, redirect_stdout
import io
from pathlib import Path
import unittest
from unittest.mock import Mock, patch

from site_routing import entry, underlay

VPN = '00000000-0000-4000-8000-000000000001'
UPLINK = '00000000-0000-4000-8000-000000000002'
OTHER = '00000000-0000-4000-8000-000000000003'
ACTIVE = '/org/freedesktop/NetworkManager/ActiveConnection/'


def rules():
    mark = {'fwmark': '0x53495445', 'src': 'all', 'protocol': '197'}
    return [{**mark, 'priority': 10, 'table': 39990},
            {**mark, 'priority': 11, 'action': 'unreachable'}]


class UnderlayTests(unittest.TestCase):
    def test_terminal_guard_precedes_lookup_and_cleanup_only_removes_owned_rules(self):
        runner = Mock()
        runner.read_ip.side_effect = [[], [], rules(), rules()]
        underlay.change_policy(runner, remove=False)
        self.assertEqual([call.args[1:4] for call in runner.write_ip.call_args_list],
                         [('rule', 'add', 'unreachable')] * 2 + [('rule', 'add', 'priority')] * 2)
        self.assertEqual([call.args[0] for call in runner.write_ip.call_args_list], [4, 6, 4, 6])
        runner.write_ip.reset_mock()
        runner.read_ip.side_effect = [rules(), [rules()[1], {'priority': 11, 'table': 880}]]
        underlay.change_policy(runner, remove=True)
        self.assertEqual(len(runner.write_ip.call_args_list), 3)
        self.assertEqual(runner.write_ip.call_args_list[0].args[1:4], ('rule', 'del', 'priority'))
        self.assertTrue(all('197' in call.args for call in runner.write_ip.call_args_list))

    def test_policy_refuses_foreign_priority_before_any_write(self):
        runner = Mock()
        runner.read_ip.side_effect = [rules(), [{'priority': 10, 'table': 880}]]
        with self.assertRaisesRegex(RuntimeError, 'priority'):
            underlay.change_policy(runner, remove=False)
        runner.write_ip.assert_not_called()

    def test_policy_rechecks_both_families_and_preserves_site_rules(self):
        site_rule = {'priority': 8, 'dst': '198.51.100.8', 'protocol': '196', 'table': 40000}
        local = {'priority': 0, 'table': 255}
        site_deny = {'priority': 9, 'dst': '198.51.100.8', 'protocol': '196', 'action': 'unreachable'}
        runner = Mock()
        runner.read_ip.side_effect = [[site_rule, site_deny, local, *rules()], rules()]
        underlay.verify_policy(runner)
        for invalid in ([rules()[0]], [*rules(), {'priority': 1, 'table': 880}],
                        [rules()[0], {**rules()[1], 'fwmask': '0x0'}],
                        [rules()[0], {**rules()[1], 'fwmark': '0x1'}],
                        [*rules(), {**site_rule, 'dst': '198.51.100.0/24'}],
                        [*rules(), {**site_rule, 'table': 880}],
                        [*rules(), {**rules()[0], 'invert': True}], [*rules(), rules()[0]]):
            runner.read_ip.side_effect = [invalid, rules()]
            with self.assertRaises(RuntimeError):
                underlay.verify_policy(runner)

    def test_only_verified_nm_base_and_dedicated_routes_can_mark_a_launch(self):
        configuration = underlay.Configuration(VPN, UPLINK)
        bus, runner = Mock(), Mock()
        device = '/org/freedesktop/NetworkManager/Devices/1'
        link = {'ifname': 'fixturewan', 'ifindex': 2, 'flags': ['UP'],
                'addr_info': [{'local': '192.0.2.2'}, {'local': '2001:db8::2'}]}
        vpn = {'Uuid': VPN, 'State': 1, 'Vpn': True, 'SpecificObject': ACTIVE + '2'}
        uplink = {'Uuid': UPLINK, 'State': 2, 'Type': '802-3-ethernet', 'Devices': [device],
                  'Ip4Config': '/ip4', 'Ip6Config': '/ip6'}
        routes = {
            4: [{'dst': 'default', 'table': 39990, 'dev': 'fixturewan', 'gateway': '192.0.2.1'},
                {'dst': '192.0.2.0/24', 'table': 39990, 'dev': 'fixturewan'}],
            6: [{'dst': 'default', 'table': 39990, 'dev': 'fixturewan', 'gateway': 'fe80::1'}],
        }
        runner.read_ip.side_effect = lambda family, kind, *_args: rules() if kind == 'rule' else routes[family]
        runner.read_links.return_value = [link]
        data = {underlay.ROOT: {'ActiveConnections': [ACTIVE + '1', ACTIVE + '2']},
                ACTIVE + '1': vpn, ACTIVE + '2': uplink,
                device: {'ActiveConnection': ACTIVE + '2', 'IpInterface': 'fixturewan'},
                '/ip4': {'AddressData': [{'address': '192.0.2.2'}], 'Gateway': '192.0.2.1'},
                '/ip6': {'AddressData': [{'address': '2001:db8::2'}], 'Gateway': 'fe80::1'}}
        bus.properties.side_effect = lambda _destination, path, _interface: data[path]
        self.assertEqual(underlay.verify_activation(configuration, bus, runner), 'fixturewan')
        routes[6] = [{'dst': 'fe80::/64', 'table': 39990, 'dev': 'fixturewan'}]
        underlay.verify_activation(configuration, bus, runner)
        for row in ({'dst': 'default', 'table': 39990, 'dev': 'foreign'},
                    {'dst': 'default', 'table': 39990, 'dev': 'fixturewan', 'gateway': '192.0.2.3'},
                    {'dst': 'default', 'table': 39990, 'dev': 'fixturewan', 'gateway': '192.0.2.1', 'nexthops': []}):
            old, routes[4][0] = routes[4][0], row
            with self.assertRaisesRegex(RuntimeError, 'dedicated'):
                underlay.verify_activation(configuration, bus, runner)
            routes[4][0] = old
        vpn['SpecificObject'] = ACTIVE + '3'
        with self.assertRaisesRegex(RuntimeError, 'selected base'):
            underlay.verify_activation(configuration, bus, runner)
        vpn['SpecificObject'] = ACTIVE + '2'
        vpn['State'] = 2
        with self.assertRaisesRegex(RuntimeError, 'unique activating'):
            underlay.verify_activation(configuration, bus, runner)
        vpn['State'] = 1
        uplink['Devices'].append(device)
        with self.assertRaisesRegex(RuntimeError, 'physical'):
            underlay.verify_activation(configuration, bus, runner)
        uplink['Devices'].pop()
        data[device]['ActiveConnection'] = ACTIVE + '3'
        with self.assertRaisesRegex(RuntimeError, 'device'):
            underlay.verify_activation(configuration, bus, runner)
        data[device]['ActiveConnection'] = ACTIVE + '2'
        routes[4].append(routes[4][0])
        with self.assertRaisesRegex(RuntimeError, 'unique usable default'):
            underlay.verify_activation(configuration, bus, runner)
        routes[4].pop()
        routes[4][0]['flags'] = ['linkdown']
        with self.assertRaisesRegex(RuntimeError, 'unique usable default'):
            underlay.verify_activation(configuration, bus, runner)
        del routes[4][0]['flags']
        old_gateway = data['/ip4'].pop('Gateway')
        with self.assertRaisesRegex(RuntimeError, 'unique usable default'):
            underlay.verify_activation(configuration, bus, runner)
        data['/ip4']['Gateway'] = old_gateway
        routes[4] = []
        with self.assertRaisesRegex(RuntimeError, 'no verified default'):
            underlay.verify_activation(configuration, bus, runner)
        data[underlay.ROOT]['ActiveConnections'] *= 513
        with self.assertRaisesRegex(RuntimeError, 'activation limit'):
            underlay.verify_activation(configuration, bus, runner)

    def test_root_configuration_is_bounded_and_independent_of_client_settings(self):
        document = ('{"vpn":"' + VPN + '","uplink":"' + UPLINK + '"}').encode()
        with patch.object(underlay, 'verify_path') as trust, patch.object(underlay, 'verified_open', return_value=7), \
             patch.object(underlay.os, 'read', return_value=document) as read, patch.object(underlay.os, 'close') as close:
            self.assertEqual(underlay.read_config(Path('/fixture/config')), underlay.Configuration(VPN, UPLINK))
            trust.assert_called_once_with(Path('/fixture/config'), private=True)
            close.assert_called_once_with(7)
            for invalid in (b'x' * 4097, b'[]', b'{"vpn":42,"uplink":"x"}',
                            document.replace(UPLINK.encode(), VPN.encode()), b'{}', b'\xff'):
                read.return_value = invalid
                with self.assertRaises(ValueError):
                    underlay.read_config(Path('/fixture/config'))
            trust.side_effect = FileNotFoundError
            self.assertIsNone(underlay.read_config(Path('/fixture/config')))

    def test_helper_outputs_only_a_fixed_mark_for_the_opted_in_activation(self):
        with patch.object(underlay, 'read_config', return_value=underlay.Configuration(VPN, UPLINK)), \
             patch.object(underlay, 'bindings', return_value=(Mock(), Mock())), patch.object(underlay, 'SystemBus'), \
             patch.object(underlay, 'verify_activation', return_value='fixturewan') as verify, redirect_stdout(io.StringIO()) as output:
            self.assertEqual(underlay.launch_mark(OTHER), 0)
            self.assertEqual(output.getvalue(), '')
            self.assertEqual(underlay.launch_mark(VPN), 0)
            self.assertEqual(output.getvalue(), '1397314629 fixturewan\n')
            verify.assert_called_once()
            verify.side_effect = RuntimeError('unverified fixture')
            with redirect_stderr(io.StringIO()) as errors:
                self.assertEqual(underlay.launch_mark(VPN), 1)
                self.assertEqual(underlay.launch_mark('not-a-uuid'), 1)
            self.assertIn('unverified fixture', errors.getvalue())
            self.assertIn('invalid configuration', errors.getvalue())

    def test_existing_policy_is_detected_and_restoration_is_idempotent(self):
        runner = Mock()
        runner.read_ip.side_effect = [rules(), rules(), rules(), rules()]
        underlay.change_policy(runner, remove=False)
        runner.write_ip.assert_not_called()
        runner.read_ip.side_effect = [[], rules(), [], []]
        self.assertTrue(underlay.has_policy(runner))
        self.assertFalse(underlay.has_policy(runner))

    def test_install_and_removal_keep_optional_policy_separate_from_site_releases(self):
        store, runner = Mock(lock=nullcontext), Mock()
        with patch.multiple(entry, StateStore=Mock(return_value=store), CommandRunner=Mock(return_value=runner),
                            KernelBackend=Mock(), restore_guard=Mock(), release_all=Mock(), has_policy=Mock(return_value=False),
                            read_config=Mock(return_value=underlay.Configuration(VPN, UPLINK)), change_policy=Mock()), \
             patch.object(entry.os, 'geteuid', return_value=0), redirect_stderr(io.StringIO()) as output:
            self.assertEqual(entry.main('restore'), 0)
            entry.change_policy.assert_called_once_with(runner, remove=False)
            self.assertEqual(entry.main('apply-underlay'), 0)
            self.assertEqual(entry.change_policy.call_args.kwargs, {'remove': False})
            self.assertEqual(entry.main('remove-underlay'), 2)
            self.assertEqual(entry.main('release'), 2)
            entry.release_all.assert_not_called()
            entry.change_policy.side_effect = RuntimeError('fixture collision')
            self.assertEqual(entry.main('restore'), 0)
            self.assertIn('marked launcher will refuse', output.getvalue())
            entry.change_policy.side_effect = None
            entry.read_config.return_value = None
            self.assertEqual(entry.main('apply-underlay'), 2)
            self.assertIn('Install the private', output.getvalue())
            entry.has_policy.return_value = True
            self.assertEqual(entry.main('check-empty'), 2)
            self.assertEqual(entry.main('remove-underlay'), 0)
            self.assertEqual(entry.change_policy.call_args.args, (runner,))
            self.assertEqual(entry.change_policy.call_args.kwargs, {'remove': True})


if __name__ == '__main__':
    unittest.main()
