"""Native GVariant contracts with fake bus connections, never the host system bus."""
import copy
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

from gi.repository import Gio, GLib

from site_routing import adguard
from site_routing.dbus_transport import SystemBus, bindings
from site_routing.networkmanager import NetworkManagerReader
from site_routing.variant_settings import remove_entries
from site_routing_fakes import NM_ID


def settings_variant():
    return GLib.Variant('a{sa{sv}}', {
        'connection': {'id': GLib.Variant('s', 'Fixture VPN'), 'uuid': GLib.Variant('s', NM_ID),
                       'type': GLib.Variant('s', 'vpn'), 'permissions': GLib.Variant('as', ['user:fixtureuser:'])},
        'ipv4': {'method': GLib.Variant('s', 'auto'), 'route-data': GLib.Variant('aa{sv}', [
            {'dest': GLib.Variant('s', '198.51.100.8'), 'prefix': GLib.Variant('u', 32)},
            {'dest': GLib.Variant('s', '203.0.113.0'), 'prefix': GLib.Variant('u', 24)}])},
    })


class NativeBusTests(unittest.TestCase):
    def test_unusable_profile_versions_refuse_migration(self):
        class Connection:
            def call_sync(self, *_args):
                return GLib.Variant('(v)', (GLib.Variant('t', 0),))
        with self.assertRaisesRegex(RuntimeError, 'usable profile version'):
            SystemBus(Gio, GLib, Connection()).profile_version(':1.27', '/profile')

    def test_variant_patch_preserves_signatures_and_every_untouched_setting(self):
        before = settings_variant()
        serialized, after = remove_entries(GLib, before.print_(True), [
            {'setting': 'ipv4', 'field': 'route-data', 'indices': [0]}])
        self.assertEqual(after['connection'], before.unpack()['connection'])
        self.assertEqual(after['ipv4']['method'], 'auto')
        self.assertEqual(after['ipv4']['route-data'], [{'dest': '203.0.113.0', 'prefix': 24}])
        self.assertIn('uint32', serialized)
        with self.assertRaises(ValueError):
            remove_entries(GLib, before.print_(True), [{'setting': 'ipv4', 'field': 'route-data', 'indices': [99]}])

    def test_transport_builds_native_dbus_signatures_and_never_requests_secrets(self):
        class Connection:
            def __init__(self): self.calls, self.error = [], False
            def call_sync(self, *args):
                self.calls.append(args)
                if self.error: raise GLib.Error('private diagnostic that must not escape')
                if args[3] == 'GetSettings': return GLib.Variant.new_tuple(settings_variant())
                if args[3] == 'GetAll': return GLib.Variant('(a{sv})', ({'State': GLib.Variant('u', 2)},))
                return GLib.Variant('()', ())
        connection = Connection()
        with patch.object(Gio, 'bus_get_sync', return_value=connection):
            bus = SystemBus(Gio, GLib)
        self.assertEqual(bindings(), (Gio, GLib))
        self.assertEqual(bus.properties('fixture', '/fixture', 'fixture')['State'], 2)
        settings, serialized = bus.settings('/fixture')
        self.assertEqual(settings['connection']['uuid'], NM_ID)
        bus.update_settings('/fixture', serialized, owner=':1.27', version=21)
        self.assertEqual(connection.calls[-1][4].get_type_string(), '(a{sa{sv}}ua{sv})')
        self.assertEqual(connection.calls[-1][4].get_child_value(2).lookup_value('version-id', None).get_type_string(), 't')
        self.assertNotIn('GetSecrets', [call[3] for call in connection.calls])
        connection.error = True
        with self.assertRaisesRegex(RuntimeError, 'unavailable'):
            bus.call('fixture', '/fixture', 'fixture', 'GetAll')
        with self.assertRaisesRegex(RuntimeError, 'rejected'):
            bus.update_settings('/fixture', serialized, owner=':1.27', version=21)


class NetworkManagerAdapterTests(unittest.TestCase):
    def test_profile_write_refuses_a_concurrent_edit_and_uses_the_snapshotted_version(self):
        class Connection:
            def __init__(self):
                self.profile = settings_variant()
                self.version = 21
                self.updated = None

            def call_sync(self, destination, path, interface, method, parameters, *_args):
                if method == 'GetNameOwner':
                    return GLib.Variant('(s)', (':1.27',))
                if method == 'Get':
                    return GLib.Variant('(v)', (GLib.Variant('t', self.version),))
                if method == 'GetSettings':
                    return GLib.Variant.new_tuple(self.profile)
                # An edit arrives after the caller's final read but before Update2.
                self.version += 1
                settings = {key: self.profile.lookup_value(key, None).unpack() for key in ('connection',)}
                settings['connection']['id'] = 'Concurrent rename'
                self.name = settings['connection']['id']
                self.updated = (destination, parameters.unpack()[2])
                if self.updated[1].get('version-id') != self.version:
                    raise GLib.Error('version mismatch')
                self.name = 'Overwritten'
                return GLib.Variant('()', ())

        connection = Connection()
        bus = SystemBus(Gio, GLib, connection)
        reader = NetworkManagerReader(bus, None)
        version = connection.profile.print_(True)
        profile = {'path': '/profile', 'uuid': NM_ID, 'settings': connection.profile.unpack()}
        with self.assertRaisesRegex(RuntimeError, 'rejected'):
            reader.update(profile, version)
        self.assertEqual(connection.updated, (':1.27', {'version-id': 21}))
        self.assertEqual(connection.name, 'Concurrent rename')

    def setUp(self):
        class Bus:
            glib = GLib
            def __init__(self):
                self.count, self.broken, self.updated, self.owner = 1, False, None, ':1.27'
                self.manager = {'ActiveConnections': ['/active', '/physical'], 'Devices': ['/device', '/tun']}
                self.active = {'Uuid': NM_ID, 'Id': 'Fixture VPN', 'Type': 'vpn', 'State': 2,
                               'Devices': ['/device'], 'Ip4Config': '/ip4', 'Ip6Config': '/'}
                self.physical = {'Uuid': 'uplink', 'Id': 'Fixture uplink', 'Type': '802-3-ethernet', 'State': 2,
                                 'Devices': ['/device'], 'Ip4Config': '/uplink-ip4'}
                self.tunnel = {'IpInterface': 'fixturevpn', 'Ip4Config': '/ip4', 'ActiveConnection': '/'}
            def networkmanager_owner(self): return self.owner
            def profile_version(self, owner, path): return 21
            def call(self, *args): return (['/profile'] * self.count,)
            def settings(self, path, *, owner):
                value = settings_variant()
                return value.unpack(), value.print_(True)
            def properties(self, destination, path, interface):
                if self.broken: raise RuntimeError('NM restarting')
                return {'/org/freedesktop/NetworkManager': self.manager, '/active': self.active, '/physical': self.physical,
                         '/device': {'Interface': 'fixturewan', 'Ip4Config': '/uplink-ip4', 'ActiveConnection': '/physical'},
                         '/tun': self.tunnel, '/ip4': {'AddressData': [{'address': '192.0.2.2'}]},
                         '/ip4-new': {'AddressData': [{'address': '192.0.2.2'}]},
                         '/uplink-ip4': {'AddressData': [{'address': '192.0.2.3'}]}}[path]
            def update_settings(self, path, serialized, *, owner, version):
                self.updated = path, serialized, owner, version
        self.bus = Bus()
        self.links = [{'ifname': 'fixturevpn', 'ifindex': 17}, {'ifname': 'fixturewan', 'ifindex': 4}]
        self.reader = NetworkManagerReader(self.bus, SimpleNamespace(read_links=lambda: self.links))

    def test_saved_profiles_permissions_and_active_ip_configurations_are_read_without_activation(self):
        snapshot = self.reader.snapshot()
        self.assertEqual(snapshot['profiles'][0]['users'], ('fixtureuser',))
        self.assertEqual(snapshot['active'][0]['interfaces'], ['fixturevpn'])
        self.assertEqual(snapshot['active'][0]['tunnel_indices'], {4: (17,)})
        self.assertEqual(snapshot['active'][1]['interfaces'], ['fixturewan'])
        self.assertEqual(snapshot['active'][0]['ip6'], {})
        self.assertEqual(snapshot['active'][0]['ip4']['AddressData'][0]['address'], '192.0.2.2')
        self.assertEqual(self.reader.migration_profiles()[0]['interfaces'], ['fixturevpn'])
        profile = snapshot['profiles'][0]
        serialized, settings = self.reader.render_without(profile['serialized'], [{'setting': 'ipv4', 'field': 'route-data', 'indices': [0]}])
        self.reader.update(profile, serialized)
        self.assertEqual(self.bus.updated, ('/profile', serialized, ':1.27', 21))
        self.assertEqual(len(settings['ipv4']['route-data']), 1)

    def test_restart_and_oversized_registry_do_not_create_fake_active_providers(self):
        self.bus.broken = True
        self.assertEqual(self.reader.snapshot()['active'], [])
        self.bus.count = 1025
        with self.assertRaises(RuntimeError): self.reader.profiles()

    def test_nm_object_binding_refuses_base_device_same_name_reuse_and_ambiguous_claims(self):
        def binding():
            return self.reader.snapshot()['active'][0]['tunnel_indices']

        self.assertEqual(binding(), {4: (17,)})
        self.links[0]['ifindex'] = 27
        self.assertEqual(binding(), {})
        self.bus.active['Ip4Config'] = '/ip4-new'
        self.assertEqual(binding(), {})
        self.bus.tunnel['Ip4Config'] = '/ip4-new'
        self.assertEqual(binding(), {4: (27,)})
        self.bus.active['Devices'] = ['/tun']
        self.assertEqual(binding(), {})
        self.bus.active['Type'] = 'wireguard'
        self.assertEqual(binding(), {})
        self.bus.tunnel['ActiveConnection'] = '/active'
        self.assertEqual(binding(), {4: (27,)})
        self.bus.physical.update({**self.bus.active, 'Uuid': 'other'})
        self.assertEqual(binding(), {})
        self.bus.physical['State'] = 1
        self.links[0]['ifindex'] = 37
        self.bus.owner = ':1.28'
        self.assertEqual(binding(), {4: (37,)})
        self.bus.manager['Devices'] *= 513
        self.assertEqual(self.reader.snapshot()['active'], [])

    def test_race_during_the_profile_read_never_sends_update2(self):
        profile = self.reader.profiles()[0]
        with patch.object(self.bus, 'profile_version', side_effect=[21, 22]):
            with self.assertRaisesRegex(RuntimeError, 'overwrite was refused'):
                self.reader.update(profile, 'irrelevant')
        with self.assertRaisesRegex(RuntimeError, 'overwrite was refused'):
            self.reader.update({**profile, 'settings': {}}, 'irrelevant')
        self.assertIsNone(self.bus.updated)


class ProtectedAdguardAdapterTests(unittest.TestCase):
    def test_only_verified_service_process_tun_descriptors_are_used(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            control, executable, descriptors = root / 'control', root / 'cli', root / 'fdinfo'
            control.touch(); executable.touch(); descriptors.mkdir()
            (descriptors / '1').write_text('pos: 0\niff:\tfixturevpn\n')
            (descriptors / '2').write_text('pos: 0\n')
            process = SimpleNamespace(stat=lambda: SimpleNamespace(st_uid=0))
            class Process:
                def stat(self): return process.stat()
                def __truediv__(self, key):
                    return SimpleNamespace(resolve=lambda strict: executable) if key == 'exe' else descriptors
            class Proc:
                def __truediv__(self, pid): return Process()
            bus = SimpleNamespace(call=lambda *args: ('/unit',), properties=lambda *args: {'MainPID': 123})
            runner = SimpleNamespace(run=lambda args: 'Connected to Miami in TUN mode')
            with patch.object(adguard, 'CONTROL', control), patch.object(adguard, 'CLI', executable), \
                 patch.object(adguard, 'Path', return_value=Proc()), patch.object(adguard, 'verify_path'):
                result = adguard.protected_tunnel(bus, runner)
                self.assertEqual(result['interfaces'], ['fixturevpn'])
                process.stat = lambda: SimpleNamespace(st_uid=1000)
                self.assertFalse(adguard.protected_tunnel(bus, runner)['connected'])
                process.stat = lambda: SimpleNamespace(st_uid=0)
                runner.run = lambda args: 'Disconnected'
                self.assertFalse(adguard.protected_tunnel(bus, runner)['connected'])
                runner.run = lambda args: 'Connected to Miami'
                bus.properties = lambda *args: {'MainPID': 0}
                self.assertFalse(adguard.protected_tunnel(bus, runner)['connected'])
            with patch.object(adguard, 'CONTROL', root / 'absent'):
                self.assertFalse(adguard.protected_tunnel(bus, runner)['installed'])
