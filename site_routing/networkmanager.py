"""NetworkManager D-Bus snapshots; never activates or renames a connection."""
from collections import Counter

from .dbus_transport import NM, SETTINGS
from .migration_fields import settings_hash

ROOT = '/org/freedesktop/NetworkManager'
TUNNEL_PROFILES = ('vpn', 'wireguard')
IP_CONFIG = {4: 'Ip4Config', 6: 'Ip6Config'}


class NetworkManagerReader:
    def __init__(self, bus, runner):
        self.bus, self.runner = bus, runner
        self.tunnel_indices = {}

    def profiles(self, *, owner=NM) -> list[dict]:
        paths = self.bus.call(owner, SETTINGS, NM + '.Settings', 'ListConnections')[0]
        if len(paths) > 1024:
            raise RuntimeError('NetworkManager profile limit exceeded.')
        profiles = []
        for path in paths:
            settings, serialized = self.bus.settings(path, owner=owner)
            connection = settings.get('connection', {})
            permissions = connection.get('permissions', [])
            users = tuple(value.split(':')[1] if value.startswith('user:') else '!unsupported!' for value in permissions)
            profiles.append({'uuid': connection['uuid'], 'name': connection['id'], 'type': connection['type'],
                             'users': users, 'path': path, 'settings': settings, 'serialized': serialized})
        return profiles

    def render_without(self, serialized: str, patches: list[dict]):
        from .variant_settings import remove_entries
        return remove_entries(self.bus.glib, serialized, patches)

    def update(self, profile: dict, serialized: str) -> None:
        owner, path = self.bus.networkmanager_owner(), profile['path']
        version = self.bus.profile_version(owner, path)
        current, _ = self.bus.settings(path, owner=owner)
        if version != self.bus.profile_version(owner, path) or settings_hash(current) != settings_hash(profile['settings']):
            raise RuntimeError('NetworkManager settings changed during verification; automatic overwrite was refused.')
        self.bus.update_settings(path, serialized, owner=owner, version=version)

    def migration_profiles(self) -> list[dict]:
        snapshot = self.snapshot()
        return [{**profile, 'interfaces': [name for active in snapshot['active'] if active['uuid'] == profile['uuid']
                                           for name in active['interfaces']]} for profile in snapshot['profiles']]

    def _verified_tunnel_indices(self, owner, activations, devices, links):
        # NM shares an IP configuration object between its VPN activation and the
        # device for that interface. The VPN activation's Devices list is the base.
        device_keys = {(owner, path, device.get(field)) for path, device in devices.items() for field in IP_CONFIG.values()}
        self.tunnel_indices = {key: index for key, index in self.tunnel_indices.items() if key in device_keys}
        link_indices = {link['ifname']: link['ifindex'] for link in links}
        claims = Counter((field, active.get(field)) for active in activations.values() if active['Type'] in TUNNEL_PROFILES
                         and active['State'] == 2 for field in IP_CONFIG.values())
        result = {}
        for path, active in activations.items():
            kind = active['Type']
            if kind not in TUNNEL_PROFILES or active['State'] != 2:
                continue
            for family, field in IP_CONFIG.items():
                config = active.get(field)
                if not config or config == '/' or claims[field, config] != 1:
                    continue
                selected_devices = active.get('Devices', [])
                matching = [device_path for device_path, device in devices.items() if device.get(field) == config and
                            (device_path not in selected_devices if kind == 'vpn' else
                             device_path in selected_devices and device.get('ActiveConnection') == path)]
                if len(matching) != 1:
                    continue
                device_path = matching[0]
                device = devices[device_path]
                name = device.get('IpInterface') or device.get('Interface')
                index = link_indices.get(name)
                # A stale object must never adopt a new kernel link of the same name.
                if index and self.tunnel_indices.setdefault((owner, device_path, config), index) == index:
                    result.setdefault(path, {})[family] = (index,)
        return result

    def snapshot(self) -> dict:
        links = self.runner.read_links()
        try:
            owner = self.bus.networkmanager_owner()
            profiles = self.profiles(owner=owner)
            manager = self.bus.properties(owner, ROOT, NM)
            paths, device_paths = manager['ActiveConnections'], manager['Devices']
            if len(paths) > 1024 or len(device_paths) > 1024:
                raise RuntimeError('NetworkManager active connection or device limit exceeded.')
            activations = {path: self.bus.properties(owner, path, NM + '.Connection.Active') for path in paths}
            devices = {path: self.bus.properties(owner, path, NM + '.Device') for path in device_paths}
            tunnel_bindings = self._verified_tunnel_indices(owner, activations, devices, links)
            active = []
            for path, properties in activations.items():
                indices = tunnel_bindings.get(path, {})
                if properties['Type'] in TUNNEL_PROFILES:
                    interfaces = [link['ifname'] for link in links if any(link['ifindex'] in binding for binding in indices.values())]
                else:
                    interfaces = [device.get('IpInterface') or device.get('Interface')
                                  for name in properties.get('Devices', []) if (device := devices.get(name))]
                configurations = {}
                for family, field in IP_CONFIG.items():
                    config = properties.get(field, '/')
                    configurations[f'ip{family}'] = self.bus.properties(owner, config, NM + f'.IP{family}Config') if config != '/' else {}
                active.append({'uuid': properties['Uuid'], 'name': properties['Id'], 'type': properties['Type'],
                               'state': properties['State'], 'interfaces': interfaces, 'tunnel_indices': indices, **configurations})
            return {'profiles': profiles, 'active': active, 'links': links}
        except (KeyError, RuntimeError):
            return {'profiles': [], 'active': [], 'links': links}
