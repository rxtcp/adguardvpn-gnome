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
        active = [row for row in snapshot['active'] if row['state'] == 2]
        owners = Counter((family, index) for row in active for family, indices in row['interface_indices'].items()
                         for index in indices)
        profiles = []
        for profile in snapshot['profiles']:
            activations = [row for row in active if row['uuid'] == profile['uuid']]
            activation = activations[0] if len(activations) == 1 else {}
            indices = {family: tuple(index for index in binding if owners[family, index] == 1)
                       for family, binding in activation.get('interface_indices', {}).items()}
            profiles.append({**profile, 'interfaces': activation.get('interfaces', []), 'interface_indices': indices})
        return profiles

    @staticmethod
    def _verified_interface_indices(activations, devices, ip_configs, links):
        # NM shares an IP configuration object between its VPN activation and the
        # device for that interface. The VPN activation's Devices list is the base.
        link_indices = {link['ifname']: link['ifindex'] for link in links}
        claims = Counter((field, active.get(field)) for active in activations.values()
                         if active['State'] == 2 for field in IP_CONFIG.values())
        result = {}
        for path, active in activations.items():
            kind = active['Type']
            if active['State'] != 2:
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
                device = devices[matching[0]]
                name = device.get('IpInterface') or device.get('Interface')
                # The index comes from NM's IP configuration, not a local name lookup.
                index = ip_configs[config].get('InterfaceIndex')
                if type(index) is int and index > 0 and link_indices.get(name) == index:
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
            ip_configs = {'/': {}}
            for properties in activations.values():
                for family, field in IP_CONFIG.items():
                    config = properties.get(field, '/')
                    if config not in ip_configs:
                        ip_configs[config] = self.bus.properties(owner, config, NM + f'.IP{family}Config')
            interface_bindings = self._verified_interface_indices(activations, devices, ip_configs, links)
            active = []
            for path, properties in activations.items():
                indices = interface_bindings.get(path, {})
                if properties['Type'] in TUNNEL_PROFILES:
                    interfaces = [link['ifname'] for link in links if any(link['ifindex'] in binding for binding in indices.values())]
                else:
                    interfaces = [device.get('IpInterface') or device.get('Interface')
                                  for name in properties.get('Devices', []) if (device := devices.get(name))]
                configurations = {f'ip{family}': ip_configs[properties.get(field, '/')]
                                  for family, field in IP_CONFIG.items()}
                active.append({'uuid': properties['Uuid'], 'name': properties['Id'], 'type': properties['Type'],
                               'state': properties['State'], 'interfaces': interfaces, 'interface_indices': indices,
                               'tunnel_indices': indices if properties['Type'] in TUNNEL_PROFILES else {}, **configurations})
            return {'profiles': profiles, 'active': active, 'links': links}
        except (KeyError, RuntimeError):
            return {'profiles': [], 'active': [], 'links': links}
