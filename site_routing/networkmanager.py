"""NetworkManager D-Bus snapshots; never activates or renames a connection."""
from .dbus_transport import NM, SETTINGS

ROOT = '/org/freedesktop/NetworkManager'


class NetworkManagerReader:
    def __init__(self, bus, runner):
        self.bus, self.runner = bus, runner

    def profiles(self) -> list[dict]:
        paths = self.bus.call(NM, SETTINGS, NM + '.Settings', 'ListConnections')[0]
        if len(paths) > 1024:
            raise RuntimeError('NetworkManager profile limit exceeded.')
        profiles = []
        for path in paths:
            settings, serialized = self.bus.settings(path)
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
        self.bus.update_settings(profile['path'], serialized)

    def snapshot(self) -> dict:
        links = self.runner.read_links()
        try:
            profiles = self.profiles()
            paths = self.bus.properties(NM, ROOT, NM)['ActiveConnections']
            active = []
            for path in paths[:1024]:
                properties = self.bus.properties(NM, path, NM + '.Connection.Active')
                interfaces = []
                for device in properties.get('Devices', []):
                    data = self.bus.properties(NM, device, NM + '.Device')
                    interfaces.append(data.get('IpInterface') or data.get('Interface'))
                configurations = {}
                for family in (4, 6):
                    configuration = properties.get(f'Ip{family}Config', '/')
                    configurations[f'ip{family}'] = self.bus.properties(NM, configuration, NM + f'.IP{family}Config') if configuration != '/' else {}
                active.append({'uuid': properties['Uuid'], 'name': properties['Id'], 'type': properties['Type'],
                               'state': properties['State'], 'interfaces': interfaces, **configurations})
            return {'profiles': profiles, 'active': active, 'links': links}
        except (KeyError, RuntimeError):
            return {'profiles': [], 'active': [], 'links': links}
