"""Small Gio transport, injected into adapters so tests never touch the host bus."""
NM = 'org.freedesktop.NetworkManager'
SETTINGS = '/org/freedesktop/NetworkManager/Settings'
CONNECTION_IFACE = NM + '.Settings.Connection'


def bindings():
    import gi
    gi.require_version('Gio', '2.0')
    from gi.repository import Gio, GLib
    return Gio, GLib


class SystemBus:
    def __init__(self, gio, glib, connection=None):
        self.gio, self.glib = gio, glib
        self.connection = connection if connection is not None else gio.bus_get_sync(gio.BusType.SYSTEM, None)

    def raw(self, destination, path, interface, method, signature=None, values=None, timeout=5000):
        parameters = self.glib.Variant(signature, values) if signature else None
        try:
            return self.connection.call_sync(destination, path, interface, method, parameters, None,
                                             self.gio.DBusCallFlags.NONE, timeout, None)
        except self.glib.Error as error:
            raise RuntimeError('A required system D-Bus provider is unavailable.') from error

    def call(self, *args, **kwargs):
        return self.raw(*args, **kwargs).unpack()

    def properties(self, destination, path, interface):
        return self.call(destination, path, 'org.freedesktop.DBus.Properties', 'GetAll', '(s)', (interface,))[0]

    def settings(self, path):
        value = self.raw(NM, path, CONNECTION_IFACE, 'GetSettings').get_child_value(0)
        return value.unpack(), value.print_(True)

    def update_settings(self, path, serialized):
        value = self.glib.Variant.parse(self.glib.VariantType.new('a{sa{sv}}'), serialized, None, None)
        parameters = self.glib.Variant.new_tuple(value, self.glib.Variant('u', 1), self.glib.Variant('a{sv}', {}))
        try:
            self.connection.call_sync(NM, path, CONNECTION_IFACE, 'Update2', parameters, None,
                                      self.gio.DBusCallFlags.NONE, 5000, None)
        except self.glib.Error as error:
            raise RuntimeError('NetworkManager rejected the confirmed migration update.') from error
