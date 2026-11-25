"""System daemon lifecycle; settings windows and GNOME Shell may close at any time."""
import signal
import logging

from .adguard import protected_tunnel
from .authorization import PolkitAuthorizer
from .dbus_service import DbusService
from .dbus_transport import SystemBus, bindings
from .dns import DnsResolver
from .lifecycle import restore_guard
from .manager import RoutingManager
from .migrations import MigrationManager
from .network_events import NetworkEvents
from .networkmanager import NetworkManagerReader
from .providers import ProviderRegistry
from .rpc import BUS_NAME, INTROSPECTION, OBJECT_PATH, RequestDispatcher
from .scheduler import ReconciliationWorker


def serve(store, kernel, runner) -> None:
    logging.basicConfig(level=logging.INFO, format='%(levelname)s %(message)s')
    gio, glib = bindings()
    bus = SystemBus(gio, glib)
    restore_guard(store, kernel)
    reader = NetworkManagerReader(bus, runner)
    registry = ProviderRegistry(reader, lambda: protected_tunnel(bus, runner))
    manager = RoutingManager(store, registry, DnsResolver(), kernel,
                             migrations=MigrationManager(store, reader, kernel))
    service = DbusService(RequestDispatcher(manager, PolkitAuthorizer(bus)), glib)
    worker = ReconciliationWorker(manager)
    monitor = NetworkEvents(lambda: worker.request(True))
    loop = glib.MainLoop()
    node = gio.DBusNodeInfo.new_for_xml(INTROSPECTION)
    registration = bus.connection.register_object(OBJECT_PATH, node.interfaces[0], service.method_call, None, None)
    name = gio.bus_own_name_on_connection(bus.connection, BUS_NAME, gio.BusNameOwnerFlags.NONE,
                                         None, lambda *_args: loop.quit())
    subscriptions = [bus.connection.signal_subscribe(destination, 'org.freedesktop.DBus.Properties',
        'PropertiesChanged', None, None, gio.DBusSignalFlags.NONE, lambda *_args: worker.request(True))
        for destination in ('org.freedesktop.NetworkManager', 'org.freedesktop.systemd1')]
    def tick():
        worker.request(False)
        return glib.SOURCE_CONTINUE
    def stop():
        loop.quit()
        return glib.SOURCE_CONTINUE
    sources = [glib.timeout_add_seconds(10, tick),
               glib.unix_signal_add(glib.PRIORITY_DEFAULT, signal.SIGTERM, stop),
               glib.unix_signal_add(glib.PRIORITY_DEFAULT, signal.SIGINT, stop)]
    try:
        monitor.start()
        worker.request(True)
        loop.run()
    finally:
        monitor.close()
        service.close()
        worker.close()
        for subscription in subscriptions:
            bus.connection.signal_unsubscribe(subscription)
        for source in sources:
            glib.source_remove(source)
        bus.connection.unregister_object(registration)
        gio.bus_unown_name(name)
