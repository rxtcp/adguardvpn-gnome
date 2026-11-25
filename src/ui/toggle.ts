import type Gio from 'gi://Gio';
import GObject from 'gi://GObject';
import {QuickMenuToggle} from 'resource:///org/gnome/shell/ui/quickSettings.js';
import {ConnectionController} from '../application/connection-controller.js';
import {ConnectionState} from '../application/connection-state.js';
import {LocationSelection} from '../application/location-selection.js';
import {ServerCatalog} from '../application/server-catalog.js';
import {StatusMonitor} from '../application/status-monitor.js';
import {VpnClient} from '../application/vpn-client.js';
import {ServerMenu} from './server-menu.js';

export class AdGuardToggle extends QuickMenuToggle {
    static { GObject.registerClass(this); }
    private readonly client = new VpnClient();
    private readonly state = new ConnectionState();
    private readonly monitor: StatusMonitor;

    constructor(onConnectedChanged: (connected: boolean) => void, planetIcon: Gio.Icon, openPreferences: () => void) {
        super({title: 'AdGuard VPN', subtitle: 'Checking status…', gicon: planetIcon, toggleMode: true});
        const selection = new LocationSelection(display => {
            serverMenu.setDefault(display);
            if (!this.state.connected && !this.state.busy)
                this.subtitle = display;
        });
        this.monitor = new StatusMonitor(this.client, this.state, selection, this, onConnectedChanged);
        const controller = new ConnectionController(this.client, this.state, selection, this, () => this.refresh());
        const catalog = new ServerCatalog(this.client, this.state, this, locations => serverMenu.render(locations),
            controller, () => this.refresh());
        const serverMenu = new ServerMenu(this.menu, planetIcon, selection, {
            connect: (location, iso) => { void controller.connect({kind: 'location', location, iso}); },
            connectFastest: () => { void controller.connect({kind: 'fastest'}); },
            connectFastestInCountry: iso => { void catalog.connectFastestInCountry(iso); },
            refresh: () => { void catalog.load(); },
            openPreferences,
        });
        // Normalize saved preferences only after the header can receive updates.
        serverMenu.render([]);
        this.connect('clicked', () => { void controller.toggle(); });
        this.monitor.start();
        void catalog.load();
    }

    refresh(): Promise<void> { return this.monitor.refresh(); }

    shutdown(): void {
        this.monitor.stop();
        this.client.cancel();
    }
}
