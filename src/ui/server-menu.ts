import type Gio from 'gi://Gio';
import St from 'gi://St';
import * as Main from 'resource:///org/gnome/shell/ui/main.js';
import * as PopupMenu from 'resource:///org/gnome/shell/ui/popupMenu.js';
import type {QuickToggleMenu} from 'resource:///org/gnome/shell/ui/quickSettings.js';
import {countryFlag, groupLocations, sortCities} from '../domain/locations.js';
import type {CountryGroup, ServerLocation} from '../domain/types.js';
import type {LocationSelection} from '../application/location-selection.js';
import {createMenuHeader} from './menu-header.js';
import {createServerButton} from './server-button.js';

interface ServerMenuActions {
    connect(location: string, iso: string): void;
    connectFastest(): void;
    connectFastestInCountry(iso: string): void;
    refresh(): void;
}

export class ServerMenu {
    private readonly defaultLabel: St.Label;
    private readonly title = new PopupMenu.PopupSeparatorMenuItem('Available servers');
    private readonly backButton: St.Button;
    private readonly list = new St.BoxLayout({vertical: true});
    private readonly scroll = new St.ScrollView({style_class: 'vfade', overlay_scrollbars: true});

    constructor(private readonly menu: QuickToggleMenu, planetIcon: Gio.Icon,
        private readonly selection: LocationSelection, private readonly actions: ServerMenuActions) {
        const header = createMenuHeader(planetIcon, selection.format());
        this.defaultLabel = header.label;
        menu.box.insert_child_at_index(header.actor, 0);
        const section = new PopupMenu.PopupMenuSection();
        menu.addMenuItem(section);
        section.addAction('⚡ Connect to fastest server', () => actions.connectFastest());
        section.addAction('Refresh server list', () => actions.refresh());
        menu.addMenuItem(this.title);
        this.backButton = createServerButton('← Back to countries', () => this.showCountries());
        this.backButton.hide();
        menu.box.add_child(this.backButton);
        const monitorHeight = Main.layoutManager.primaryMonitor?.height ?? 900;
        const scrollHeight = Math.max(160, Math.min(300, Math.floor(monitorHeight * 0.36)));
        this.scroll.set_policy(St.PolicyType.NEVER, St.PolicyType.AUTOMATIC);
        this.scroll.set_child(this.list);
        this.scroll.set_height(scrollHeight);
        menu.box.add_child(this.scroll);
        menu.connect('open-state-changed', (_menu, open: boolean) => {
            if (open)
                this.showCountries();
            return undefined;
        });
    }

    setDefault(display: string): void {
        this.defaultLabel.text = `Default: ${display}`;
    }

    render(locations: ServerLocation[]): void {
        this.selection.groups = groupLocations(locations);
        this.showCountries();
        this.selection.remember(this.selection.preferred.location, this.selection.preferred.iso);
    }

    private clear(): void {
        for (const child of this.list.get_children())
            child.destroy();
    }

    private resetScroll(): void {
        this.scroll.get_vadjustment().set_value(0);
    }

    private showCountries(): void {
        this.title.label.text = 'Available servers';
        this.backButton.hide();
        this.clear();
        if (this.selection.groups.size === 0)
            this.list.add_child(new St.Label({text: 'No servers loaded — select Refresh server list', style: 'padding: 12px 16px;'}));
        for (const [iso, group] of this.selection.groups)
            this.list.add_child(this.createCountryRow(iso, group));
        this.resetScroll();
    }

    private showCities(iso: string): void {
        const group = this.selection.groups.get(iso);
        if (!group)
            return;
        this.title.label.text = `${countryFlag(iso)} ${group.country}`;
        this.backButton.show();
        this.clear();
        for (const location of sortCities(group.cities)) {
            const pingLabel = location.ping === null ? '' : ` — ${location.ping} ms`;
            this.list.add_child(createServerButton(`${location.city}${pingLabel}`, () => {
                this.menu.close();
                this.actions.connect(location.city, iso);
            }));
        }
        this.resetScroll();
    }

    private createCountryRow(iso: string, group: CountryGroup): St.BoxLayout {
        const row = new St.BoxLayout({x_expand: true, style: 'spacing: 4px;'});
        row.add_child(createServerButton(`${countryFlag(iso)} ${group.country}`, () => this.showCities(iso), true));
        const fastestButton = new St.Button({style_class: 'popup-menu-item', child: new St.Label({text: '⚡'}),
            accessible_name: `Connect to lowest-ping server in ${group.country}`,
            reactive: true, can_focus: true, track_hover: true});
        fastestButton.connect('clicked', () => {
            this.menu.close();
            this.actions.connectFastestInCountry(iso);
        });
        row.add_child(fastestButton);
        return row;
    }
}
