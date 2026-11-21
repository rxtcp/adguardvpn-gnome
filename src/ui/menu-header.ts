import Clutter from 'gi://Clutter';
import type Gio from 'gi://Gio';
import St from 'gi://St';

export function createMenuHeader(planetIcon: Gio.Icon, display: string): {actor: St.BoxLayout; label: St.Label} {
    const header = new St.BoxLayout({style: 'padding: 12px 14px 10px; spacing: 12px;', x_expand: true});
    const iconBackground = new St.Bin({
        style: 'width: 40px; height: 40px; border-radius: 999px; background-color: #3584e4;',
        x_align: Clutter.ActorAlign.CENTER, y_align: Clutter.ActorAlign.CENTER,
        child: new St.Icon({gicon: planetIcon, icon_size: 20, style: 'color: white;'}),
    });
    const headerText = new St.BoxLayout({vertical: true, y_align: Clutter.ActorAlign.CENTER, style: 'spacing: 2px;'});
    headerText.add_child(new St.Label({text: 'AdGuard VPN', style: 'font-weight: bold; font-size: 15px;'}));
    const label = new St.Label({text: `Default: ${display}`, style: 'font-size: 11px;'});
    headerText.add_child(label);
    header.add_child(iconBackground);
    header.add_child(headerText);
    return {actor: header, label};
}
