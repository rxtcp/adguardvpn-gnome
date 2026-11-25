// Unofficial GNOME Shell extension for AdGuard VPN CLI.
import Gio from 'gi://Gio';
import {Extension} from 'resource:///org/gnome/shell/extensions/extension.js';
import * as Main from 'resource:///org/gnome/shell/ui/main.js';
import {AdGuardIndicator} from './ui/indicator.js';

export default class AdGuardVpnQuickToggleExtension extends Extension {
    private indicator: AdGuardIndicator | null = null;

    override enable(): void {
        const file = this.dir.get_child('icons').get_child('planet-symbolic.svg');
        this.indicator = new AdGuardIndicator(new Gio.FileIcon({file}), () => { void this.openPreferences(); });
        Main.panel.statusArea.quickSettings!.addExternalIndicator(this.indicator);
    }

    override disable(): void {
        this.indicator!.destroy();
        this.indicator = null;
    }
}
