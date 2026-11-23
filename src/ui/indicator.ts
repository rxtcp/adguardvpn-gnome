import type Gio from 'gi://Gio';
import GObject from 'gi://GObject';
import {SystemIndicator} from 'resource:///org/gnome/shell/ui/quickSettings.js';
import {AdGuardToggle} from './toggle.js';

export class AdGuardIndicator extends SystemIndicator {
    static { GObject.registerClass(this); }
    private readonly vpnToggle: AdGuardToggle;

    constructor(planetIcon: Gio.Icon, openPreferences: () => void) {
        super();
        const icon = this._addIndicator();
        icon.gicon = planetIcon;
        icon.visible = false;
        this.vpnToggle = new AdGuardToggle(connected => { icon.visible = connected; }, planetIcon, openPreferences);
        this.quickSettingsItems.push(this.vpnToggle);
    }

    override destroy(): void {
        this.vpnToggle.shutdown();
        this.quickSettingsItems.forEach(item => item.destroy());
        super.destroy();
    }
}
