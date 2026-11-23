import type Adw from 'gi://Adw';
import {ExtensionPreferences} from 'resource:///org/gnome/Shell/Extensions/js/extensions/prefs.js';
import {SiteRoutingPage} from './ui/site-routing/page.js';

export default class AdGuardVpnPreferences extends ExtensionPreferences {
    override async fillPreferencesWindow(window: Adw.PreferencesWindow): Promise<void> {
        new SiteRoutingPage(window);
    }
}
