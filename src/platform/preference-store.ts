import GLib from 'gi://GLib';
import {parsePreferredLocation} from '../domain/preferences.js';
import type {PreferredLocation} from '../domain/types.js';

function getPreferencePath(): string {
    return GLib.build_filenamev([GLib.get_user_config_dir(), 'adguardvpn-gnome-toggle', 'location']);
}

export function readPreferredLocation(): PreferredLocation {
    try {
        const [, contents] = GLib.file_get_contents(getPreferencePath());
        return parsePreferredLocation(new TextDecoder().decode(contents));
    } catch {
        return parsePreferredLocation('');
    }
}

export function savePreferredLocation(location: string, iso: string | null): void {
    const path = getPreferencePath();
    GLib.mkdir_with_parents(GLib.path_get_dirname(path), 0o700);
    GLib.file_set_contents(path, JSON.stringify({location, iso}));
}
