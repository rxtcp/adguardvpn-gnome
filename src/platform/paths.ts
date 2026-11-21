import Gio from 'gi://Gio';
import GLib from 'gi://GLib';

export function getCliPath(): string | null {
    const fromPath = GLib.find_program_in_path('adguardvpn-cli');
    if (fromPath)
        return fromPath;
    const installedPath = '/opt/adguardvpn_cli/adguardvpn-cli';
    return Gio.File.new_for_path(installedPath).query_exists(null) ? installedPath : null;
}

export function getProtectedControlPath(): string | null {
    const installedPath = '/usr/local/bin/adguardvpn-gnome-ctl';
    if (Gio.File.new_for_path(installedPath).query_exists(null))
        return installedPath;
    return GLib.find_program_in_path('adguardvpn-gnome-ctl');
}
