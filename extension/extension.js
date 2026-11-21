// Unofficial GNOME Shell extension for AdGuard VPN CLI.
// GNOME Extensions (EGO) publication requires separate review and maintenance.

import Clutter from 'gi://Clutter';
import Gio from 'gi://Gio';
import GLib from 'gi://GLib';
import GObject from 'gi://GObject';
import St from 'gi://St';

import {Extension} from 'resource:///org/gnome/shell/extensions/extension.js';
import * as Main from 'resource:///org/gnome/shell/ui/main.js';
import * as PopupMenu from 'resource:///org/gnome/shell/ui/popupMenu.js';
import * as QuickSettings from 'resource:///org/gnome/shell/ui/quickSettings.js';

const STATUS_INTERVAL_SECONDS = 8;
const CONNECTING_GRACE_SECONDS = 30;
const STATUS_CHECK_GRACE_SECONDS = 12;
const DEFAULT_LOCATION = 'US';

function cleanCliOutput(output) {
    return output
        .replace(/\u001b\][^\u0007]*(?:\u0007|\u001b\\)/g, '')
        .replace(/\u001b\[[0-?]*[ -/]*[@-~]/g, '')
        .replace(/\r/g, '');
}

function getPreferencePath() {
    return GLib.build_filenamev([
        GLib.get_user_config_dir(), 'adguardvpn-gnome-toggle', 'location',
    ]);
}

function isValidLocation(location) {
    return typeof location === 'string' && location.length > 0 &&
        location.length <= 100 && !/[\x00-\x1f\x7f]/.test(location);
}

function readPreferredLocation() {
    try {
        const [, contents] = GLib.file_get_contents(getPreferencePath());
        const saved = new TextDecoder().decode(contents).trim();

        // Earlier versions saved only the city name; continue to read them.
        if (saved.startsWith('{')) {
            const parsed = JSON.parse(saved);
            if (isValidLocation(parsed.location)) {
                return {
                    location: parsed.location,
                    iso: /^[A-Z]{2}$/.test(parsed.iso) ? parsed.iso : null,
                };
            }
        } else if (isValidLocation(saved)) {
            return {location: saved, iso: /^[A-Z]{2}$/.test(saved) ? saved : null};
        }
    } catch (error) {
        // No saved preference yet.
    }

    return {location: DEFAULT_LOCATION, iso: DEFAULT_LOCATION};
}

function savePreferredLocation(location, iso) {
    const directory = GLib.path_get_dirname(getPreferencePath());
    GLib.mkdir_with_parents(directory, 0o700);
    GLib.file_set_contents(getPreferencePath(), JSON.stringify({location, iso}));
}

function parseLocations(output) {
    const seen = new Set();
    const locations = [];

    for (const line of cleanCliOutput(output).split('\n')) {
        const columns = line.trim().split(/\s{2,}|\t+/);
        if (columns.length < 3 || !/^[A-Z]{2}$/.test(columns[0]))
            continue;

        const [iso, country, city] = columns;
        if (!country || !city)
            continue;

        const key = `${iso}:${city}`;
        if (seen.has(key))
            continue;

        const pingText = columns.slice(3).join(' ').trim();
        const pingMatch = pingText.match(/(?:^|\s)(\d+(?:[.,]\d+)?)\s*ms\b/i) ??
            pingText.match(/^(\d+(?:[.,]\d+)?)$/);
        const ping = pingMatch ? Number(pingMatch[1].replace(',', '.')) : null;

        seen.add(key);
        locations.push({iso, country, city, ping: Number.isFinite(ping) ? ping : null});
    }

    return locations;
}

function findLowestPing(locations, iso) {
    return locations.reduce((best, location) => {
        if (location.iso !== iso || location.ping === null)
            return best;
        return !best || location.ping < best.ping ? location : best;
    }, null);
}

function countryFlag(iso) {
    if (!/^[A-Z]{2}$/.test(iso))
        return '🌍';

    return String.fromCodePoint(...[...iso].map(letter => letter.charCodeAt(0) + 127397));
}

function getCliPath() {
    const fromPath = GLib.find_program_in_path('adguardvpn-cli');
    if (fromPath)
        return fromPath;

    const installedPath = '/opt/adguardvpn_cli/adguardvpn-cli';
    if (Gio.File.new_for_path(installedPath).query_exists(null))
        return installedPath;

    return null;
}

function getProtectedControlPath() {
    // The optional root-owned helper uses a dedicated AdGuard profile.
    // Only connect/disconnect/status use it; server listing stays unprivileged.
    const installedPath = '/usr/local/bin/adguardvpn-gnome-ctl';
    if (Gio.File.new_for_path(installedPath).query_exists(null))
        return installedPath;
    return GLib.find_program_in_path('adguardvpn-gnome-ctl');
}

function runCli(cliPath, args, timeoutSeconds, cancellable) {
    return new Promise((resolve, reject) => {
        let process;

        try {
            process = Gio.Subprocess.new(
                [cliPath, ...args],
                Gio.SubprocessFlags.STDOUT_PIPE | Gio.SubprocessFlags.STDERR_PIPE
            );
        } catch (error) {
            reject(error);
            return;
        }

        let timedOut = false;
        let timeoutId = GLib.timeout_add_seconds(
            GLib.PRIORITY_DEFAULT,
            timeoutSeconds,
            () => {
                timeoutId = 0;
                timedOut = true;
                process.force_exit();
                return GLib.SOURCE_REMOVE;
            }
        );

        const cancelId = cancellable.connect(() => process.force_exit());

        process.communicate_utf8_async(null, null, (source, result) => {
            if (timeoutId)
                GLib.Source.remove(timeoutId);
            cancellable.disconnect(cancelId);

            try {
                const [, stdout, stderr] = source.communicate_utf8_finish(result);
                if (cancellable.is_cancelled()) {
                    reject(new Error('Cancelled'));
                } else if (timedOut) {
                    reject(new Error('Timeout'));
                } else {
                    resolve({
                        success: source.get_successful(),
                        output: `${stdout ?? ''}\n${stderr ?? ''}`.trim(),
                    });
                }
            } catch (error) {
                reject(error);
            }
        });
    });
}

function parseStatus(output) {
    const cleanOutput = cleanCliOutput(output);

    if (/\bdisconnected\b|\bnot connected\b|\bVPN stopped\b/i.test(cleanOutput))
        return {connected: false, subtitle: 'Disconnected'};

    if (/\bVPN active, but status unavailable\b/i.test(cleanOutput))
        return null;

    const location = cleanOutput.match(/^Connected to (.+?)(?: in (?:TUN|SOCKS) mode|$)/im);
    if (location) {
        const name = location[1].trim().replace(/\s+/g, ' ');
        if (name === 'FASTEST')
            return {connected: true, subtitle: 'FASTEST', location: null};
        return {connected: true, subtitle: name || 'Connected', location: name};
    }

    return null;
}

function openActionTerminal(cliPath, action, location = '') {
    const terminal = ['ptyxis', 'kgx', 'gnome-terminal', 'konsole', 'xterm']
        .map(name => GLib.find_program_in_path(name))
        .find(path => path !== null);

    if (!terminal)
        return false;

    const script = [
        'case "$2" in',
        '  connect) "$1" connect -l "$3" ;;',
        '  switch) "$1" disconnect && "$1" connect -l "$3" ;;',
        '  fastest) "$1" connect -f ;;',
        '  switch-fastest) "$1" disconnect && "$1" connect -f ;;',
        '  disconnect) "$1" disconnect ;;',
        '  *) exit 2 ;;',
        'esac',
        'result=$?',
        'if [ "$result" -ne 0 ]; then',
        '  printf "\\nAdGuard VPN error. Press Enter to close this window..."',
        '  read -r _',
        'fi',
    ].join('\n');

    const prefix = terminal.endsWith('/xterm') ? ['-e'] : ['--'];
    const argv = [terminal, ...prefix, 'bash', '-c', script, 'adguardvpn', cliPath, action, location];

    try {
        Gio.Subprocess.new(argv, Gio.SubprocessFlags.NONE);
        return true;
    } catch (error) {
        console.error(`AdGuard VPN: cannot open terminal: ${error.message}`);
        return false;
    }
}

const AdGuardToggle = GObject.registerClass(
class AdGuardToggle extends QuickSettings.QuickMenuToggle {
    constructor(onConnectedChanged, planetIcon) {
        super({
            title: 'AdGuard VPN',
            subtitle: 'Checking status…',
            gicon: planetIcon,
            toggleMode: true,
        });

        this._cliPath = getCliPath();
        this._controlPath = getProtectedControlPath();
        this._cancellable = new Gio.Cancellable();
        this._onConnectedChanged = onConnectedChanged;
        this._connected = false;
        this._currentLocation = '';
        this._busy = false;
        this._checking = false;
        this._connectionRequestedAt = 0;
        this._statusUnavailableSince = 0;
        this._loadingLocations = false;
        this._findingFastest = false;
        const preferred = readPreferredLocation();
        this._preferredLocation = preferred.location;
        this._preferredIso = preferred.iso;
        this._locationGroups = new Map();

        // The standard menu header accepts only an icon name, whereas the
        // toggle's planet is a Gio.FileIcon. Build a matching header with that
        // same icon so the two views remain visually consistent.
        const header = new St.BoxLayout({
            style: 'padding: 12px 14px 10px; spacing: 12px;',
            x_expand: true,
        });
        const iconBackground = new St.Bin({
            style: 'width: 40px; height: 40px; border-radius: 999px; background-color: #3584e4;',
            x_align: Clutter.ActorAlign.CENTER,
            y_align: Clutter.ActorAlign.CENTER,
            child: new St.Icon({
                gicon: planetIcon,
                icon_size: 20,
                style: 'color: white;',
            }),
        });
        const headerText = new St.BoxLayout({
            vertical: true,
            y_align: Clutter.ActorAlign.CENTER,
            style: 'spacing: 2px;',
        });
        headerText.add_child(new St.Label({
            text: 'AdGuard VPN',
            style: 'font-weight: bold; font-size: 15px;',
        }));
        this._defaultLocationLabel = new St.Label({
            text: `Default: ${this._formatLocation(this._preferredLocation, this._preferredIso)}`,
            style: 'font-size: 11px;',
        });
        headerText.add_child(this._defaultLocationLabel);
        header.add_child(iconBackground);
        header.add_child(headerText);
        this.menu.box.insert_child_at_index(header, 0);

        this._locationsSection = new PopupMenu.PopupMenuSection();
        this.menu.addMenuItem(this._locationsSection);
        this._locationsSection.addAction('⚡ Connect to fastest server', () => {
            this._connectToLocation(null, null, true);
        });
        this._locationsSection.addAction('Refresh server list', () => this._loadLocations());
        this._serversTitle = new PopupMenu.PopupSeparatorMenuItem('Available servers');
        this.menu.addMenuItem(this._serversTitle);
        this._backButton = this._createServerButton('← Back to countries', () => this._showCountries());
        this._backButton.hide();
        this.menu.box.add_child(this._backButton);
        this._serversList = new St.BoxLayout({vertical: true});

        const monitorHeight = Main.layoutManager.primaryMonitor?.height ?? 900;
        const scrollHeight = Math.max(160, Math.min(300, Math.floor(monitorHeight * 0.36)));
        this._serversScrollView = new St.ScrollView({
            style_class: 'vfade',
            overlay_scrollbars: true,
        });
        this._serversScrollView.set_policy(St.PolicyType.NEVER, St.PolicyType.AUTOMATIC);
        this._serversScrollView.set_child(this._serversList);
        this._serversScrollView.set_height(scrollHeight);
        this.menu.box.add_child(this._serversScrollView);
        this._renderLocations([]);

        this.menu.connect('open-state-changed', (_menu, open) => {
            if (open)
                this._showCountries();
        });

        this.connect('clicked', () => this._onClicked());

        this._timerId = GLib.timeout_add_seconds(
            GLib.PRIORITY_DEFAULT,
            STATUS_INTERVAL_SECONDS,
            () => {
                this.refresh();
                return GLib.SOURCE_CONTINUE;
            }
        );

        this.refresh();
        this._loadLocations();
    }

    _createServerButton(text, callback, showArrow = false) {
        const row = new St.BoxLayout({
            x_expand: true,
            style: 'spacing: 8px;',
        });
        row.add_child(new St.Label({
            text,
            x_expand: true,
            y_align: Clutter.ActorAlign.CENTER,
        }));
        if (showArrow) {
            row.add_child(new St.Icon({
                icon_name: 'go-next-symbolic',
                icon_size: 12,
                y_align: Clutter.ActorAlign.CENTER,
            }));
        }
        const button = new St.Button({
            style_class: 'popup-menu-item',
            child: row,
            x_expand: true,
            reactive: true,
            can_focus: true,
            track_hover: true,
        });
        button.connect('clicked', callback);
        return button;
    }

    _createCountryRow(iso, group) {
        const row = new St.BoxLayout({
            x_expand: true,
            style: 'spacing: 4px;',
        });
        row.add_child(this._createServerButton(
            `${countryFlag(iso)} ${group.country}`,
            () => this._showCities(iso),
            true
        ));
        const fastestButton = new St.Button({
            style_class: 'popup-menu-item',
            child: new St.Label({text: '⚡'}),
            accessible_name: `Connect to lowest-ping server in ${group.country}`,
            reactive: true,
            can_focus: true,
            track_hover: true,
        });
        fastestButton.connect('clicked', () => {
            this.menu.close();
            this._connectFastestInCountry(iso);
        });
        row.add_child(fastestButton);
        return row;
    }

    _clearServerList() {
        for (const child of this._serversList.get_children())
            child.destroy();
    }

    _resetServerScroll() {
        this._serversScrollView.get_vadjustment().set_value(0);
    }

    _showCountries() {
        this._serversTitle.label.text = 'Available servers';
        this._backButton.hide();
        this._clearServerList();

        if (this._locationGroups.size === 0) {
            this._serversList.add_child(new St.Label({
                text: 'No servers loaded — select Refresh server list',
                style: 'padding: 12px 16px;',
            }));
        }

        for (const [iso, group] of this._locationGroups) {
            this._serversList.add_child(this._createCountryRow(iso, group));
        }
        this._resetServerScroll();
    }

    _showCities(iso) {
        const group = this._locationGroups.get(iso);
        if (!group)
            return;

        this._serversTitle.label.text = `${countryFlag(iso)} ${group.country}`;
        this._backButton.show();
        this._clearServerList();
        const cities = [...group.cities].sort((a, b) => {
            const aPing = a.ping ?? Infinity;
            const bPing = b.ping ?? Infinity;
            return aPing === bPing ? a.city.localeCompare(b.city) : aPing - bPing;
        });
        for (const location of cities) {
            const pingLabel = location.ping === null ? '' : ` — ${location.ping} ms`;
            this._serversList.add_child(this._createServerButton(`${location.city}${pingLabel}`, () => {
                this.menu.close();
                this._chooseLocation(location.city, iso);
            }));
        }
        this._resetServerScroll();
    }

    _renderLocations(locations) {
        const groups = new Map();
        for (const location of locations) {
            if (!groups.has(location.iso))
                groups.set(location.iso, {country: location.country, cities: []});
            groups.get(location.iso).cities.push(location);
        }
        this._locationGroups = groups;
        this._showCountries();
        this._rememberLocation(this._preferredLocation, this._preferredIso);
    }

    async _loadLocations() {
        if (!this._cliPath || this._loadingLocations || this._cancellable.is_cancelled())
            return;

        this._loadingLocations = true;
        try {
            const result = await runCli(this._cliPath, ['list-locations'], 20, this._cancellable);
            if (!result.success)
                throw new Error(result.output || 'Could not load server list');
            if (!this._cancellable.is_cancelled())
                this._renderLocations(parseLocations(result.output));
        } catch (error) {
            if (!this._cancellable.is_cancelled())
                console.warn(`AdGuard VPN: cannot load locations: ${error.message}`);
        } finally {
            this._loadingLocations = false;
        }
    }

    _runAction(args, timeoutSeconds) {
        if (!this._controlPath)
            return runCli(this._cliPath, args, timeoutSeconds, this._cancellable);

        if (args[0] === 'connect' && args[1] === '-f')
            return runCli(this._controlPath, ['connect', '--fastest'], timeoutSeconds, this._cancellable);
        if (args[0] === 'connect' && args[1] === '-l' && isValidLocation(args[2]))
            return runCli(this._controlPath, ['connect', '--location', args[2]], timeoutSeconds, this._cancellable);
        if (args.length === 1 && ['disconnect', 'status'].includes(args[0]))
            return runCli(this._controlPath, args, timeoutSeconds, this._cancellable);

        return Promise.reject(new Error('Unsupported protected helper operation'));
    }

    async _connectFastestInCountry(iso) {
        if (!this._cliPath || this._busy || this._findingFastest || this._cancellable.is_cancelled())
            return;

        this._findingFastest = true;
        this.subtitle = `Checking ping: ${iso}…`;
        let fastest = null;

        try {
            const result = await runCli(this._cliPath, ['list-locations'], 25, this._cancellable);
            if (!result.success)
                throw new Error(result.output || 'Could not refresh server latency');

            const locations = parseLocations(result.output);
            fastest = findLowestPing(locations, iso);
            if (!fastest)
                throw new Error(`No ping data available for ${iso}`);

            if (!this._cancellable.is_cancelled())
                this._renderLocations(locations);
        } catch (error) {
            if (!this._cancellable.is_cancelled())
                Main.notify('AdGuard VPN', `Fastest server selection failed: ${error.message}`);
        } finally {
            this._findingFastest = false;
        }

        if (this._cancellable.is_cancelled())
            return;

        if (fastest)
            await this._connectToLocation(fastest.city, fastest.iso);
        else
            this.refresh();
    }

    _chooseLocation(location, iso) {
        this._connectToLocation(location, iso);
    }

    _resolveLocationIso(location, hint = null) {
        if (hint && /^[A-Z]{2}$/.test(hint))
            return hint;

        const normalized = location.trim().toUpperCase();
        if (/^[A-Z]{2}$/.test(normalized))
            return normalized;
        if (normalized === this._preferredLocation.toUpperCase() && this._preferredIso)
            return this._preferredIso;

        let country = null;
        for (const [iso, group] of this._locationGroups) {
            if (group.cities.some(city => city.city.toUpperCase() === normalized)) {
                if (country && country !== iso)
                    return null;
                country = iso;
            }
        }
        return country;
    }

    _formatLocation(location, hint = null) {
        const name = location.trim().toUpperCase();
        const iso = this._resolveLocationIso(location, hint);
        return iso && name !== iso ? `${iso} -> ${name}` : name;
    }

    _rememberLocation(location, isoHint = null) {
        const name = location.trim();
        if (!isValidLocation(name))
            return;

        const iso = this._resolveLocationIso(name, isoHint);
        if (name.toLowerCase() === this._preferredLocation.toLowerCase() &&
            iso === this._preferredIso)
            return;

        this._preferredLocation = name;
        this._preferredIso = iso;
        const display = this._formatLocation(name, iso);
        this._defaultLocationLabel.text = `Default: ${display}`;
        if (!this._connected && !this._busy)
            this.subtitle = display;
        try {
            savePreferredLocation(name, iso);
        } catch (error) {
            console.warn(`AdGuard VPN: cannot save last location: ${error.message}`);
        }
    }

    async refresh() {
        if (this._busy || this._checking || this._findingFastest || this._cancellable.is_cancelled())
            return;

        if (!this._controlPath && !this._cliPath) {
            this.subtitle = 'AdGuard VPN controller not found';
            this.checked = false;
            this._onConnectedChanged(false);
            return;
        }

        this._checking = true;
        try {
            const result = await this._runAction(['status'], 6);
            if (this._cancellable.is_cancelled() || this._busy || this._findingFastest)
                return;

            const status = parseStatus(result.output);
            const now = GLib.get_monotonic_time();
            const recentlyRequested = this._connectionRequestedAt > 0 &&
                now - this._connectionRequestedAt < CONNECTING_GRACE_SECONDS * 1000000;
            if (status) {
                this._statusUnavailableSince = 0;
                this._connected = status.connected;
                this._currentLocation = status.connected ? status.subtitle : '';
                if (status.connected) {
                    this._connectionRequestedAt = 0;
                    if (status.location)
                        this._rememberLocation(status.location);
                } else if (!recentlyRequested) {
                    this._connectionRequestedAt = 0;
                }
                this.checked = status.connected;
                this.subtitle = status.connected
                    ? (status.location
                        ? this._formatLocation(status.location, this._preferredIso)
                        : status.subtitle)
                    : (recentlyRequested ? 'Connecting…'
                        : this._formatLocation(this._preferredLocation, this._preferredIso));
                this._onConnectedChanged(status.connected);
            } else {
                if (this._statusUnavailableSince === 0)
                    this._statusUnavailableSince = now;
                this.subtitle = recentlyRequested ? 'Connecting…'
                    : now - this._statusUnavailableSince < STATUS_CHECK_GRACE_SECONDS * 1000000
                        ? 'Checking VPN…' : 'Status unavailable';
            }
        } catch (error) {
            if (!this._cancellable.is_cancelled()) {
                const recentlyRequested = this._connectionRequestedAt > 0 &&
                    GLib.get_monotonic_time() - this._connectionRequestedAt <
                    CONNECTING_GRACE_SECONDS * 1000000;
                this.subtitle = recentlyRequested ? 'Connecting…'
                    : `Status check failed: ${error.message}`;
            }
        } finally {
            this._checking = false;
        }
    }

    async _onClicked() {
        if (this._busy || this._findingFastest || this._cancellable.is_cancelled())
            return;

        // A second click during systemd startup must not restart the same VPN.
        if (this._connectionRequestedAt > 0 &&
            GLib.get_monotonic_time() - this._connectionRequestedAt <
            CONNECTING_GRACE_SECONDS * 1000000) {
            this.checked = this._connected;
            return;
        }

        this.checked = this._connected;
        if (!this._controlPath && !this._cliPath) {
            Main.notify('AdGuard VPN', 'AdGuard VPN controller not found');
            return;
        }

        if (!this._connected) {
            await this._connectToLocation(this._preferredLocation);
            return;
        }

        this._busy = true;
        this.reactive = false;
        this._connectionRequestedAt = 0;
        this.subtitle = 'Disconnecting…';

        try {
            const result = await this._runAction(['disconnect'], 25);
            if (!result.success)
                throw new Error(result.output || 'Command failed');
        } catch (error) {
            if (!this._cancellable.is_cancelled()) {
                if (this._controlPath) {
                    Main.notify('AdGuard VPN', `Protected service: ${error.message}`);
                } else {
                    const opened = openActionTerminal(this._cliPath, 'disconnect');
                    Main.notify('AdGuard VPN', opened
                        ? 'Terminal opened: an administrator password or additional diagnostics may be required.'
                        : `Command failed: ${error.message}`);
                }
            }
        } finally {
            this._busy = false;
            if (!this._cancellable.is_cancelled()) {
                this.reactive = true;
                this.refresh();
            }
        }
    }

    async _connectToLocation(location, iso = null, fastest = false) {
        if (this._busy || this._findingFastest || this._cancellable.is_cancelled() ||
            (!this._controlPath && !this._cliPath))
            return;

        if (!fastest && this._connected && this._currentLocation.toLowerCase() === location.toLowerCase()) {
            this._rememberLocation(location, iso);
            return;
        }

        this._busy = true;
        this.reactive = false;
        this.subtitle = 'Connecting…';
        let needsDisconnect = this._connected;

        try {
            if (needsDisconnect) {
                const disconnected = await this._runAction(['disconnect'], 25);
                if (!disconnected.success)
                    throw new Error(disconnected.output || 'Could not disconnect from the previous server');
                needsDisconnect = false;
            }

            const args = fastest ? ['connect', '-f'] : ['connect', '-l', location];
            const connected = await this._runAction(args, 30);
            if (!connected.success)
                throw new Error(connected.output || 'Could not connect to the server');
            this._connectionRequestedAt = GLib.get_monotonic_time();
            this._statusUnavailableSince = 0;
            if (fastest) {
                const match = cleanCliOutput(connected.output).match(/^Successfully Connected to\s+(.+?)\s*$/im);
                if (match)
                    this._rememberLocation(match[1]);
            } else if (!this._controlPath) {
                this._rememberLocation(location, iso);
            }
        } catch (error) {
            this._connectionRequestedAt = 0;
            if (!this._cancellable.is_cancelled()) {
                const mode = fastest
                    ? (needsDisconnect ? 'switch-fastest' : 'fastest')
                    : (needsDisconnect ? 'switch' : 'connect');
                if (this._controlPath) {
                    Main.notify('AdGuard VPN', `Protected service: ${error.message}`);
                } else {
                    const opened = openActionTerminal(this._cliPath, mode, location ?? '');
                    Main.notify('AdGuard VPN', opened
                        ? 'Terminal opened: an administrator password may be required.'
                        : `Could not connect: ${error.message}`);
                }
            }
        } finally {
            this._busy = false;
            if (!this._cancellable.is_cancelled()) {
                this.reactive = true;
                this.refresh();
            }
        }
    }

    shutdown() {
        if (this._timerId) {
            GLib.Source.remove(this._timerId);
            this._timerId = 0;
        }
        this._cancellable.cancel();
    }
});

const AdGuardIndicator = GObject.registerClass(
class AdGuardIndicator extends QuickSettings.SystemIndicator {
    constructor(planetIcon) {
        super();
        this._icon = this._addIndicator();
        this._icon.gicon = planetIcon;
        this._icon.visible = false;
        this._toggle = new AdGuardToggle(connected => {
            this._icon.visible = connected;
        }, planetIcon);
        this.quickSettingsItems.push(this._toggle);
    }

    destroy() {
        this._toggle.shutdown();
        this.quickSettingsItems.forEach(item => item.destroy());
        super.destroy();
    }
});

export default class AdGuardVpnQuickToggleExtension extends Extension {
    enable() {
        const planetFile = this.dir.get_child('icons').get_child('planet-symbolic.svg');
        const planetIcon = new Gio.FileIcon({file: planetFile});
        this._indicator = new AdGuardIndicator(planetIcon);
        Main.panel.statusArea.quickSettings.addExternalIndicator(this._indicator);
    }

    disable() {
        this._indicator.destroy();
        this._indicator = null;
    }
}
