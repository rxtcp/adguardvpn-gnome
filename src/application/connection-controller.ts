import GLib from 'gi://GLib';
import * as Main from 'resource:///org/gnome/shell/ui/main.js';
import {cleanCliOutput, errorMessage} from '../domain/cli-output.js';
import type {ConnectionRequest, ToggleView} from '../domain/types.js';
import {openActionTerminal, type TerminalAction} from '../platform/terminal.js';
import type {ConnectionState} from './connection-state.js';
import type {LocationSelection} from './location-selection.js';
import type {VpnClient} from './vpn-client.js';

export class ConnectionController {
    constructor(private readonly client: VpnClient, private readonly state: ConnectionState,
        private readonly selection: LocationSelection, private readonly view: ToggleView,
        private readonly refresh: () => Promise<void>) {}

    async toggle(): Promise<void> {
        const {client, state, view} = this;
        if (state.busy || state.findingFastest || client.cancelled)
            return;
        view.checked = state.connected;
        if (state.isStarting(GLib.get_monotonic_time()))
            return;
        if (!client.available) {
            Main.notify('AdGuard VPN', 'AdGuard VPN controller not found');
            return;
        }
        if (!state.connected) {
            await this.connect({kind: 'location', location: this.selection.preferred.location});
            return;
        }
        state.busy = true;
        view.reactive = false;
        state.connectionRequestedAt = 0;
        view.subtitle = 'Disconnecting…';
        try {
            const result = await client.runAction(['disconnect'], 25);
            if (!result.success)
                throw new Error(result.output || 'Command failed');
        } catch (error) {
            this.reportFailure(error, 'disconnect');
        } finally {
            this.finishAction();
        }
    }

    async connect(request: ConnectionRequest): Promise<void> {
        const {client, state, view, selection} = this;
        if (state.busy || state.findingFastest || client.cancelled || !client.available)
            return;
        if (request.kind === 'location' && state.connected &&
            state.currentLocation.toLowerCase() === request.location.toLowerCase()) {
            selection.remember(request.location, request.iso);
            return;
        }
        state.busy = true;
        view.reactive = false;
        view.subtitle = 'Connecting…';
        let needsDisconnect = state.connected;
        try {
            if (needsDisconnect) {
                const disconnected = await client.runAction(['disconnect'], 25);
                if (!disconnected.success)
                    throw new Error(disconnected.output || 'Could not disconnect from the previous server');
                needsDisconnect = false;
            }
            const args = request.kind === 'fastest' ? ['connect', '-f'] : ['connect', '-l', request.location];
            const connected = await client.runAction(args, 30);
            if (!connected.success)
                throw new Error(connected.output || 'Could not connect to the server');
            state.connectionRequestedAt = GLib.get_monotonic_time();
            state.statusUnavailableSince = 0;
            if (request.kind === 'fastest') {
                const match = cleanCliOutput(connected.output).match(/^Successfully Connected to\s+(.+?)\s*$/im);
                if (match)
                    selection.remember(match[1]!);
            } else if (!client.controlPath) {
                selection.remember(request.location, request.iso);
            }
        } catch (error) {
            state.connectionRequestedAt = 0;
            const mode = request.kind === 'fastest'
                ? (needsDisconnect ? 'switch-fastest' : 'fastest')
                : (needsDisconnect ? 'switch' : 'connect');
            this.reportFailure(error, mode, request.kind === 'location' ? request.location : '');
        } finally {
            this.finishAction();
        }
    }

    private reportFailure(error: unknown, action: TerminalAction, location = ''): void {
        if (this.client.cancelled)
            return;
        if (this.client.controlPath) {
            Main.notify('AdGuard VPN', `Protected service: ${errorMessage(error)}`);
            return;
        }
        const opened = openActionTerminal(this.client.cliPath!, action, location);
        const disconnecting = action === 'disconnect';
        Main.notify('AdGuard VPN', opened
            ? disconnecting
                ? 'Terminal opened: an administrator password or additional diagnostics may be required.'
                : 'Terminal opened: an administrator password may be required.'
            : `${disconnecting ? 'Command failed' : 'Could not connect'}: ${errorMessage(error)}`);
    }

    private finishAction(): void {
        this.state.busy = false;
        if (!this.client.cancelled) {
            this.view.reactive = true;
            void this.refresh();
        }
    }
}
