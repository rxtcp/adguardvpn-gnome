import GLib from 'gi://GLib';
import {errorMessage} from '../domain/cli-output.js';
import {parseStatus} from '../domain/status.js';
import type {ToggleView} from '../domain/types.js';
import type {ConnectionState} from './connection-state.js';
import type {LocationSelection} from './location-selection.js';
import type {VpnClient} from './vpn-client.js';

const STATUS_INTERVAL_SECONDS = 8;
const STATUS_CHECK_GRACE_SECONDS = 12;

export class StatusMonitor {
    private checking = false;
    private timerId = 0;

    constructor(private readonly client: VpnClient, private readonly state: ConnectionState,
        private readonly selection: LocationSelection, private readonly view: ToggleView,
        private readonly onConnectedChanged: (connected: boolean) => void) {}

    start(): void {
        this.timerId = GLib.timeout_add_seconds(GLib.PRIORITY_DEFAULT, STATUS_INTERVAL_SECONDS, () => {
            void this.refresh();
            return GLib.SOURCE_CONTINUE;
        });
        void this.refresh();
    }

    stop(): void {
        if (this.timerId) {
            GLib.Source.remove(this.timerId);
            this.timerId = 0;
        }
    }

    async refresh(): Promise<void> {
        const {client, state, view, selection} = this;
        if (state.busy || this.checking || state.findingFastest || client.cancelled)
            return;
        if (!client.available) {
            view.subtitle = 'AdGuard VPN controller not found';
            view.checked = false;
            this.onConnectedChanged(false);
            return;
        }
        this.checking = true;
        try {
            const result = await client.runAction(['status'], 6);
            if (client.cancelled || state.busy || state.findingFastest)
                return;
            const status = parseStatus(result.output);
            const now = GLib.get_monotonic_time(), recentlyRequested = state.isStarting(now);
            if (status) {
                state.statusUnavailableSince = 0;
                state.connected = status.connected;
                state.currentLocation = status.connected ? status.subtitle : '';
                if (status.connected) {
                    state.connectionRequestedAt = 0;
                    if (status.location)
                        selection.remember(status.location);
                } else if (!recentlyRequested) {
                    state.connectionRequestedAt = 0;
                }
                view.checked = status.connected;
                view.subtitle = status.connected
                    ? (status.location ? selection.format(status.location) : status.subtitle)
                    : (recentlyRequested ? 'Connecting…' : selection.format());
                this.onConnectedChanged(status.connected);
            } else {
                if (state.statusUnavailableSince === 0)
                    state.statusUnavailableSince = now;
                view.subtitle = recentlyRequested ? 'Connecting…'
                    : now - state.statusUnavailableSince < STATUS_CHECK_GRACE_SECONDS * 1_000_000
                        ? 'Checking VPN…' : 'Status unavailable';
            }
        } catch (error) {
            if (!client.cancelled)
                view.subtitle = state.isStarting(GLib.get_monotonic_time()) ? 'Connecting…'
                    : `Status check failed: ${errorMessage(error)}`;
        } finally {
            this.checking = false;
        }
    }
}
