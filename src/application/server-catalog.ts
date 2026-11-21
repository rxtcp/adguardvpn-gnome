import * as Main from 'resource:///org/gnome/shell/ui/main.js';
import {errorMessage} from '../domain/cli-output.js';
import {findLowestPing, parseLocations} from '../domain/locations.js';
import type {ServerLocation, ToggleView} from '../domain/types.js';
import type {ConnectionController} from './connection-controller.js';
import type {ConnectionState} from './connection-state.js';
import type {VpnClient} from './vpn-client.js';

export class ServerCatalog {
    private loading = false;

    constructor(private readonly client: VpnClient, private readonly state: ConnectionState,
        private readonly view: ToggleView, private readonly onLocations: (locations: ServerLocation[]) => void,
        private readonly controller: ConnectionController, private readonly refresh: () => Promise<void>) {}

    async load(): Promise<void> {
        if (!this.client.cliPath || this.loading || this.client.cancelled)
            return;
        this.loading = true;
        try {
            const result = await this.client.listLocations(20);
            if (!result.success)
                throw new Error(result.output || 'Could not load server list');
            if (!this.client.cancelled)
                this.onLocations(parseLocations(result.output));
        } catch (error) {
            if (!this.client.cancelled)
                console.warn(`AdGuard VPN: cannot load locations: ${errorMessage(error)}`);
        } finally {
            this.loading = false;
        }
    }

    async connectFastestInCountry(iso: string): Promise<void> {
        const {client, state} = this;
        if (!client.cliPath || state.busy || state.findingFastest || client.cancelled)
            return;
        state.findingFastest = true;
        this.view.subtitle = `Checking ping: ${iso}…`;
        let fastest: ServerLocation | null = null;
        try {
            const result = await client.listLocations(25);
            if (!result.success)
                throw new Error(result.output || 'Could not refresh server latency');
            const locations = parseLocations(result.output);
            fastest = findLowestPing(locations, iso);
            if (!fastest)
                throw new Error(`No ping data available for ${iso}`);
            if (!client.cancelled)
                this.onLocations(locations);
        } catch (error) {
            if (!client.cancelled)
                Main.notify('AdGuard VPN', `Fastest server selection failed: ${errorMessage(error)}`);
        } finally {
            state.findingFastest = false;
        }
        if (client.cancelled)
            return;
        if (fastest)
            await this.controller.connect({kind: 'location', location: fastest.city, iso: fastest.iso});
        else
            void this.refresh();
    }
}
