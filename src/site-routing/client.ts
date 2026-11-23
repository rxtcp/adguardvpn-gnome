import Gio from 'gi://Gio';
import GLib from 'gi://GLib';
import {errorMessage} from '../domain/cli-output.js';
import {parseRoutingResponse} from './domain.js';
import * as response from './responses.js';
import type {RoutingApi, RoutingDiagnostics, RoutingMutation, RoutingRequest, RoutingRule, VpnProvider} from './types.js';

const BUS = 'org.gnome.AdGuardVPN.SiteRouting';
const PATH = '/org/gnome/AdGuardVPN/SiteRouting';

export class RoutingClient implements RoutingApi {
    private readonly cancellable = new Gio.Cancellable();
    private connection: Promise<Gio.DBusConnection> | null = null;

    cancel(): void { this.cancellable.cancel(); }

    private bus(): Promise<Gio.DBusConnection> {
        this.connection ??= new Promise((resolve, reject) => {
            Gio.bus_get(Gio.BusType.SYSTEM, this.cancellable, (_source, result) => {
                try { resolve(Gio.bus_get_finish(result)); }
                catch (error) { reject(error); }
            });
        });
        return this.connection;
    }

    private async request(request: RoutingRequest): Promise<Record<string, unknown>> {
        if (this.cancellable.is_cancelled())
            throw new Error('Cancelled');
        const connection = await this.bus();
        if (this.cancellable.is_cancelled())
            throw new Error('Cancelled');
        return new Promise((resolve, reject) => {
            connection.call(BUS, PATH, BUS, 'Request', new GLib.Variant('(s)', [JSON.stringify(request)]),
                GLib.VariantType.new('(s)'), Gio.DBusCallFlags.NONE, 125000, this.cancellable, (source, result) => {
                    try {
                        const values: unknown = source!.call_finish(result).deepUnpack();
                        if (!Array.isArray(values) || typeof values[0] !== 'string' || values[0].length > 2 * 1024 * 1024)
                            throw new Error('Invalid Site Routing response.');
                        resolve(parseRoutingResponse(values[0]));
                    } catch (error) {
                        const message = errorMessage(error);
                        reject(new Error(/ServiceUnknown|NameHasNoOwner/.test(message)
                            ? 'Site Routing service is unavailable. Install or start the optional system component.' : message));
                    }
                });
        });
    }

    async providers(): Promise<VpnProvider[]> {
        return response.list((await this.request({operation: 'list-providers'})).providers, response.provider, 1024);
    }

    async rules(): Promise<RoutingRule[]> {
        return response.list((await this.request({operation: 'list-rules'})).rules, response.rule);
    }

    async change(request: RoutingMutation): Promise<void> { await this.request(request); }

    async diagnose(id: string): Promise<RoutingDiagnostics> {
        return response.diagnostics(await this.request({operation: 'diagnose-rule', id}));
    }
}
