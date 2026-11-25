import assert from 'node:assert/strict';
import {test} from 'node:test';
import {createEnvironment, plain} from './gnome-environment.mjs';

test('preferences client uses asynchronous structured system D-Bus and validates protocol versions', async () => {
    const app = await createEnvironment(); const {RoutingClient} = await app.importModule('platform/routing-client.js');
    const client = new RoutingClient();
    app.dbusResponses.push({data: {providers: [{target: {kind: 'direct', id: 'direct'}, name: 'Direct',
        active: false, detail: '', ipv4: false, ipv6: false}]}});
    assert.equal((await client.providers())[0].active, false);
    assert.equal(app.dbusCalls[0].destination, 'org.gnome.AdGuardVPN.SiteRouting');
    assert.deepEqual(plain(app.dbusCalls[0].request), {operation: 'list-providers'});
    app.dbusResponses.push({raw: '{"schema_version":2,"ok":true,"data":{"rules":[]}}'});
    await assert.rejects(client.rules(), /Unsupported/);
});

test('invalid response statuses cannot be displayed as active, and service absence is explicit', async () => {
    const app = await createEnvironment(); const {RoutingClient} = await app.importModule('platform/routing-client.js');
    const client = new RoutingClient();
    app.dbusResponses.push({data: {rules: [{status: 'everything-is-safe'}]}});
    await assert.rejects(client.rules());
    app.dbusResponses.push({error: 'org.freedesktop.DBus.Error.ServiceUnknown'});
    await assert.rejects(client.providers(), /Site Routing service is unavailable/);
});

test('closing client cancels a pending call and prevents future calls', async () => {
    const app = await createEnvironment(); const {RoutingClient} = await app.importModule('platform/routing-client.js');
    const client = new RoutingClient(); app.dbusResponses.push({deferred: true, data: {rules: []}});
    const pending = client.rules(); await app.settle(); client.cancel(); app.dbusPending[0]();
    await assert.rejects(pending, /Cancelled/);
    const count = app.dbusCalls.length; await assert.rejects(client.rules(), /Cancelled/);
    assert.equal(app.dbusCalls.length, count);
});

test('system bus failure and cancellation before connection produce no privileged method call', async () => {
    const broken = await createEnvironment({busError: 'No system bus'});
    const {RoutingClient: BrokenClient} = await broken.importModule('platform/routing-client.js');
    await assert.rejects(new BrokenClient().providers(), /No system bus/);
    const app = await createEnvironment({busDeferred: true}); const {RoutingClient} = await app.importModule('platform/routing-client.js');
    const client = new RoutingClient(); const result = client.rules();
    client.cancel(); app.dbusBusPending[0](); await assert.rejects(result, /Cancelled/);
    assert.equal(app.dbusCalls.length, 0);
});

test('malformed D-Bus return types and oversized responses are rejected', async () => {
    const app = await createEnvironment(); const {RoutingClient} = await app.importModule('platform/routing-client.js');
    const client = new RoutingClient();
    for (const response of [{values: 7}, {values: []}, {values: [42]}, {raw: 'x'.repeat(2 * 1024 * 1024 + 1)}]) {
        app.dbusResponses.push(response); await assert.rejects(client.rules(), /Invalid Site Routing response/);
    }
});
