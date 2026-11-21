import assert from 'node:assert/strict';
import {test} from 'node:test';
import {createEnvironment} from './gnome-environment.mjs';

const listing = 'US  United States  Miami  10 ms\nDE  Germany  Berlin  —';
async function start(options) {
    const app = await createEnvironment(options);
    app.commands.push({output: 'Disconnected'}, {output: listing});
    return app.start();
}

test('poll timer refreshes status and remains scheduled until shutdown', async () => {
    const app = await start(); const poll = [...app.timers.values()][0];
    app.commands.push({output: 'Connected to Miami'});
    assert.equal(poll.callback(), true); await app.settle(); assert.equal(app.toggle.checked, true);
    app.stop(); const count = app.calls.length; await app.refresh(); assert.equal(app.calls.length, count);
});

test('disconnect success clears indicator after confirmed status', async () => {
    const app = await start(); app.commands.push({output: 'Connected to Miami'}); await app.refresh();
    app.commands.push({output: 'Disconnected'}, {output: 'Disconnected'}); await app.click();
    assert.equal(app.toggle.checked, false); assert.equal(app.indicator.children[0].visible, false);
    assert.equal(app.toggle.reactive, true); assert.equal(app.toggle.subtitle, 'US -> MIAMI');
});

for (const [options, height] of [[{height: 300}, 160], [{height: 500}, 180], [{height: 2000}, 300], [{noMonitor: true}, 300]]) {
    test(`server scroll adapts to monitor ${JSON.stringify(options)}`, async () => {
        const app = await start(options); assert.equal(app.actors.find(actor => actor.policy).height, height);
        await app.press('🇩🇪 Germany'); await app.press('Berlin');
        assert.ok(app.calls.some(call => call.argv.at(-1) === 'Berlin'));
    });
}

test('duplicate listing is suppressed, and cancellation ignores late list results', async () => {
    const app = await start(); app.commands.push({deferred: true, output: listing});
    await app.press('Refresh server list'); const count = app.calls.length;
    await app.press('Refresh server list'); assert.equal(app.calls.length, count);
    app.stop(); app.processes.at(-1).complete(); await app.settle();
    assert.equal(app.warnings.length, 0); await app.press('Refresh server list'); assert.equal(app.calls.length, count);
});

test('country latency lookup excludes toggle, status and duplicate lookup until completion', async () => {
    const app = await start(); app.commands.push({deferred: true, output: listing});
    await app.press('Connect to lowest-ping server in United States');
    const count = app.calls.length; assert.equal(app.toggle.subtitle, 'Checking ping: US…');
    await app.click(); await app.refresh(); await app.press('Connect to lowest-ping server in Germany');
    await app.press('⚡ Connect to fastest server'); assert.equal(app.calls.length, count);
    app.stop(); app.processes.at(-1).complete(); await app.settle();
    assert.equal(app.calls.length, count); assert.equal(app.notifications.length, 0);
});

test('country latency lookup reports CLI errors and permits retry', async () => {
    const app = await start(); app.commands.push({success: false});
    await app.press('Connect to lowest-ping server in United States');
    assert.match(app.notifications[0][1], /Could not refresh server latency/);
    app.commands.push({success: false, output: 'offline'});
    await app.press('Connect to lowest-ping server in United States');
    assert.match(app.notifications[1][1], /offline/);
});

test('listing error without output uses default diagnostic', async () => {
    const app = await start(); app.commands.push({success: false}); await app.press('Refresh server list');
    assert.match(app.warnings[0], /Could not load server list/);
});

test('protected global fastest translates arguments and waits for a confirmed city', async () => {
    const app = await start({files: ['/usr/local/bin/adguardvpn-gnome-ctl']});
    app.commands.push({output: 'Connection requested'}, {output: 'VPN active, but status unavailable'});
    await app.press('⚡ Connect to fastest server');
    assert.deepEqual(Array.from(app.calls[2].argv.slice(1)), ['connect', '--fastest']);
    assert.equal(app.saved, undefined); assert.equal(app.toggle.subtitle, 'Connecting…');
});

test('protected city selection preserves the previous default until that city is confirmed', async () => {
    const previous = '{"location":"Miami","iso":"US"}';
    const app = await start({saved: previous, files: ['/usr/local/bin/adguardvpn-gnome-ctl']});
    app.commands.push({output: 'US  United States  New York  5 ms'});
    await app.press('Refresh server list'); await app.press('🇺🇸 United States');
    app.commands.push({output: 'Connection requested'}, {output: 'VPN active, but status unavailable'});
    await app.press('New York — 5 ms');
    assert.equal(app.saved, previous);
    assert.ok(app.actors.some(actor => actor.text === 'Default: US -> MIAMI'));
    app.commands.push({output: 'Connected to New York in TUN mode'}); await app.refresh();
    assert.deepEqual(JSON.parse(app.saved), {location: 'New York', iso: 'US'});
    assert.ok(app.actors.some(actor => actor.text === 'Default: US -> NEW YORK'));
});

for (const fastest of [false, true]) test(`switch fallback tracks whether disconnection succeeded, fastest=${fastest}`, async () => {
    for (const disconnected of [false, true]) {
        const app = await start({programs: {'adguardvpn-cli': '/cli', kgx: '/kgx'}});
        app.commands.push({output: 'Connected to Miami'}); await app.refresh();
        await app.press('🇺🇸 United States');
        app.commands.push({success: disconnected}); if (disconnected) app.commands.push({success: false});
        if (fastest) await app.press('⚡ Connect to fastest server');
        else {
            // Select another city after refreshing the catalog.
            app.commands.unshift({output: 'US  United States  New York  5 ms'});
            await app.press('Refresh server list'); await app.press('🇺🇸 United States');
            await app.press('New York — 5 ms');
        }
        const terminal = app.calls.find(call => call.flags === 0);
        assert.equal(terminal.argv.at(-2), fastest
            ? (disconnected ? 'fastest' : 'switch-fastest') : (disconnected ? 'connect' : 'switch'));
    }
});

test('direct disconnect with no terminal reports default command failure', async () => {
    const app = await start(); app.commands.push({output: 'Connected to Miami'}); await app.refresh();
    app.commands.push({success: false}); await app.click();
    assert.equal(app.notifications[0][1], 'Command failed: Command failed');
});

test('late action failure after shutdown neither notifies nor changes UI', async () => {
    const app = await start(); app.commands.push({deferred: true, success: false});
    await app.click(); app.stop(); app.processes.at(-1).complete(); await app.settle();
    assert.equal(app.notifications.length, 0); assert.equal(app.toggle.reactive, false);
});
