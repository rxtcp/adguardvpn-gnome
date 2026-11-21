import assert from 'node:assert/strict';
import {test} from 'node:test';
import {createEnvironment, plain} from './gnome-environment.mjs';

const listing = 'US  United States  Miami  25 ms\nUS  United States  New York  10 ms\nDE  Germany  Berlin  —';
async function start(options) {
    const environment = await createEnvironment(options);
    environment.commands.push({output: 'Disconnected'}, {output: listing});
    return environment.start();
}

test('initial state, polling interval and complete shutdown', async () => {
    const app = await start();
    assert.equal(app.toggle.checked, false);
    assert.equal(app.indicator.children[0].visible, false);
    assert.equal([...app.timers.values()][0].seconds, 8);
    assert.deepEqual(plain(app.calls.map(call => call.argv.slice(1))), [['status'], ['list-locations']]);
    app.stop();
    assert.equal(app.timers.size, 0);
    assert.equal(app.cancelled, true);
    assert.equal(app.toggle.destroyed, true);
    assert.equal(app.indicator.destroyed, true);
});

for (const [saved, location] of [[undefined, 'US'], ['Miami', 'Miami'], ['{"location":"Berlin","iso":"DE"}', 'Berlin'], ['{bad', 'US']]) {
    test(`toggle connects to saved/default location: ${saved}`, async () => {
        const app = await start({saved});
        await app.click();
        assert.deepEqual(plain(app.calls[2].argv.slice(1)), ['connect', '-l', location]);
        // Selecting the already preferred location does not rewrite preferences.
        if (location === 'US') assert.equal(app.saved, saved);
        else assert.equal(JSON.parse(app.saved).location, location);
    });
}

test('confirmed external status updates indicator, formatted subtitle and saved preference', async () => {
    const app = await start();
    app.commands.push({output: '\x1b[32mConnected to Miami in TUN mode\x1b[0m', success: false});
    await app.refresh();
    assert.equal(app.toggle.checked, true);
    assert.equal(app.toggle.subtitle, 'US -> MIAMI');
    assert.equal(app.indicator.children[0].visible, true);
    assert.deepEqual(JSON.parse(app.saved), {location: 'Miami', iso: 'US'});
});

test('JSON preferences with surrounding location whitespace normalize during menu initialization', async () => {
    const app = await start({saved: '{"location":" Miami ","iso":"US"}'});
    assert.deepEqual(JSON.parse(app.saved), {location: 'Miami', iso: 'US'});
    assert.ok(app.actors.some(actor => actor.text === 'Default: US -> MIAMI'));
    assert.equal(app.toggle.subtitle, 'US -> MIAMI');
});

test('unknown status grace retains confirmed indicator and then reports unavailable', async () => {
    const app = await start();
    app.commands.push({output: 'Connected to Miami'}); await app.refresh();
    app.commands.push({output: 'VPN active, but status unavailable'}); await app.refresh();
    assert.equal(app.toggle.subtitle, 'Checking VPN…');
    assert.equal(app.toggle.checked, true);
    app.advance(12);
    app.commands.push({output: '???'}); await app.refresh();
    assert.equal(app.toggle.subtitle, 'Status unavailable');
    assert.equal(app.indicator.children[0].visible, true);
});

test('protected connection waits for status confirmation and suppresses repeated startup clicks', async () => {
    const app = await start({files: ['/usr/local/bin/adguardvpn-gnome-ctl']});
    app.commands.push({output: 'Connection requested'}, {output: 'Disconnected'});
    await app.click();
    assert.equal(app.saved, undefined);
    assert.equal(app.toggle.subtitle, 'Connecting…');
    const count = app.calls.length; await app.click(); assert.equal(app.calls.length, count);
    app.commands.push({output: 'Connected to Miami in TUN mode'}); await app.refresh();
    assert.deepEqual(JSON.parse(app.saved), {location: 'Miami', iso: 'US'});
    assert.deepEqual(plain(app.calls[2].argv), ['/usr/local/bin/adguardvpn-gnome-ctl', 'connect', '--location', 'US']);
    assert.equal(app.calls[1].argv[0], '/bin/adguardvpn-cli');
});

test('startup grace expires exactly at thirty seconds', async () => {
    const app = await start(); await app.click();
    app.advance(30); await app.refresh();
    assert.equal(app.toggle.subtitle, 'US');
    const count = app.calls.length; await app.click(); assert.ok(app.calls.length > count);
});

test('country navigation sorts cities, keeps back outside scroll, and reconnects in order', async () => {
    const app = await start();
    await app.press('🇺🇸 United States');
    const scroll = app.actors.find(actor => actor.policy);
    assert.equal(scroll.children[0].children[0].child.children[0].text, 'New York — 10 ms');
    assert.equal(scroll.scroll, 0);
    assert.ok(app.toggle.menu.box.children.some(child => child.visible && child.child?.children?.[0]?.text === '← Back to countries'));
    app.commands.push({output: 'Connected to Miami'}); await app.refresh();
    app.commands.push({output: 'Disconnected'}, {output: 'OK'}, {output: 'Connected to New York'});
    await app.press('New York — 10 ms');
    assert.deepEqual(plain(app.calls.slice(-3).map(call => call.argv.slice(1))), [['disconnect'], ['connect', '-l', 'New York'], ['status']]);
    await app.press('← Back to countries');
    app.toggle.menu.emit('open-state-changed', true);
    assert.equal(scroll.scroll, 0);
});

test('selecting current city remembers it without restarting the connection', async () => {
    const app = await start(); app.commands.push({output: 'Connected to Miami'}); await app.refresh();
    await app.press('🇺🇸 United States'); const count = app.calls.length;
    await app.press('Miami — 25 ms'); assert.equal(app.calls.length, count);
});

test('global fastest uses CLI flag and saves the reported successful city', async () => {
    const app = await start();
    app.commands.push({output: 'Successfully Connected to Miami'}, {output: 'Connected to Miami'});
    await app.press('⚡ Connect to fastest server');
    assert.deepEqual(plain(app.calls[2].argv.slice(1)), ['connect', '-f']);
    assert.equal(JSON.parse(app.saved).location, 'Miami');
});

test('country fastest refreshes latency and selects measured minimum', async () => {
    const app = await start();
    app.commands.push({output: listing}, {output: 'OK'}, {output: 'Connected to New York'});
    await app.press('Connect to lowest-ping server in United States');
    assert.deepEqual(plain(app.calls.slice(-3).map(call => call.argv.slice(1))), [['list-locations'], ['connect', '-l', 'New York'], ['status']]);
});

test('country fastest without measurements notifies without connecting', async () => {
    const app = await start(); app.commands.push({output: listing});
    await app.press('Connect to lowest-ping server in Germany');
    assert.match(app.notifications[0][1], /No ping data available for DE/);
    assert.equal(app.calls.filter(call => call.argv.includes('connect')).length, 0);
});

for (const protectedMode of [false, true]) {
    test(`failed connection and disconnect fallback, protected=${protectedMode}`, async () => {
        const app = await start({files: protectedMode ? ['/usr/local/bin/adguardvpn-gnome-ctl'] : [],
            programs: {'adguardvpn-cli': '/bin/adguardvpn-cli', kgx: '/bin/kgx'}});
        app.commands.push({success: false, output: 'denied'}); await app.click();
        assert.match(app.notifications[0][1], protectedMode ? /Protected service: denied/ : /Terminal opened/);
        app.commands.push({output: 'Connected to Miami'}); await app.refresh();
        app.commands.push({success: false, output: 'denied'}); await app.click();
        assert.match(app.notifications[1][1], protectedMode ? /Protected service: denied/ : /Terminal opened/);
        if (!protectedMode) {
            const terminals = app.calls.filter(call => call.flags === 0);
            assert.equal(terminals.length, 2);
            assert.equal(terminals[1].argv.at(-2), 'disconnect');
        }
    });
}

test('a failed disconnect during switching never starts another connection', async () => {
    const app = await start(); app.commands.push({output: 'Connected to Miami'}); await app.refresh();
    await app.press('🇺🇸 United States');
    app.commands.push({success: false}); await app.press('New York — 10 ms');
    assert.equal(app.calls.filter(call => call.argv.includes('connect')).length, 0);
    assert.match(app.notifications[0][1], /Could not disconnect from the previous server/);
});

test('FASTEST status confirms connection without saving a fabricated location', async () => {
    const app = await start(); app.commands.push({output: 'Connected to FASTEST in TUN mode'}); await app.refresh();
    assert.equal(app.toggle.subtitle, 'FASTEST'); assert.equal(app.toggle.checked, true);
    assert.equal(app.saved, undefined);
});

test('missing controller shows a useful state and click notification', async () => {
    const app = await start({programs: {}});
    assert.equal(app.toggle.subtitle, 'AdGuard VPN controller not found');
    await app.click(); assert.match(app.notifications[0][1], /controller not found/);
    assert.equal(app.calls.length, 0);
});

test('disable cancels in-flight work and ignores late completion', async () => {
    const app = await start(); app.commands.push({deferred: true, output: 'Connected to Miami'});
    const refresh = app.refresh(), process = app.processes.at(-1), subtitle = app.toggle.subtitle;
    app.stop(); assert.equal(process.forced, true); process.complete(); await refresh;
    assert.equal(app.toggle.subtitle, subtitle); assert.equal(app.saved, undefined);
    assert.equal(app.cancelHandlerCount, 0);
});

test('status and connection duplicates are suppressed; stale status cannot overwrite an action', async () => {
    const app = await start(); app.commands.push({deferred: true, output: 'Connected to Berlin'});
    const refresh = app.refresh(), status = app.processes.at(-1), count = app.calls.length;
    await app.refresh(); assert.equal(app.calls.length, count);
    app.commands.push({deferred: true}); await app.click();
    const connection = app.processes.at(-1); await app.click();
    assert.equal(app.calls.length, count + 1);
    status.complete(); await refresh; assert.equal(app.toggle.subtitle, 'Connecting…');
    app.stop(); connection.complete(); await app.settle();
});

test('listing failure retains previous servers and allows retry', async () => {
    const app = await start(); app.commands.push({success: false, output: 'offline'});
    await app.press('Refresh server list'); assert.match(app.warnings[0], /offline/);
    await app.press('🇺🇸 United States'); await app.press('← Back to countries');
    app.commands.push({output: 'FR  France  Paris  5 ms'}); await app.press('Refresh server list');
    await app.press('🇫🇷 France');
});

test('status exception is shown unless a connection is still starting', async () => {
    const app = await start(); app.commands.push({spawnError: 'unavailable'}); await app.refresh();
    assert.equal(app.toggle.subtitle, 'Status check failed: unavailable');
    await app.click(); app.commands.push({spawnError: 'unavailable'}); await app.refresh();
    assert.equal(app.toggle.subtitle, 'Connecting…');
});
