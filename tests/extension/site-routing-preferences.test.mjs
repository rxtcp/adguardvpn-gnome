import assert from 'node:assert/strict';
import {test} from 'node:test';
import {createEnvironment} from './gnome-environment.mjs';

const target = {kind: 'direct', id: 'direct'};
const provider = {target, name: 'Physical connection', active: false, detail: '', ipv4: false, ipv6: false};
const rule = {id: '00000000-0000-4000-8000-000000000002', domain: 'one.example', target,
    status: 'blocked-offline', detail: 'No verified path', ipv4_count: 1, ipv6_count: 1, updated_at: 1000};

async function preferences(rules = []) {
    const app = await createEnvironment();
    app.dbusResponses.push({data: {providers: [provider]}}, {data: {rules}});
    const {default: Preferences} = await app.importModule('prefs.js');
    const window = new app.Adw.PreferencesWindow();
    await new Preferences().fillPreferencesWindow(window); await app.settle();
    return {app, window};
}

test('standard preferences normalize an entire exact host, add a rule asynchronously and clean up on close', async () => {
    const {app, window} = await preferences();
    const entry = app.actors.find(actor => actor.title === 'URL or exact domain');
    entry.set_text('https://ONE.Example/private/path');
    assert.ok(app.actors.some(actor => actor.subtitle === 'Entire host: one.example'));
    app.dbusResponses.push({data: {}}, {data: {providers: [provider]}}, {data: {rules: [rule]}});
    await app.press('Add');
    assert.equal(app.dbusCalls[2].request.domain, 'one.example');
    assert.ok(app.actors.some(actor => actor.subtitle?.includes?.('IPv4: 1') && actor.subtitle.includes('IPv6: 1')));
    assert.ok(app.actors.some(actor => actor.description?.includes?.('known IP')));
    window.emit('close-request'); assert.equal(app.timers.size, 0);
});

test('removal dialog explains fallback and cancellation leaves the rule intact', async () => {
    const {app, window} = await preferences([rule]); const count = app.dbusCalls.length;
    await app.press('Remove rule for one.example');
    const dialog = app.actors.find(actor => !actor.destroyed && actor.responses?.has('confirm'));
    assert.match(dialog.body, /ordinary system routing/);
    dialog.emit('response', 'cancel'); await app.settle();
    assert.equal(app.dbusCalls.length, count);
    window.emit('close-request');
});

test('check displays known addresses and the exact migration diff without executing migration automatically', async () => {
    const {app, window} = await preferences([rule]);
    app.dbusResponses.push({data: {rule, addresses: ['198.51.100.8'], protection: 'Known IPs only',
        migration: {id: '00000000-0000-4000-8000-000000000009', stage: 'preview', changes: ['Fixture VPN: remove exact 198.51.100.8/32']}}},
        {data: {providers: [provider]}}, {data: {rules: [rule]}});
    await app.press('Check rule for one.example');
    const dialog = app.actors.find(actor => !actor.destroyed && actor.responses?.has('protect'));
    assert.ok(dialog);
    assert.ok(app.actors.some(actor => actor.text?.includes?.('198.51.100.8/32')));
    assert.equal(app.dbusCalls.filter(call => call.request.operation === 'update-rule').length, 0);
    dialog.emit('response', 'close'); window.emit('close-request');
});

test('Quick Settings opens the standard preferences process', async () => {
    const app = await createEnvironment(); await app.start();
    await app.press('Site Routing…'); assert.equal(app.preferencesOpened, 1); app.stop();
});
