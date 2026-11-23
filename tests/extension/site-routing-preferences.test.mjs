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
        routes: [{address: '198.51.100.8', dev: 'fixturevpn', table: 40000, gateway: '192.0.2.1', type: 'unicast'}],
        migration: {id: '00000000-0000-4000-8000-000000000009', stage: 'preview', changes: ['Fixture VPN: remove exact 198.51.100.8/32']}}},
        {data: {providers: [provider]}}, {data: {rules: [rule]}});
    await app.press('Check rule for one.example');
    const dialog = app.actors.find(actor => !actor.destroyed && actor.responses?.has('protect'));
    assert.ok(dialog);
    assert.ok(app.actors.some(actor => actor.text?.includes?.('198.51.100.8/32')));
    assert.ok(app.actors.some(actor => actor.text?.includes?.('fixturevpn') && actor.text.includes('40000')));
    assert.equal(app.dbusCalls.filter(call => call.request.operation === 'update-rule').length, 0);
    dialog.emit('response', 'close'); window.emit('close-request');
});

test('Quick Settings opens the standard preferences process', async () => {
    const app = await createEnvironment(); await app.start();
    await app.press('Site Routing…'); assert.equal(app.preferencesOpened, 1); app.stop();
});

test('editing preserves the host and stable provider selection through rename and removal', async () => {
    const {app, window} = await preferences([rule]);
    const entry = app.actors.find(actor => actor.title === 'URL or exact domain');
    const selection = app.actors.find(actor => actor.title === 'Target connection');
    await app.press('Edit rule for one.example');
    assert.equal(entry.get_text(), rule.domain);
    assert.equal(entry.sensitive, false);
    assert.equal(selection.get_selected(), 0);
    app.dbusResponses.push({data: {providers: [{...provider, name: 'Renamed connection', active: true}]}}, {data: {rules: [rule]}});
    [...app.timers.values()].find(timer => timer.seconds === 5).callback(); await app.settle();
    assert.equal(selection.get_selected(), 0);
    app.dbusResponses.push({data: {}}, {data: {providers: [provider]}}, {data: {rules: [rule]}});
    await app.press('Save');
    assert.equal(app.dbusCalls.find(call => call.request.operation === 'update-rule').request.id, rule.id);
    assert.equal(entry.get_text(), '');
    await app.press('Edit rule for one.example');
    await app.press('Cancel edit');
    assert.equal(entry.sensitive, true);
    entry.set_text('*.example'); entry.emit('notify::text');
    assert.ok(app.actors.some(actor => actor.subtitle?.includes?.('exact')));
    app.dbusResponses.push({data: {providers: []}}, {data: {rules: [{...rule, updated_at: 0}]}});
    [...app.timers.values()].find(timer => timer.seconds === 5).callback(); await app.settle();
    assert.ok(app.actors.some(actor => actor.subtitle?.includes?.('Not updated') && actor.subtitle.includes('direct: direct')));
    await app.press('Edit rule for one.example');
    assert.equal(selection.get_selected(), app.Gtk.INVALID_LIST_POSITION);
    app.dbusResponses.push({data: {providers: [provider]}}, {data: {rules: [rule]}});
    [...app.timers.values()].find(timer => timer.seconds === 5).callback(); await app.settle();
    assert.equal(selection.get_selected(), app.Gtk.INVALID_LIST_POSITION);
    const calls = app.dbusCalls.length;
    await app.press('Save');
    assert.equal(app.dbusCalls.length, calls);
    assert.ok(app.actors.some(actor => actor.subtitle?.includes?.('Choose an available provider')));
    window.emit('close-request'); window.emit('close-request');
});

test('diagnostic migration actions each require a complete diff confirmation before mutation', async () => {
    const {app, window} = await preferences([rule]);
    const {confirm, showDiagnostics} = await app.importModule('ui/site-routing/dialogs.js');
    const longDiff = 'exact fixture route removal\n'.repeat(50);
    const promise = confirm(window, 'Review', longDiff);
    const longDialog = app.actors.findLast(actor => actor.responses?.has('confirm'));
    assert.match(longDialog.body, /complete details/);
    assert.ok(app.actors.some(actor => actor.text === longDiff));
    longDialog.emit('response', 'confirm'); assert.equal(await promise, true);
    const stages = ['preview', 'protected', 'failed', 'retiring', 'retired', 'rolled-back'];
    const actions = [];
    for (const stage of stages) {
        const migration = {id: rule.id, stage, changes: ['exact fixture /32 route']};
        showDiagnostics(window, {rule, addresses: [], routes: [], protection: 'Known IPs', migration}, (plan, action) => actions.push([plan.id, action]));
        const dialog = app.actors.findLast(actor => actor.responses?.has('close'));
        assert.equal(dialog.responses.has('protect'), stage === 'preview');
        assert.equal(dialog.responses.has('retire'), ['protected', 'failed', 'retiring'].includes(stage));
        assert.equal(dialog.responses.has('rollback'), !['preview', 'rolled-back'].includes(stage));
        dialog.emit('response', stage === 'preview' ? 'protect' : stage === 'protected' ? 'retire' : stage === 'failed' ? 'rollback' : 'close');
    }
    assert.deepEqual(actions, [[rule.id, 'protect'], [rule.id, 'retire'], [rule.id, 'rollback']]);
    showDiagnostics(window, {rule, addresses: [], routes: [], protection: 'Known IPs', migration: null}, () => assert.fail('no migration'));
    const empty = app.actors.findLast(actor => actor.responses?.has('close'));
    empty.emit('response', 'close');
    assert.ok(app.actors.some(actor => actor.text?.includes?.('No eligible legacy')));

    app.dbusResponses.push({data: {rule, addresses: [], routes: [], protection: 'Known IPs',
        migration: {id: rule.id, stage: 'preview', changes: ['exact fixture route']}}},
        {data: {providers: [provider]}}, {data: {rules: [rule]}});
    await app.press('Check rule for one.example');
    app.actors.findLast(actor => !actor.destroyed && actor.responses?.has('protect')).emit('response', 'protect');
    await app.settle();
    app.dbusResponses.push({data: {}}, {data: {providers: [provider]}}, {data: {rules: [rule]}});
    app.actors.findLast(actor => !actor.destroyed && actor.responses?.has('confirm')).emit('response', 'confirm');
    await app.settle();
    assert.equal(app.dbusCalls.find(call => call.request.migration)?.request.migration.stage, 'protect');
    window.emit('close-request');
});
