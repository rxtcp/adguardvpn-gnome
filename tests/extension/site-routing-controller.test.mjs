import assert from 'node:assert/strict';
import {domainToASCII} from 'node:url';
import {test} from 'node:test';
import {createEnvironment, plain} from './gnome-environment.mjs';

const target = {kind: 'direct', id: 'direct'};
const rule = {id: '00000000-0000-4000-8000-000000000002', domain: 'one.example', target,
    status: 'blocked-offline', detail: 'No physical gateway', ipv4_count: 1, ipv6_count: 1, updated_at: 1000};

async function setup() {
    const app = await createEnvironment();
    const {RoutingController} = await app.importModule('site-routing/controller.js');
    const calls = [], messages = [], busy = [], displayed = {};
    const client = {
        providers: async () => [{target, name: 'Direct', active: false, detail: '', ipv4: false, ipv6: false}],
        rules: async () => [rule], change: async request => { calls.push(plain(request)); },
        diagnose: async () => ({rule, addresses: ['198.51.100.8'], protection: 'Known IPs only', migration: null}),
        cancel() { this.cancelled = true; },
    };
    const view = {
        providers: value => { displayed.providers = value; }, rules: value => { displayed.rules = value; },
        busy: value => busy.push(value), message: text => messages.push(text),
        clearEditor: () => { displayed.cleared = true; }, confirm: async () => true,
        diagnostics: value => { displayed.diagnostics = value; },
    };
    return {controller: new RoutingController(client, view, domainToASCII), client, view, calls, messages, busy, displayed};
}

test('load includes inactive assignable providers, and add sends only a normalized exact host and stable target', async () => {
    const app = await setup(); await app.controller.refresh();
    assert.equal(app.displayed.providers[0].active, false);
    await app.controller.save('https://ONE.Example/path?private=x', target);
    assert.deepEqual(app.calls, [{operation: 'add-rule', domain: 'one.example', target}]);
    assert.equal(app.displayed.cleared, true);
    assert.deepEqual(app.busy, [true, false]);
});

test('invalid hosts are rejected before calling privileged API', async () => {
    const app = await setup(); await app.controller.save('*.example.com', target);
    assert.equal(app.calls.length, 0); assert.ok(app.messages.length > 0);
});

test('remove requires an explicit return-to-system-routing confirmation', async () => {
    const app = await setup(); let confirmation;
    app.view.confirm = async (title, body) => { confirmation = body; return false; };
    await app.controller.remove(rule); assert.equal(app.calls.length, 0);
    assert.match(confirmation, /ordinary system routing/i);
    app.view.confirm = async () => true; await app.controller.remove(rule);
    assert.deepEqual(app.calls, [{operation: 'remove-rule', id: rule.id}]);
});

test('updates keep domain identity and migrations use separate confirmed operations', async () => {
    const app = await setup(); await app.controller.save('one.example', target, rule.id);
    const plan = {id: '00000000-0000-4000-8000-000000000009', stage: 'protected', changes: ['Exact synthetic diff']};
    await app.controller.migrate(rule, plan, 'retire');
    assert.equal(app.calls[1].migration.stage, 'retire');
    assert.equal(app.calls[1].migration.id, plan.id);
    await app.controller.diagnose(rule); assert.equal(app.displayed.diagnostics.rule.id, rule.id);
});

test('closing preferences cancels reads and ignores late completion', async () => {
    const app = await setup(); let complete;
    app.client.rules = () => new Promise(resolve => { complete = resolve; });
    const loading = app.controller.refresh(); app.controller.close(); complete([rule]); await loading;
    assert.equal(app.client.cancelled, true); assert.equal(app.displayed.rules, undefined);
    await app.controller.save('one.example', target); assert.equal(app.calls.length, 0);
});
