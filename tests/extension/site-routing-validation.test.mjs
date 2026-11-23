import assert from 'node:assert/strict';
import {test} from 'node:test';
import {createEnvironment} from './gnome-environment.mjs';

const id = '00000000-0000-4000-8000-000000000002';
const rule = {id, domain: 'one.example', target: {kind: 'direct', id: 'direct'},
    status: 'active', detail: '', ipv4_count: 1, ipv6_count: 0, updated_at: 1000};

test('typed responses reject every unsafe field class and accept all provider identities', async () => {
    const app = await createEnvironment(); const parse = await app.importModule('domain/site-routing-responses.js');
    for (const target of [{kind: 'adguard', id: 'adguardvpn-gnome'}, {kind: 'networkmanager', id}])
        assert.equal(parse.target(target).id, target.id);
    for (const target of [{kind: 'networkmanager', id: 7}, {kind: 'networkmanager', id: 'invalid'}, {kind: 'unknown', id}, []])
        assert.throws(() => parse.target(target));
    assert.throws(() => parse.list({}, value => value));
    assert.throws(() => parse.list([1, 2], value => value, 1));
    for (const replacement of [{id: 7}, {id: 'invalid'}, {domain: 'x'.repeat(254)}, {detail: 7},
        {ipv4_count: -1}, {ipv6_count: '1'}, {updated_at: Infinity}, {status: 'toString'}])
        assert.throws(() => parse.rule({...rule, ...replacement}));
    assert.throws(() => parse.provider({target: rule.target, name: 'Direct', active: 'yes', detail: '', ipv4: true, ipv6: true}));
    assert.equal(parse.rule(rule).status, 'active');
    assert.equal(parse.diagnostics({rule, addresses: [], routes: [], protection: '', migration: null}).migration, null);
    const diagnosis = {rule, addresses: [], protection: '', migration: null};
    const routes = [{address: '198.51.100.8'}, {address: '198.51.100.8', table: 'main', type: 'unreachable'}];
    assert.equal(parse.diagnostics({...diagnosis, routes}).routes[1].table, 'main');
    for (const replacement of [{dev: 1}, {gateway: {}}, {type: false}, {table: null}, {table: -1}])
        assert.throws(() => parse.diagnostics({...diagnosis, routes: [{address: '198.51.100.8', ...replacement}]}));
});

test('protocol rejects non-object data, invalid boolean/version and malformed errors', async () => {
    const app = await createEnvironment(); const {parseRoutingResponse, normalizeSiteDomain} = await app.importModule('domain/site-routing.js');
    for (const text of ['null', '[]', '{"schema_version":1,"ok":"yes"}', '{"schema_version":1,"ok":true,"data":[]}'])
        assert.throws(() => parseRoutingResponse(text));
    assert.throws(() => parseRoutingResponse('{"schema_version":1,"ok":false,"error":{"message":7}}'), /request failed/);
    assert.throws(() => normalizeSiteDomain('one.example', () => null));
    assert.throws(() => normalizeSiteDomain('one.example', () => 'bad_name.example'));
});
