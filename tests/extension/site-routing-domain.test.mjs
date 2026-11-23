import assert from 'node:assert/strict';
import {domainToASCII} from 'node:url';
import {test} from 'node:test';
import {createEnvironment, plain} from './gnome-environment.mjs';

test('site input normalizes exact URL hosts and IDNA before sending a privileged request', async () => {
    const app = await createEnvironment();
    const {normalizeSiteDomain} = await app.importModule('site-routing/domain.js');
    assert.equal(normalizeSiteDomain(' HTTPS://Packages.Corp.Example:8443/a?q=x#y ', domainToASCII), 'packages.corp.example');
    assert.equal(normalizeSiteDomain('ПРИМЕР.рф', domainToASCII), 'xn--e1afmkfd.xn--p1ai');
    assert.equal(normalizeSiteDomain('faß.example.', domainToASCII), 'xn--fa-hia.example');
    for (const input of ['*.example.com', 'example.com/path', '198.51.100.1', '2001:db8::1',
        'http://user:secret@example.com', 'ftp://example.com', 'https://example.com:99999',
        'bad..example', '-bad.example', 'a'.repeat(64) + '.example', 'example.com;id', 'example.com\n--help'])
        assert.throws(() => normalizeSiteDomain(input, domainToASCII));
});

test('routing protocol validates responses and displays the boundary of IP-based protection', async () => {
    const app = await createEnvironment();
    const {parseRoutingResponse, protectionNotice, statusLabel} = await app.importModule('site-routing/domain.js');
    assert.deepEqual(plain(parseRoutingResponse('{"schema_version":1,"ok":true,"data":{"rules":[]}}')), {rules: []});
    assert.throws(() => parseRoutingResponse('{"schema_version":1,"ok":false,"error":{"message":"DNS failed"}}'), /DNS failed/);
    for (const text of ['{}', '{bad', '{"schema_version":2,"ok":true,"data":{}}'])
        assert.throws(() => parseRoutingResponse(text));
    assert.match(protectionNotice, /known IP/i);
    assert.match(protectionNotice, /DoH/);
    for (const status of ['active', 'blocked-offline', 'resolving', 'dns-error', 'conflict', 'apply-error', 'provider-missing'])
        assert.equal(typeof statusLabel(status), 'string');
});
