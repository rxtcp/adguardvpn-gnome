import assert from 'node:assert/strict';
import {test} from 'node:test';
import {createEnvironment, plain} from './gnome-environment.mjs';

test('path discovery respects CLI PATH and protected installed path precedence', async () => {
    const app = await createEnvironment({programs: {'adguardvpn-cli': '/custom/cli', 'adguardvpn-gnome-ctl': '/custom/control'},
        files: ['/opt/adguardvpn_cli/adguardvpn-cli', '/usr/local/bin/adguardvpn-gnome-ctl']});
    const {VpnClient} = await app.importModule('application/vpn-client.js'); const client = new VpnClient();
    assert.equal(client.cliPath, '/custom/cli');
    assert.equal(client.controlPath, '/usr/local/bin/adguardvpn-gnome-ctl');
    assert.equal(client.available, true);
});

test('path discovery falls back to installed CLI and PATH controller', async () => {
    const app = await createEnvironment({programs: {'adguardvpn-gnome-ctl': '/custom/control'},
        files: ['/opt/adguardvpn_cli/adguardvpn-cli']});
    const {VpnClient} = await app.importModule('application/vpn-client.js'); const client = new VpnClient();
    assert.equal(client.cliPath, '/opt/adguardvpn_cli/adguardvpn-cli'); assert.equal(client.controlPath, '/custom/control');
});

test('protected allowlist translates connection arguments and rejects unsupported commands before spawning', async () => {
    const app = await createEnvironment({files: ['/usr/local/bin/adguardvpn-gnome-ctl']});
    const {VpnClient} = await app.importModule('application/vpn-client.js'); const client = new VpnClient();
    for (const args of [['connect', '-f'], ['connect', '-l', 'New York'], ['disconnect'], ['status']])
        await client.runAction(args, 3);
    assert.deepEqual(plain(app.calls.map(call => call.argv.slice(1))), [
        ['connect', '--fastest'], ['connect', '--location', 'New York'], ['disconnect'], ['status'],
    ]);
    for (const args of [[], ['list-locations'], ['connect', '-l', ''], ['connect', '-l', 'bad\ncity'], ['status', '--debug']])
        await assert.rejects(client.runAction(args, 3), /Unsupported protected helper operation/);
    assert.equal(app.calls.length, 4);
    await client.listLocations(20);
    assert.equal(app.calls.at(-1).argv[0], '/bin/adguardvpn-cli');
});

test('cancellation forces exit, rejects and releases all resources', async () => {
    const app = await createEnvironment(); const {VpnClient} = await app.importModule('application/vpn-client.js');
    const client = new VpnClient(); app.commands.push({deferred: true});
    const operation = client.runAction(['status'], 6);
    client.cancel(); assert.equal(client.cancelled, true); assert.equal(app.processes[0].forced, true);
    app.processes[0].complete(); await assert.rejects(operation, /Cancelled/);
    assert.equal(app.timers.size, 0); assert.equal(app.cancelHandlerCount, 0);
});
