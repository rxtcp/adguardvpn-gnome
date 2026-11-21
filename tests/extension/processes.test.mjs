import assert from 'node:assert/strict';
import {test} from 'node:test';
import {createEnvironment, plain} from './gnome-environment.mjs';

test('process combines streams and cleans up timers and cancellation handlers', async () => {
    const app = await createEnvironment({includeFunctions: true});
    app.commands.push({output: 'hello', stderr: 'warning', success: false});
    const result = await app.entry.namespace.runCli('/cli', ['status'], 6, new app.Gio.Cancellable());
    assert.deepEqual(plain(result), {success: false, output: 'hello\nwarning'});
    assert.equal(app.timers.size, 0); assert.equal(app.cancelHandlerCount, 0);
});

for (const error of ['spawnError', 'finishError']) test(`process propagates ${error}`, async () => {
    const app = await createEnvironment({includeFunctions: true}); app.commands.push({[error]: 'broken'});
    await assert.rejects(app.entry.namespace.runCli('/cli', [], 1, new app.Gio.Cancellable()), /broken/);
    assert.equal(app.timers.size, 0); assert.equal(app.cancelHandlerCount, 0);
});

test('process timeout forces exit and rejects after completion', async () => {
    const app = await createEnvironment({includeFunctions: true}); app.commands.push({deferred: true});
    const result = app.entry.namespace.runCli('/cli', [], 1, new app.Gio.Cancellable());
    const [id, timer] = [...app.timers][0]; app.timers.delete(id); assert.equal(timer.callback(), false);
    assert.equal(app.processes[0].forced, true); app.processes[0].complete();
    await assert.rejects(result, /Timeout/); assert.equal(app.cancelHandlerCount, 0);
});

for (const terminal of ['xterm', 'kgx']) test(`terminal ${terminal} uses positional arguments for untrusted city`, async () => {
    const app = await createEnvironment({includeFunctions: true, programs: {[terminal]: `/bin/${terminal}`}});
    const location = 'Miami; $(touch /tmp/no)';
    assert.equal(app.entry.namespace.openActionTerminal('/cli', 'connect', location), true);
    const argv = app.calls[0].argv;
    assert.equal(argv[1], terminal === 'xterm' ? '-e' : '--');
    assert.equal(argv.at(-1), location); assert.ok(!argv[4].includes(location));
});

test('terminal absence and launch errors return false', async () => {
    const absent = await createEnvironment({includeFunctions: true, programs: {}});
    assert.equal(absent.entry.namespace.openActionTerminal('/cli', 'disconnect'), false);
    const broken = await createEnvironment({includeFunctions: true, programs: {kgx: '/bin/kgx'}});
    broken.commands.push({spawnError: 'missing'});
    assert.equal(broken.entry.namespace.openActionTerminal('/cli', 'disconnect'), false);
    assert.match(broken.warnings[0], /missing/);
});
