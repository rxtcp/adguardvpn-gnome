import assert from 'node:assert/strict';
import {test} from 'node:test';
import {createEnvironment, plain} from './gnome-environment.mjs';

async function functions() { return (await createEnvironment({includeFunctions: true})).entry.namespace; }

test('terminal escapes and carriage returns are removed', async () => {
    const {cleanCliOutput} = await functions();
    assert.equal(cleanCliOutput('\x1b]0;title\x07\x1b[32mMiami\x1b[0m\r\n'), 'Miami\n');
});

test('location parser handles real columns, duplicates and missing/decimal latency', async () => {
    const {parseLocations, findLowestPing} = await functions();
    const locations = parseLocations('ISO  Country  City  Ping\nUS  United States  New York  10,5 ms\nUS\tUnited States\tMiami\t20.5\nUS  United States  Miami  1 ms\nDE  Germany  Berlin  N/A\nxx bad\nFR  France\nCA  Canada  Toronto  0 MS');
    assert.deepEqual(plain(locations), [
        {iso: 'US', country: 'United States', city: 'New York', ping: 10.5},
        {iso: 'US', country: 'United States', city: 'Miami', ping: 20.5},
        {iso: 'DE', country: 'Germany', city: 'Berlin', ping: null},
        {iso: 'CA', country: 'Canada', city: 'Toronto', ping: 0},
    ]);
    assert.equal(findLowestPing(locations, 'US').city, 'New York');
    assert.equal(findLowestPing(locations, 'DE'), null);
    assert.equal(findLowestPing([], 'FR'), null);
});

test('status parser recognizes only explicit status and normalizes spaces', async () => {
    const {parseStatus} = await functions();
    for (const text of ['Disconnected', 'Not connected', 'VPN stopped'])
        assert.deepEqual(plain(parseStatus(text)), {connected: false, subtitle: 'Disconnected'});
    assert.deepEqual(plain(parseStatus('Connected to New   York in SOCKS mode')), {connected: true, subtitle: 'New York', location: 'New York'});
    assert.deepEqual(plain(parseStatus('Connected to FASTEST')), {connected: true, subtitle: 'FASTEST', location: null});
    assert.equal(parseStatus('VPN active, but status unavailable'), null);
    assert.equal(parseStatus('waiting'), null);
});

test('location validation boundaries and flags', async () => {
    const {isValidLocation, countryFlag} = await functions();
    for (const location of ['', 'a'.repeat(101), 'Miami\n', '\x7f', null, 5]) assert.equal(isValidLocation(location), false);
    for (const location of ['São Paulo', 'a'.repeat(100), 'New York']) assert.equal(isValidLocation(location), true);
    assert.equal(countryFlag('US'), '🇺🇸'); assert.equal(countryFlag('us'), '🌍');
});

for (const [saved, expected] of [
    [undefined, {location: 'US', iso: 'US'}], ['  Miami\n', {location: 'Miami', iso: null}],
    ['DE', {location: 'DE', iso: 'DE'}], ['{"location":"Miami","iso":"us"}', {location: 'Miami', iso: null}],
    ['{"location":""}', {location: 'US', iso: 'US'}], ['{broken', {location: 'US', iso: 'US'}],
]) test(`preference compatibility: ${saved}`, async () => {
    const app = await createEnvironment({saved, includeFunctions: true});
    assert.deepEqual(plain(app.entry.namespace.readPreferredLocation()), expected);
});
