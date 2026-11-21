import assert from 'node:assert/strict';
import {test} from 'node:test';
import {createEnvironment, plain} from './gnome-environment.mjs';

async function selection(options = {}) {
    const app = await createEnvironment(options);
    const {LocationSelection} = await app.importModule('application/location-selection.js');
    const changes = [], selected = new LocationSelection(display => changes.push(display));
    return {app, selected, changes};
}

test('country resolution prefers explicit hints, country codes and saved country; ambiguous cities stay unknown', async () => {
    const {selected} = await selection({saved: '{"location":"London","iso":"GB"}'});
    selected.groups = new Map([
        ['GB', {country: 'United Kingdom', cities: [{city: 'London'}, {city: 'Springfield'}]}],
        ['US', {country: 'United States', cities: [{city: 'Springfield'}, {city: 'Miami'}]}],
    ]);
    assert.equal(selected.resolveIso('Miami', 'DE'), 'DE');
    assert.equal(selected.resolveIso(' de '), 'DE');
    assert.equal(selected.resolveIso('london'), 'GB');
    assert.equal(selected.resolveIso('Miami', 'invalid'), 'US');
    assert.equal(selected.resolveIso('Springfield'), null);
    assert.equal(selected.resolveIso('Unknown'), null);
    assert.equal(selected.format('Miami', null), 'US -> MIAMI');
    assert.equal(selected.format('Unknown', null), 'UNKNOWN');
});

test('remember validates, trims, deduplicates and persists only changes', async () => {
    const {app, selected, changes} = await selection();
    selected.remember(''); selected.remember('bad\ncity'); selected.remember('us');
    assert.equal(app.saved, undefined); assert.equal(changes.length, 0);
    selected.remember(' Miami ', 'US');
    assert.deepEqual(plain(selected.preferred), {location: 'Miami', iso: 'US'});
    assert.deepEqual(JSON.parse(app.saved), {location: 'Miami', iso: 'US'});
    assert.deepEqual(changes, ['US -> MIAMI']);
    selected.remember('miami', 'US'); assert.equal(changes.length, 1);
    assert.equal(app.GLib.mkdir.mode, 0o700);
    assert.equal(app.GLib.mkdir.path, '/config/adguardvpn-gnome-toggle');
});

test('unwritable preference still updates session selection and reports diagnostic', async () => {
    const {app, selected, changes} = await selection({saveError: true});
    selected.remember('Miami', 'US');
    assert.equal(selected.preferred.location, 'Miami');
    assert.deepEqual(changes, ['US -> MIAMI']);
    assert.equal(app.saved, undefined); assert.match(app.warnings[0], /cannot save last location: Read-only/);
});

test('city sorting is stable for equal ping, alphabetical for missing measurements, and does not mutate input', async () => {
    const app = await createEnvironment();
    const {sortCities, groupLocations} = await app.importModule('domain/locations.js');
    const cities = [
        {iso: 'US', country: 'USA', city: 'Zulu', ping: null},
        {iso: 'DE', country: 'Germany', city: 'Berlin', ping: 10},
        {iso: 'US', country: 'USA', city: 'Miami', ping: 10},
        {iso: 'US', country: 'USA', city: 'Atlanta', ping: null},
    ];
    const original = structuredClone(cities);
    assert.deepEqual(plain(sortCities(cities)).map(city => city.city), ['Berlin', 'Miami', 'Atlanta', 'Zulu']);
    assert.deepEqual(cities, original);
    const groups = groupLocations(cities);
    assert.deepEqual([...groups.keys()], ['US', 'DE']);
    assert.equal(groups.get('US').cities.length, 3);
});

test('lowest latency keeps first tie, accepts zero, and never crosses country', async () => {
    const app = await createEnvironment(); const {findLowestPing} = await app.importModule('domain/locations.js');
    const cities = [{iso: 'DE', ping: 0}, {iso: 'US', city: 'First', ping: 5},
        {iso: 'US', city: 'Second', ping: 5}, {iso: 'US', ping: null}];
    assert.equal(findLowestPing(cities, 'US').city, 'First');
    cities.push({iso: 'US', city: 'Zero', ping: 0});
    assert.equal(findLowestPing(cities, 'US').city, 'Zero');
});

test('invalid preference shapes and unknown error values are handled at the boundary', async () => {
    const app = await createEnvironment();
    const {parsePreferredLocation} = await app.importModule('domain/preferences.js');
    for (const text of ['', '{"location":7}', '{"location":"Miami","iso":7}', 'a'.repeat(101)]) {
        const preferred = parsePreferredLocation(text);
        assert.equal(preferred.location, text.includes('Miami') ? 'Miami' : 'US');
    }
    const {errorMessage} = await app.importModule('domain/cli-output.js');
    assert.equal(errorMessage('unavailable'), 'unavailable');
    assert.equal(errorMessage({message: 'unavailable'}), 'unavailable');
    assert.equal(errorMessage(null), 'null');
    const {parseStatus} = await app.importModule('domain/status.js');
    assert.deepEqual(plain(parseStatus('Connected to   ')), {connected: true, subtitle: 'Connected', location: ''});
});

test('a country removed during refresh cannot open an obsolete city list', async () => {
    const app = await createEnvironment();
    const {LocationSelection} = await app.importModule('application/location-selection.js');
    const {ServerMenu} = await app.importModule('ui/server-menu.js');
    const selected = new LocationSelection(() => {}), menu = app.createMenu();
    const view = new ServerMenu(menu, new app.Gio.FileIcon(), selected, {});
    view.render([{iso: 'US', country: 'United States', city: 'Miami', ping: 5}]);
    selected.groups.clear();
    await app.press('🇺🇸 United States');
    const title = menu.box.children.find(child => child.label);
    assert.equal(title.label.text, 'Available servers');
});
