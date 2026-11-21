import {cleanCliOutput} from './cli-output.js';
import type {LocationGroups, ServerLocation} from './types.js';

export function parseLocations(output: string): ServerLocation[] {
    const seen = new Set<string>();
    const locations: ServerLocation[] = [];
    for (const line of cleanCliOutput(output).split('\n')) {
        const columns = line.trim().split(/\s{2,}|\t+/);
        const [iso, country, city] = columns;
        if (!iso || !/^[A-Z]{2}$/.test(iso) || !country || !city)
            continue;
        const key = `${iso}:${city}`;
        if (seen.has(key))
            continue;
        const pingText = columns.slice(3).join(' ').trim();
        const pingMatch = pingText.match(/(?:^|\s)(\d+(?:[.,]\d+)?)\s*ms\b/i) ??
            pingText.match(/^(\d+(?:[.,]\d+)?)$/);
        const ping = pingMatch ? Number(pingMatch[1]!.replace(',', '.')) : null;
        seen.add(key);
        locations.push({iso, country, city, ping: Number.isFinite(ping) ? ping : null});
    }
    return locations;
}

export function findLowestPing(locations: readonly ServerLocation[], iso: string): ServerLocation | null {
    return locations.reduce<ServerLocation | null>((best, location) => {
        if (location.iso !== iso || location.ping === null)
            return best;
        return !best || location.ping < best.ping! ? location : best;
    }, null);
}

export function groupLocations(locations: readonly ServerLocation[]): LocationGroups {
    const groups: LocationGroups = new Map();
    for (const location of locations) {
        let group = groups.get(location.iso);
        if (!group) {
            group = {country: location.country, cities: []};
            groups.set(location.iso, group);
        }
        group.cities.push(location);
    }
    return groups;
}

export function sortCities(locations: readonly ServerLocation[]): ServerLocation[] {
    return [...locations].sort((first, second) => {
        const firstPing = first.ping ?? Infinity, secondPing = second.ping ?? Infinity;
        return firstPing === secondPing ? first.city.localeCompare(second.city) : firstPing - secondPing;
    });
}

export function countryFlag(iso: string): string {
    if (!/^[A-Z]{2}$/.test(iso))
        return '🌍';
    return String.fromCodePoint(...[...iso].map(letter => letter.charCodeAt(0) + 127397));
}
