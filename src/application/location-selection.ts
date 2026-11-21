import {errorMessage} from '../domain/cli-output.js';
import {isValidLocation} from '../domain/preferences.js';
import type {LocationGroups, PreferredLocation} from '../domain/types.js';
import {readPreferredLocation, savePreferredLocation} from '../platform/preference-store.js';

export class LocationSelection {
    preferred: PreferredLocation = readPreferredLocation();
    groups: LocationGroups = new Map();

    constructor(private readonly onChanged: (display: string) => void) {}

    resolveIso(location: string, hint: string | null = null): string | null {
        if (hint && /^[A-Z]{2}$/.test(hint))
            return hint;
        const normalized = location.trim().toUpperCase();
        if (/^[A-Z]{2}$/.test(normalized))
            return normalized;
        if (normalized === this.preferred.location.toUpperCase() && this.preferred.iso)
            return this.preferred.iso;
        let country: string | null = null;
        for (const [iso, group] of this.groups) {
            if (group.cities.some(city => city.city.toUpperCase() === normalized)) {
                if (country && country !== iso)
                    return null;
                country = iso;
            }
        }
        return country;
    }

    format(location = this.preferred.location, hint: string | null = this.preferred.iso): string {
        const name = location.trim().toUpperCase();
        const iso = this.resolveIso(location, hint);
        return iso && name !== iso ? `${iso} -> ${name}` : name;
    }

    remember(location: string, isoHint: string | null = null): void {
        const name = location.trim();
        if (!isValidLocation(name))
            return;
        const iso = this.resolveIso(name, isoHint);
        if (name.toLowerCase() === this.preferred.location.toLowerCase() && iso === this.preferred.iso)
            return;
        this.preferred = {location: name, iso};
        this.onChanged(this.format(name, iso));
        try {
            savePreferredLocation(name, iso);
        } catch (error) {
            console.warn(`AdGuard VPN: cannot save last location: ${errorMessage(error)}`);
        }
    }
}
