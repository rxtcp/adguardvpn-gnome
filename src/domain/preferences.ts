import type {PreferredLocation} from './types.js';

export const DEFAULT_LOCATION = 'US';

export function isValidLocation(location: unknown): location is string {
    return typeof location === 'string' && location.length > 0 &&
        location.length <= 100 && !/[\x00-\x1f\x7f]/.test(location);
}

export function parsePreferredLocation(saved: string): PreferredLocation {
    const text = saved.trim();
    try {
        if (text.startsWith('{')) {
            const parsed: unknown = JSON.parse(text);
            if (typeof parsed === 'object' && parsed !== null &&
                'location' in parsed && isValidLocation(parsed.location)) {
                const iso = 'iso' in parsed && typeof parsed.iso === 'string' &&
                    /^[A-Z]{2}$/.test(parsed.iso) ? parsed.iso : null;
                return {location: parsed.location, iso};
            }
        } else if (isValidLocation(text)) {
            return {location: text, iso: /^[A-Z]{2}$/.test(text) ? text : null};
        }
    } catch {
        // Missing or malformed preferences use the original country default.
    }
    return {location: DEFAULT_LOCATION, iso: DEFAULT_LOCATION};
}
