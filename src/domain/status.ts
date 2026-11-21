import {cleanCliOutput} from './cli-output.js';
import type {VpnStatus} from './types.js';

export function parseStatus(output: string): VpnStatus | null {
    const cleanOutput = cleanCliOutput(output);
    if (/\bdisconnected\b|\bnot connected\b|\bVPN stopped\b/i.test(cleanOutput))
        return {connected: false, subtitle: 'Disconnected'};
    if (/\bVPN active, but status unavailable\b/i.test(cleanOutput))
        return null;
    const location = cleanOutput.match(/^Connected to (.+?)(?: in (?:TUN|SOCKS) mode|$)/im);
    if (location) {
        const name = location[1]!.trim().replace(/\s+/g, ' ');
        if (name === 'FASTEST')
            return {connected: true, subtitle: 'FASTEST', location: null};
        return {connected: true, subtitle: name || 'Connected', location: name};
    }
    return null;
}
