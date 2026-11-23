import type {RoutingStatus} from './types.js';

export const protectionNotice = 'Protection applies only to known IP addresses. Shared IPs affect other hosts; ' +
    'application DoH/DoT and unknown cached addresses are outside this guarantee. ' +
    'DNS queries may use the system resolver. A missing target blocks known IPs; VPNs are never started automatically.';

export function normalizeSiteDomain(value: string, toAscii: (host: string) => string | null): string {
    const text = value.trim();
    if (!text || text.length > 8192 || /[\s\\\x00-\x1f\x7f]/.test(text))
        throw new Error('Enter an exact domain or an HTTP(S) URL.');
    let host = text;
    if (text.includes('://')) {
        const match = /^https?:\/\/([^/?#]+)(?:[/?#].*)?$/i.exec(text);
        if (!match || match[1]!.includes('@'))
            throw new Error('Only HTTP(S) URLs without credentials are supported.');
        const authority = match[1]!;
        const parts = authority.split(':');
        if (parts.length > 2 || (parts.length === 2 && (!/^\d+$/.test(parts[1]!) || Number(parts[1]) < 1 || Number(parts[1]) > 65535)))
            throw new Error('Invalid URL port.');
        host = parts[0]!;
    }
    host = host.replace(/\.$/, '');
    if (/[/:?#@*%;\[\]]/.test(host))
        throw new Error('Use an exact hostname, not an IP address or wildcard.');
    const canonical = toAscii(host)?.toLowerCase();
    if (!canonical || canonical.length > 253 || /[^a-z0-9.-]/.test(canonical))
        throw new Error('Invalid exact domain name.');
    const labels = canonical.split('.');
    if (labels.length < 2 || /^\d+$/.test(labels.at(-1)!) || labels.some(label =>
        !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label)))
        throw new Error('Use a fully qualified domain, not an IP address or wildcard.');
    return canonical;
}

export function record(value: unknown): Record<string, unknown> {
    if (typeof value !== 'object' || value === null || Array.isArray(value))
        throw new Error('Invalid Site Routing response.');
    return value as Record<string, unknown>;
}

export function parseRoutingResponse(text: string): Record<string, unknown> {
    const response = record(JSON.parse(text) as unknown);
    if (response.schema_version !== 1 || typeof response.ok !== 'boolean')
        throw new Error('Unsupported Site Routing response.');
    if (!response.ok) {
        const error = record(response.error);
        throw new Error(typeof error.message === 'string' ? error.message : 'Site Routing request failed.');
    }
    return record(response.data);
}

const labels: Record<RoutingStatus, string> = {
    active: 'Active', 'blocked-offline': 'Blocked: target offline', resolving: 'Resolving DNS',
    'dns-error': 'DNS error', conflict: 'IP conflict', 'apply-error': 'Could not safely apply',
    'provider-missing': 'Provider missing',
};
export function statusLabel(status: RoutingStatus): string { return labels[status]; }

export function isRoutingStatus(value: unknown): value is RoutingStatus {
    return typeof value === 'string' && Object.hasOwn(labels, value);
}
