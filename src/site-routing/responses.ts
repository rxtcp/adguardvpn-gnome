import {isRoutingStatus, record} from './domain.js';
import type {MigrationPlan, RoutingDiagnostics, RoutingRule, RoutingTarget, VpnProvider} from './types.js';

function text(value: unknown, maximum = 4096): string {
    if (typeof value !== 'string' || value.length > maximum)
        throw new Error('Invalid Site Routing text field.');
    return value;
}

function count(value: unknown): number {
    if (typeof value !== 'number' || !Number.isFinite(value) || value < 0)
        throw new Error('Invalid Site Routing numeric field.');
    return value;
}

function boolean(value: unknown): boolean {
    if (typeof value !== 'boolean')
        throw new Error('Invalid Site Routing boolean field.');
    return value;
}

function identity(value: unknown): string {
    const result = text(value, 36);
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(result))
        throw new Error('Invalid Site Routing identity.');
    return result;
}

export function target(value: unknown): RoutingTarget {
    const item = record(value);
    if (item.kind === 'networkmanager')
        return {kind: item.kind, id: identity(item.id)};
    if ((item.kind === 'direct' && item.id === 'direct') || (item.kind === 'adguard' && item.id === 'adguardvpn-gnome'))
        return {kind: item.kind, id: item.id};
    throw new Error('Invalid Site Routing provider.');
}

export function list<T>(value: unknown, parse: (item: unknown) => T, maximum = 128): T[] {
    if (!Array.isArray(value) || value.length > maximum)
        throw new Error('Invalid Site Routing list.');
    return value.map(parse);
}

export function provider(value: unknown): VpnProvider {
    const item = record(value);
    return {target: target(item.target), name: text(item.name), active: boolean(item.active),
        detail: text(item.detail), ipv4: boolean(item.ipv4), ipv6: boolean(item.ipv6)};
}

export function rule(value: unknown): RoutingRule {
    const item = record(value);
    if (!isRoutingStatus(item.status))
        throw new Error('Invalid Site Routing status.');
    return {id: identity(item.id), domain: text(item.domain, 253), target: target(item.target),
        status: item.status, detail: text(item.detail), ipv4_count: count(item.ipv4_count),
        ipv6_count: count(item.ipv6_count), updated_at: count(item.updated_at)};
}

export function diagnostics(value: unknown): RoutingDiagnostics {
    const item = record(value);
    let migration: MigrationPlan | null = null;
    if (item.migration !== null) {
        const plan = record(item.migration);
        migration = {id: identity(plan.id), stage: text(plan.stage, 32), changes: list(plan.changes, entry => text(entry), 4096)};
    }
    return {rule: rule(item.rule), addresses: list(item.addresses, address => text(address, 45), 256),
        protection: text(item.protection), migration};
}
