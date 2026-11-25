export type ProviderKind = 'networkmanager' | 'adguard' | 'direct';
export interface RoutingTarget {kind: ProviderKind; id: string}
export type RoutingStatus = 'active' | 'blocked-offline' | 'resolving' | 'dns-error' |
    'conflict' | 'apply-error' | 'provider-missing';
export interface VpnProvider {
    target: RoutingTarget;
    name: string;
    active: boolean;
    detail: string;
    ipv4: boolean;
    ipv6: boolean;
}
export interface RoutingRule {
    id: string;
    domain: string;
    target: RoutingTarget;
    status: RoutingStatus;
    detail: string;
    ipv4_count: number;
    ipv6_count: number;
    updated_at: number;
}
export interface MigrationPlan {
    id: string;
    stage: string;
    changes: string[];
    detail: string;
    rollback_only: boolean;
}
export interface RoutingDiagnostics {
    rule: RoutingRule;
    addresses: string[];
    routes: ObservedRoute[];
    checked_at: number | null;
    provider: VpnProvider | null;
    protection: string;
    migration: MigrationPlan | null;
}
export interface ObservedRoute {
    address: string;
    dev?: string;
    table?: string | number;
    gateway?: string;
    type?: string;
}
export type MigrationStage = 'protect' | 'retire' | 'rollback';
type MigrationRequest = {id: string} & (
    {stage: 'protect' | 'retire'} | {stage: 'rollback'; expected_stage: string});
export type RoutingMutation =
    | {operation: 'add-rule'; domain: string; target: RoutingTarget}
    | {operation: 'update-rule'; id: string; domain: string; target: RoutingTarget;
        migration?: MigrationRequest}
    | {operation: 'remove-rule'; id: string};
export type RoutingRequest = RoutingMutation |
    {operation: 'list-providers' | 'list-rules'} | {operation: 'diagnose-rule'; id: string};

export interface RoutingApi {
    providers(): Promise<VpnProvider[]>;
    rules(): Promise<RoutingRule[]>;
    change(request: RoutingMutation): Promise<void>;
    diagnose(id: string): Promise<RoutingDiagnostics>;
    cancel(): void;
}
