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
}
export interface RoutingDiagnostics {
    rule: RoutingRule;
    addresses: string[];
    protection: string;
    migration: MigrationPlan | null;
}
export type MigrationStage = 'protect' | 'retire' | 'rollback';
export type RoutingMutation =
    | {operation: 'add-rule'; domain: string; target: RoutingTarget}
    | {operation: 'update-rule'; id: string; domain: string; target: RoutingTarget;
        migration?: {id: string; stage: MigrationStage}}
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
