import {errorMessage} from '../domain/cli-output.js';
import {normalizeSiteDomain} from '../domain/site-routing.js';
import type {MigrationPlan, MigrationStage, RoutingApi, RoutingDiagnostics, RoutingRule, RoutingTarget, VpnProvider} from '../domain/site-routing-types.js';

export interface RoutingView {
    providers(value: VpnProvider[]): void;
    rules(value: RoutingRule[]): void;
    busy(value: boolean): void;
    message(text: string): void;
    clearEditor(): void;
    confirm(title: string, body: string): Promise<boolean>;
    diagnostics(value: RoutingDiagnostics): void;
}

export class RoutingController {
    private closed = false;
    private working = false;
    private loading = false;
    private generation = 0;

    constructor(private readonly client: RoutingApi, private readonly view: RoutingView,
        private readonly toAscii: (host: string) => string | null) {}

    close(): void { this.closed = true; this.client.cancel(); }

    async refresh(): Promise<void> {
        if (this.closed || this.loading || this.working)
            return;
        this.loading = true;
        const generation = this.generation;
        try {
            const [providers, rules] = await Promise.all([this.client.providers(), this.client.rules()]);
            if (!this.closed && generation === this.generation) {
                this.view.providers(providers);
                this.view.rules(rules);
            }
        } catch (error) {
            if (!this.closed)
                this.view.message(errorMessage(error));
        } finally {
            this.loading = false;
            if (!this.closed && generation !== this.generation && !this.working)
                void this.refresh();
        }
    }

    async save(input: string, target: RoutingTarget, id: string | null = null): Promise<void> {
        if (this.closed || this.working)
            return;
        try {
            const domain = normalizeSiteDomain(input, this.toAscii);
            await this.work(async () => {
                await this.client.change(id ? {operation: 'update-rule', id, domain, target} : {operation: 'add-rule', domain, target});
                if (!this.closed)
                    this.view.clearEditor();
            });
        } catch (error) { this.view.message(errorMessage(error)); }
    }

    async remove(rule: RoutingRule): Promise<void> {
        if (this.closed || this.working || !await this.view.confirm(`Remove ${rule.domain}?`,
            'Known addresses will return to ordinary system routing, which may use another VPN or the physical connection.'))
            return;
        await this.work(() => this.client.change({operation: 'remove-rule', id: rule.id}));
    }

    async diagnose(rule: RoutingRule): Promise<void> {
        await this.work(async () => {
            const diagnosis = await this.client.diagnose(rule.id);
            if (!this.closed)
                this.view.diagnostics(diagnosis);
        });
    }

    async migrate(rule: RoutingRule, plan: MigrationPlan, stage: MigrationStage): Promise<void> {
        const explanation = stage === 'rollback'
            ? plan.stage === 'protected'
                ? 'Remove this Site Routing replacement. This leaves the legacy NetworkManager settings and policies as they are.'
                : 'Restore the verified NM backup and recorded removals, then remove this Site Routing replacement.'
            : stage === 'retire'
                ? 'Remove only the listed legacy NM entries after verifying the protected replacement. A private backup is retained.'
                : 'Install and verify a guarded replacement. Existing NM entries are retained until a separate confirmation.';
        if (this.closed || this.working || !await this.view.confirm('Confirm routing migration', `${explanation}\n\n${plan.changes.join('\n')}`))
            return;
        await this.work(() => this.client.change({operation: 'update-rule', id: rule.id, domain: rule.domain,
            target: rule.target, migration: {id: plan.id, stage}}));
    }

    private async work(operation: () => Promise<void>): Promise<void> {
        if (this.closed || this.working)
            return;
        this.working = true;
        this.generation++;
        this.view.busy(true);
        let success = false;
        try {
            await operation();
            success = true;
            if (!this.closed)
                this.view.message('');
        } catch (error) {
            if (!this.closed)
                this.view.message(errorMessage(error));
        } finally {
            this.working = false;
            if (!this.closed)
                this.view.busy(false);
        }
        if (success)
            await this.refresh();
    }
}
