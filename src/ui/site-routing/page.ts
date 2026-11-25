import Adw from 'gi://Adw';
import GLib from 'gi://GLib';
import Gtk from 'gi://Gtk';
import {errorMessage} from '../../domain/cli-output.js';
import {RoutingClient} from '../../platform/routing-client.js';
import {RoutingController, type RoutingView} from '../../application/routing-controller.js';
import {normalizeSiteDomain, protectionNotice} from '../../domain/site-routing.js';
import {confirm, showDiagnostics} from './dialogs.js';
import {createRuleRow} from './rule-row.js';
import type {RoutingDiagnostics, RoutingRule, VpnProvider} from '../../domain/site-routing-types.js';

function key(provider: VpnProvider): string { return `${provider.target.kind}:${provider.target.id}`; }

export class SiteRoutingPage implements RoutingView {
    private readonly controller: RoutingController;
    private readonly entry = new Adw.EntryRow({title: 'URL or exact domain'});
    private readonly selection = new Adw.ComboRow({title: 'Target connection'});
    private readonly scope = new Adw.ActionRow({title: 'Scope', use_markup: false});
    private readonly status = new Adw.ActionRow({title: 'Site Routing status', subtitle: 'Loading the optional system service…', use_markup: false});
    private readonly submit = new Gtk.Button({label: 'Add', valign: Gtk.Align.CENTER, css_classes: ['suggested-action']});
    private readonly cancelEdit = new Gtk.Button({label: 'Cancel edit', valign: Gtk.Align.CENTER, sensitive: false});
    private readonly ruleGroup = new Adw.PreferencesGroup({title: 'Rules'});
    private rows: Adw.ActionRow[] = [];
    private available: VpnProvider[] = [];
    private editing: string | null = null;
    private working = false;
    private timer = 0;

    constructor(private readonly window: Adw.PreferencesWindow) {
        this.controller = new RoutingController(new RoutingClient(), this, host => GLib.hostname_to_ascii(host));
        const page = new Adw.PreferencesPage({title: 'Site Routing', icon_name: 'network-workgroup-symbolic'});
        const editor = new Adw.PreferencesGroup({title: 'Exact host routing', description: protectionNotice});
        editor.add(this.entry);
        editor.add(this.selection);
        editor.add(this.scope);
        const actions = new Adw.ActionRow({title: 'Changes require Polkit confirmation', use_markup: false});
        actions.add_suffix(this.cancelEdit);
        actions.add_suffix(this.submit);
        editor.add(actions);
        editor.add(this.status);
        page.add(editor);
        page.add(this.ruleGroup);
        window.add(page);
        window.set_default_size(840, 640);
        this.entry.connect('notify::text', () => this.updateScope());
        this.cancelEdit.connect('clicked', () => this.clearEditor());
        this.submit.connect('clicked', () => {
            const provider = this.available[this.selection.get_selected()];
            if (provider)
                void this.controller.save(this.entry.get_text(), provider.target, this.editing);
            else
                this.message('Choose an available provider profile. Inactive profiles can also be assigned.');
        });
        window.connect('close-request', () => {
            if (this.timer) {
                GLib.Source.remove(this.timer);
                this.timer = 0;
            }
            this.controller.close();
            return false;
        });
        this.updateScope();
        this.rules([]);
        this.busy(false);
        this.timer = GLib.timeout_add_seconds(GLib.PRIORITY_DEFAULT, 5, () => {
            void this.controller.refresh();
            return GLib.SOURCE_CONTINUE;
        });
        void this.controller.refresh();
    }

    private updateScope(): void {
        try {
            this.scope.subtitle = this.entry.get_text()
                ? `Entire host: ${normalizeSiteDomain(this.entry.get_text(), host => GLib.hostname_to_ascii(host))}`
                : 'Rules apply to the entire exact host, including all URL paths.';
        } catch (error) { this.scope.subtitle = errorMessage(error); }
    }

    providers(values: VpnProvider[]): void {
        const previous = this.available[this.selection.get_selected()];
        this.available = values;
        this.selection.set_model(Gtk.StringList.new(values.map(provider =>
            `${provider.name} · ${provider.target.kind} · ${provider.active ? 'active' : 'inactive'}`)));
        const selected = previous ? values.findIndex(provider => key(provider) === key(previous)) : this.editing ? -1 : 0;
        this.selection.set_selected(selected >= 0 && selected < values.length ? selected : Gtk.INVALID_LIST_POSITION);
        this.busy(this.working);
    }

    rules(values: RoutingRule[]): void {
        for (const row of this.rows)
            this.ruleGroup.remove(row);
        this.rows = values.length ? values.map(rule => {
            const provider = this.available.find(item => item.target.kind === rule.target.kind && item.target.id === rule.target.id);
            return createRuleRow(rule, provider?.name ?? `${rule.target.kind}: ${rule.target.id}`,
                () => this.edit(rule), () => { void this.controller.remove(rule); },
                () => { void this.controller.diagnose(rule); });
        }) : [new Adw.ActionRow({title: 'No Site Routing rules', subtitle: 'Existing system routing is unchanged.', use_markup: false})];
        for (const row of this.rows) {
            row.set_sensitive(!this.working);
            this.ruleGroup.add(row);
        }
    }

    private edit(rule: RoutingRule): void {
        this.editing = rule.id;
        this.entry.set_text(rule.domain);
        const selected = this.available.findIndex(provider => provider.target.kind === rule.target.kind && provider.target.id === rule.target.id);
        this.selection.set_selected(selected < 0 ? Gtk.INVALID_LIST_POSITION : selected);
        this.submit.set_label('Save');
        this.busy(false);
    }

    clearEditor(): void {
        this.editing = null;
        this.entry.set_text('');
        this.submit.set_label('Add');
        this.busy(this.working);
    }

    busy(value: boolean): void {
        this.working = value;
        this.entry.set_sensitive(!value && this.editing === null);
        this.selection.set_sensitive(!value);
        this.submit.set_sensitive(!value && this.available.length > 0);
        this.cancelEdit.set_sensitive(!value && this.editing !== null);
        for (const row of this.rows)
            row.set_sensitive(!value);
    }

    message(text: string): void { this.status.subtitle = text || 'Ready. Changes require Polkit confirmation.'; }
    confirm(title: string, body: string): Promise<boolean> { return confirm(this.window, title, body); }
    diagnostics(value: RoutingDiagnostics): void {
        showDiagnostics(this.window, value, (plan, stage) => { void this.controller.migrate(value.rule, plan, stage); });
    }
}
