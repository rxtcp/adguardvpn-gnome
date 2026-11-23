import Adw from 'gi://Adw';
import Gtk from 'gi://Gtk';
import type {MigrationPlan, MigrationStage, RoutingDiagnostics} from '../../domain/site-routing-types.js';

function details(text: string): Gtk.ScrolledWindow {
    const buffer = new Gtk.TextBuffer();
    buffer.set_text(text, -1);
    return new Gtk.ScrolledWindow({min_content_height: 120, max_content_height: 360,
        propagate_natural_height: true, child: new Gtk.TextView({buffer, editable: false,
            cursor_visible: false, monospace: true, wrap_mode: Gtk.WrapMode.WORD_CHAR})});
}

export function confirm(window: Adw.PreferencesWindow, title: string, body: string): Promise<boolean> {
    return new Promise(resolve => {
        const dialog = new Adw.MessageDialog({transient_for: window, modal: true, heading: title,
            body: body.length > 600 ? 'Review the complete details below before confirming.' : body,
            body_use_markup: false, extra_child: body.length > 600 ? details(body) : null});
        dialog.add_response('cancel', 'Cancel');
        dialog.add_response('confirm', 'Confirm');
        dialog.set_response_appearance('confirm', Adw.ResponseAppearance.DESTRUCTIVE);
        dialog.set_default_response('cancel');
        dialog.set_close_response('cancel');
        dialog.connect('response', (_dialog, response) => {
            dialog.destroy();
            resolve(response === 'confirm');
        });
        dialog.present();
    });
}

export function showDiagnostics(window: Adw.PreferencesWindow, diagnosis: RoutingDiagnostics,
    migrate: (plan: MigrationPlan, stage: MigrationStage) => void): void {
    const plan = diagnosis.migration;
    const provider = diagnosis.provider;
    const checked = diagnosis.checked_at ? new Date(diagnosis.checked_at * 1000).toLocaleString() : 'Unavailable from this service version';
    const providerState = provider ? `${provider.name}: ${provider.active ? 'verified paths available' : 'no verified path'}. ${provider.detail}`
        : `Provider unavailable: ${diagnosis.rule.target.kind}:${diagnosis.rule.target.id}`;
    const text = [`Checked at: ${checked}`, providerState, diagnosis.protection, `Known addresses:\n${diagnosis.addresses.join('\n')}`,
        `Observed kernel routes:\n${diagnosis.routes.map(route => JSON.stringify(route)).join('\n')}`,
        plan ? `Migration: ${plan.stage}\n${plan.detail || 'No migration error recorded.'}\nExact migration diff:\n${plan.changes.join('\n')}`
            : 'No eligible legacy NM entries were found.'].join('\n\n');
    const dialog = new Adw.MessageDialog({transient_for: window, modal: true,
        heading: diagnosis.rule.domain, body: diagnosis.rule.detail, body_use_markup: false,
        extra_child: details(text)});
    dialog.add_response('close', 'Close');
    dialog.set_close_response('close');
    if (plan?.stage === 'preview')
        dialog.add_response('protect', 'Install protected replacement');
    if (plan && ['protected', 'failed', 'retiring'].includes(plan.stage))
        dialog.add_response('retire', 'Remove listed legacy entries');
    if (plan && plan.stage !== 'preview' && plan.stage !== 'rolled-back')
        dialog.add_response('rollback', 'Roll back migration');
    dialog.connect('response', (_dialog, response) => {
        dialog.destroy();
        if (plan && (response === 'protect' || response === 'retire' || response === 'rollback'))
            migrate(plan, response);
    });
    dialog.present();
}
