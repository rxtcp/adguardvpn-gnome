import Adw from 'gi://Adw';
import Gtk from 'gi://Gtk';
import {statusLabel} from '../../domain/site-routing.js';
import type {RoutingRule} from '../../domain/site-routing-types.js';

export function createRuleRow(rule: RoutingRule, targetName: string,
    edit: () => void, remove: () => void, diagnose: () => void): Adw.ActionRow {
    const updated = rule.updated_at ? new Date(rule.updated_at * 1000).toLocaleString() : 'Not updated';
    const row = new Adw.ActionRow({title: rule.domain, use_markup: false,
        subtitle: `${targetName} · ${statusLabel(rule.status)}\nIPv4: ${rule.ipv4_count} · IPv6: ${rule.ipv6_count} · ${updated}\n${rule.detail}`});
    for (const [label, action, accessible] of [
        ['Edit', edit, `Edit rule for ${rule.domain}`],
        ['Remove', remove, `Remove rule for ${rule.domain}`],
        ['Check', diagnose, `Check rule for ${rule.domain}`],
    ] as const) {
        const button = new Gtk.Button({label, accessible_role: Gtk.AccessibleRole.BUTTON,
            tooltip_text: accessible, valign: Gtk.Align.CENTER});
        button.update_property([Gtk.AccessibleProperty.LABEL], [accessible]);
        button.connect('clicked', action);
        row.add_suffix(button);
    }
    return row;
}
