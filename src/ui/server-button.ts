import Clutter from 'gi://Clutter';
import St from 'gi://St';

export function createServerButton(text: string, callback: () => void, showArrow = false): St.Button {
    const row = new St.BoxLayout({x_expand: true, style: 'spacing: 8px;'});
    row.add_child(new St.Label({text, x_expand: true, y_align: Clutter.ActorAlign.CENTER}));
    if (showArrow)
        row.add_child(new St.Icon({icon_name: 'go-next-symbolic', icon_size: 12, y_align: Clutter.ActorAlign.CENTER}));
    const button = new St.Button({style_class: 'popup-menu-item', child: row, x_expand: true,
        reactive: true, can_focus: true, track_hover: true});
    button.connect('clicked', callback);
    return button;
}
