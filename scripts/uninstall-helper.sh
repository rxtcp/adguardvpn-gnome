#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 || $# -ne 0 ]]; then
    printf 'Run as: sudo ./scripts/uninstall-helper.sh\n' >&2
    exit 2
fi

protected_dir=/usr/libexec/adguardvpn-gnome
profile_dir=/var/lib/adguardvpn-gnome
if [[ -x $protected_dir/control ]]; then
    "$protected_dir/control" disconnect || {
        printf 'Could not safely disconnect. Uninstall stopped.\n' >&2
        exit 1
    }
fi

rm -f -- \
    /etc/polkit-1/rules.d/49-adguardvpn-gnome.rules \
    /usr/share/polkit-1/actions/org.gnome.adguardvpn.control.policy \
    /usr/local/bin/adguardvpn-gnome-ctl \
    "$protected_dir/control" \
    "$protected_dir/adguardvpn-cli" \
    "$protected_dir/adguardvpn-cli.sig"
rmdir -- "$protected_dir" 2>/dev/null || true

printf 'Protected controller removed.\n'
printf 'Your private AdGuard login remains in %s for recovery.\n' "$profile_dir"
printf 'The original /opt AdGuard VPN CLI and corporate OpenVPN were untouched.\n'
