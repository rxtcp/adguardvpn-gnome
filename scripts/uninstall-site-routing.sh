#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 || $# -gt 1 || $# -eq 1 && $1 != '--release-rules' ]]; then
    printf 'Run as: sudo ./scripts/uninstall-site-routing.sh [--release-rules]\n' >&2
    exit 2
fi

protected_dir=/usr/libexec/adguardvpn-site-routing
state_dir=/var/lib/adguardvpn-site-routing
dropin_dir=/etc/systemd/system/NetworkManager.service.d

if [[ ! -f $protected_dir/launch.py ]]; then
    if [[ -e /etc/systemd/system/adguardvpn-site-routing-guard.service ||
          -e /etc/systemd/system/adguardvpn-site-routing.service ||
          -e $dropin_dir/10-adguardvpn-site-routing.conf ]]; then
        printf 'The protected launcher is missing. Protection may remain; restore the installation before removing it.\n' >&2
        exit 1
    fi
    printf 'Site Routing is already uninstalled. Retained state, if any, was not deleted.\n'
    exit 0
fi

# Verify the launcher before asking Python to execute any installed code.
/usr/bin/python3 -I -B - <<'PY'
from pathlib import Path
import stat
launcher = Path('/usr/libexec/adguardvpn-site-routing/launch.py')
for current in (*reversed(launcher.parents), launcher):
    if current == Path('/'):
        continue
    metadata = current.lstat()
    if metadata.st_uid != 0 or metadata.st_mode & 0o022 or stat.S_ISLNK(metadata.st_mode):
        raise SystemExit('Refusing an untrusted Site Routing launcher or ancestor.')
if not launcher.is_file():
    raise SystemExit('Refusing an invalid Site Routing launcher.')
PY

/usr/bin/systemctl stop adguardvpn-site-routing.service
if [[ $# -eq 1 ]]; then
    printf 'Explicitly releasing all Site Routing rules. Their addresses return to ordinary system routing.\n'
    if ! /usr/bin/python3 -I -B "$protected_dir/launch.py" release; then
        printf 'Release failed; guards and service files are retained. Restart the service to recover.\n' >&2
        exit 1
    fi
elif ! /usr/bin/python3 -I -B "$protected_dir/launch.py" check-empty; then
    /usr/bin/systemctl start adguardvpn-site-routing.service
    printf 'Uninstall stopped. Remove rules in settings first, or explicitly use --release-rules.\n' >&2
    exit 1
fi

/usr/bin/systemctl disable adguardvpn-site-routing.service adguardvpn-site-routing-guard.service
/usr/bin/rm -f -- "$dropin_dir/10-adguardvpn-site-routing.conf"
/usr/bin/systemctl daemon-reload
/usr/bin/systemctl stop adguardvpn-site-routing-guard.service
/usr/bin/rm -f -- /etc/systemd/system/adguardvpn-site-routing.service \
    /etc/systemd/system/adguardvpn-site-routing-guard.service \
    /usr/share/dbus-1/system.d/org.gnome.AdGuardVPN.SiteRouting.conf \
    /usr/share/dbus-1/system-services/org.gnome.AdGuardVPN.SiteRouting.service \
    /usr/share/polkit-1/actions/org.gnome.adguardvpn.site-routing.policy
/usr/bin/rm -rf -- "$protected_dir"
/usr/bin/rmdir -- "$dropin_dir" 2>/dev/null || true
/usr/bin/systemctl daemon-reload
printf 'Site Routing removed. Only its own rules, tables, guard and system integration were removed.\n'
printf 'Private state and migration backups remain at %s.\n' "$state_dir"
