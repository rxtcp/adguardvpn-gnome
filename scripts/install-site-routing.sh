#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 || $# -ne 0 ]]; then
    printf 'Run as: sudo ./scripts/install-site-routing.sh\n' >&2
    exit 2
fi

script_dir=$(cd -- "$(/usr/bin/dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
project_dir=$(cd -- "$script_dir/.." && pwd -P)
protected_dir=/usr/libexec/adguardvpn-site-routing
state_dir=/var/lib/adguardvpn-site-routing
dropin_dir=/etc/systemd/system/NetworkManager.service.d

for dependency in /usr/sbin/ip /usr/sbin/nft /usr/bin/python3 /usr/bin/systemctl /usr/bin/install; do
    if [[ ! -x $dependency ]]; then
        printf 'Missing runtime dependency: %s\n' "$dependency" >&2
        exit 1
    fi
done
/usr/bin/python3 -I -B -c 'import gi, dns.resolver, idna; gi.require_version("Gio", "2.0"); from gi.repository import Gio' || {
    printf 'Install Fedora packages python3-gobject, python3-dns and python3-idna first.\n' >&2
    exit 1
}

# Refuse redirected destinations and user-writable ancestors before any writes.
/usr/bin/python3 -I -B - <<'PY'
from pathlib import Path
import stat
paths = ['/usr/libexec/adguardvpn-site-routing', '/var/lib/adguardvpn-site-routing',
         '/etc/systemd/system/NetworkManager.service.d',
         '/etc/systemd/system/NetworkManager.service.d/10-adguardvpn-site-routing.conf',
         '/etc/systemd/system/adguardvpn-site-routing.service',
         '/etc/systemd/system/adguardvpn-site-routing-guard.service',
         '/usr/share/dbus-1/system.d/org.gnome.AdGuardVPN.SiteRouting.conf',
         '/usr/share/dbus-1/system-services/org.gnome.AdGuardVPN.SiteRouting.service',
         '/usr/share/polkit-1/actions/org.gnome.adguardvpn.site-routing.policy']
for name in paths:
    path = Path(name)
    for current in (*reversed(path.parents), path):
        if current == Path('/') or not current.exists() and not current.is_symlink():
            continue
        metadata = current.lstat()
        if metadata.st_uid != 0 or metadata.st_mode & 0o022 or stat.S_ISLNK(metadata.st_mode):
            raise SystemExit('Refusing an untrusted Site Routing destination or ancestor.')
profile = Path('/var/lib/adguardvpn-site-routing')
if profile.exists() and profile.stat().st_mode & 0o077:
    raise SystemExit('Refusing a non-private existing Site Routing state directory.')
PY

if [[ -f $protected_dir/launch.py ]]; then
    /usr/bin/systemctl stop adguardvpn-site-routing.service
fi
/usr/bin/install -d -o 0 -g 0 -m 0755 -- "$protected_dir" "$protected_dir/site_routing"
/usr/bin/install -d -o 0 -g 0 -m 0700 -- "$state_dir"
for source_file in "$project_dir/site_routing/"*.py; do
    /usr/bin/install -o 0 -g 0 -m 0644 -- "$source_file" "$protected_dir/site_routing/"
done
/usr/bin/install -o 0 -g 0 -m 0644 -- "$project_dir/routing_system/launch.py" "$protected_dir/launch.py"
if [[ ! -d $dropin_dir ]]; then
    /usr/bin/install -d -o 0 -g 0 -m 0755 -- "$dropin_dir"
fi
for unit in adguardvpn-site-routing.service adguardvpn-site-routing-guard.service; do
    /usr/bin/install -o 0 -g 0 -m 0644 -- "$project_dir/routing_system/$unit" "/etc/systemd/system/$unit"
done
/usr/bin/install -o 0 -g 0 -m 0644 -- "$project_dir/routing_system/10-adguardvpn-site-routing.conf" "$dropin_dir/10-adguardvpn-site-routing.conf"
/usr/bin/install -o 0 -g 0 -m 0644 -- "$project_dir/routing_system/org.gnome.AdGuardVPN.SiteRouting.conf" /usr/share/dbus-1/system.d/
/usr/bin/install -o 0 -g 0 -m 0644 -- "$project_dir/routing_system/org.gnome.AdGuardVPN.SiteRouting.service" /usr/share/dbus-1/system-services/
/usr/bin/install -o 0 -g 0 -m 0644 -- "$project_dir/routing_system/org.gnome.adguardvpn.site-routing.policy" /usr/share/polkit-1/actions/
/usr/bin/systemctl daemon-reload
/usr/bin/systemctl enable adguardvpn-site-routing-guard.service adguardvpn-site-routing.service
# Starting an active guard is a no-op. Restarting it would propagate to NetworkManager.
/usr/bin/systemctl start adguardvpn-site-routing-guard.service
/usr/bin/systemctl start adguardvpn-site-routing.service
printf 'Site Routing installed. Open extension preferences → Site Routing.\n'
printf 'An empty rule list makes no network changes. See docs/site-routing.md before adding rules.\n'
