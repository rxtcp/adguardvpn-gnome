#!/usr/bin/env bash
set -euo pipefail

# Status checks are read-only, but still go through the same narrow helper so
# they see the dedicated root-owned AdGuard VPN profile.
exec /usr/bin/pkexec /usr/libexec/adguardvpn-gnome/control "$@"
