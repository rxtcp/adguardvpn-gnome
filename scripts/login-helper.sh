#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
    printf 'Run as: sudo ./scripts/login-helper.sh\n' >&2
    exit 1
fi

protected_cli=/usr/libexec/adguardvpn-gnome/adguardvpn-cli
protected_profile=/var/lib/adguardvpn-gnome
if [[ ! -x $protected_cli || ! -d $protected_profile ]]; then
    printf 'Protected helper is not installed. Run install-helper.sh first.\n' >&2
    exit 1
fi

cli() {
    env -i \
        HOME="$protected_profile" \
        XDG_CONFIG_HOME="$protected_profile/config" \
        XDG_DATA_HOME="$protected_profile/data" \
        XDG_CACHE_HOME="$protected_profile/cache" \
        USER=root LOGNAME=root LANG=C.UTF-8 \
        PATH=/usr/sbin:/usr/bin:/sbin:/bin \
        "$protected_cli" "$@"
}

printf 'Log in once to the protected AdGuard VPN profile.\n'
printf 'This does not copy credentials from your normal user profile.\n\n'
cli login
cli config set-mode TUN
cli config set-tun-routing-mode AUTO
printf '\nProtected profile configured for TUN + AUTO.\n'
printf 'Before connecting, disconnect any old user-owned AdGuard session.\n'
