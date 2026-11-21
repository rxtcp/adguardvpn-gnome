#!/usr/bin/env bash
set -euo pipefail

# One-time privileged install. Do not add this script to NOPASSWD sudoers.
if [[ ${EUID} -ne 0 ]]; then
    printf 'Run as: sudo ./scripts/install-helper.sh USERNAME\n' >&2
    exit 1
fi

if [[ $# -lt 1 || $# -gt 3 ]]; then
    printf 'Usage: sudo ./scripts/install-helper.sh USERNAME [--key-file PUBLIC_KEY.asc]\n' >&2
    exit 2
fi

target_user=$1
if [[ ! $target_user =~ ^[a-z_][a-z0-9_-]*$ ]]; then
    printf 'Invalid local username.\n' >&2
    exit 2
fi
if ! getent passwd "$target_user" >/dev/null; then
    printf 'Local user does not exist: %s\n' "$target_user" >&2
    exit 2
fi

key_file=''
if [[ $# -eq 3 ]]; then
    if [[ $2 != '--key-file' || ! -f $3 ]]; then
        printf 'Expected --key-file PATH for an AdGuard public GPG key.\n' >&2
        exit 2
    fi
    key_file=$3
elif [[ $# -eq 2 ]]; then
    printf 'Use --key-file PATH, or omit both arguments.\n' >&2
    exit 2
fi

for dependency in gpg install readlink mktemp sed systemctl systemd-run journalctl pkexec; do
    command -v "$dependency" >/dev/null || {
        printf 'Required command not found: %s\n' "$dependency" >&2
        exit 1
    }
done

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
source_root=$(cd -- "$script_dir/.." && pwd -P)
source_binary=/opt/adguardvpn_cli/adguardvpn-cli
source_signature=/opt/adguardvpn_cli/adguardvpn-cli.sig
official_fingerprint=28645AC9776EC4C00BCE2AFC0FE641E7235E2EC6
protected_dir=/usr/libexec/adguardvpn-gnome
profile_dir=/var/lib/adguardvpn-gnome
polkit_policy=/usr/share/polkit-1/actions/org.gnome.adguardvpn.control.policy
polkit_rule=/etc/polkit-1/rules.d/49-adguardvpn-gnome.rules
client=/usr/local/bin/adguardvpn-gnome-ctl

if [[ ! -f $source_binary || ! -f $source_signature ]]; then
    printf 'AdGuard CLI binary or detached .sig is missing in /opt/adguardvpn_cli.\n' >&2
    printf 'Reinstall the official signed AdGuard VPN CLI release first.\n' >&2
    exit 1
fi

if systemctl is-active --quiet adguardvpn-gnome.service; then
    printf 'Disconnect the protected AdGuard VPN service before updating it.\n' >&2
    exit 1
fi

# The outer profile directory must remain a private root-only boundary.
# AdGuard creates its own directories/files within it and may use permissions
# that are less restrictive than 0700. Those descendants cannot be reached
# by an unprivileged user through the 0700 parent, so do not reject them or
# alter their ownership. Never take over a user-owned outer profile.
if [[ -e $profile_dir ]]; then
    profile_owner=$(stat -c '%u' -- "$profile_dir")
    profile_mode=$(stat -c '%a' -- "$profile_dir")
    if [[ $profile_owner != 0 || $profile_mode != 700 ]]; then
        printf 'Refusing existing non-private/root profile: %s\n' "$profile_dir" >&2
        exit 1
    fi
    linked_entry=$(find "$profile_dir" -type l -print -quit)
    if [[ -n $linked_entry ]]; then
        printf 'Refusing symlink inside protected profile: %s\n' "$linked_entry" >&2
        printf 'Inspect this link before running privileged AdGuard CLI.\n' >&2
        exit 1
    fi
fi

stage=$(mktemp -d /tmp/adguardvpn-gnome-install.XXXXXXXX)
cleanup() {
    rm -f -- "$stage/cli" "$stage/cli.sig" "$stage/status" "$stage/polkit-rule" \
        "$stage/gnupg/pubring.kbx" "$stage/gnupg/pubring.kbx~" \
        "$stage/gnupg/trustdb.gpg" "$stage/gnupg/keys.openpgp.org" \
        "$stage/gnupg/random_seed"
    # GPG may create keyserver-specific cache files: only this mktemp directory.
    if [[ -d $stage ]]; then
        rm -rf -- "$stage"
    fi
}
trap cleanup EXIT

# Take a snapshot BEFORE verifying to prevent an unprivileged updater from
# swapping the bytes between verification and the protected installation.
install -m 0700 -- "$source_binary" "$stage/cli"
install -m 0600 -- "$source_signature" "$stage/cli.sig"
install -d -m 0700 -- "$stage/gnupg"

if [[ -n $key_file ]]; then
    gpg --homedir "$stage/gnupg" --batch --import -- "$key_file"
else
    printf 'Fetching the AdGuard release signing key...\n'
    if ! gpg --homedir "$stage/gnupg" --batch \
        --keyserver hkps://keys.openpgp.org --recv-keys "$official_fingerprint"; then
        printf 'Key download failed; retry with --key-file /path/to/verified-public-key.asc.\n' >&2
        exit 1
    fi
fi

if ! gpg --homedir "$stage/gnupg" --batch --status-fd 1 \
    --verify "$stage/cli.sig" "$stage/cli" > "$stage/status"; then
    printf 'AdGuard CLI signature verification failed. Nothing installed.\n' >&2
    exit 1
fi
if ! awk -v fingerprint="$official_fingerprint" \
    '$1 == "[GNUPG:]" && $2 == "VALIDSIG" && $3 == fingerprint {valid=1} END {exit !valid}' \
    "$stage/status"; then
    printf 'AdGuard signature key fingerprint does not match the official key.\n' >&2
    exit 1
fi

printf 'Signature verified against official AdGuard key %s.\n' "$official_fingerprint"

# Refuse to install onto a symlink that could redirect writes outside the
# intended protected directories.
for destination in "$protected_dir" "$profile_dir" "$client" "$polkit_policy" "$polkit_rule"; do
    if [[ -L $destination ]]; then
        printf 'Unsafe symlink at install destination: %s\n' "$destination" >&2
        exit 1
    fi
done

install -d -o 0 -g 0 -m 0755 -- "$protected_dir"
install -d -o 0 -g 0 -m 0700 -- "$profile_dir"
install -o 0 -g 0 -m 0755 -- "$stage/cli" "$protected_dir/adguardvpn-cli"
install -o 0 -g 0 -m 0644 -- "$stage/cli.sig" "$protected_dir/adguardvpn-cli.sig"
install -o 0 -g 0 -m 0755 -- "$source_root/helper/control.py" "$protected_dir/control"
install -o 0 -g 0 -m 0755 -- "$source_root/helper/client.sh" "$client"
install -o 0 -g 0 -m 0644 -- "$source_root/helper/org.gnome.adguardvpn.control.policy" "$polkit_policy"
sed "s/@USERNAME@/$target_user/g" \
    "$source_root/helper/49-adguardvpn-gnome.rules.in" > "$stage/polkit-rule"
install -o 0 -g 0 -m 0644 -- "$stage/polkit-rule" "$polkit_rule"

printf '\nInstalled protected AdGuard VPN controller for %s.\n' "$target_user"
printf 'Next: sudo ./scripts/login-helper.sh\n'
printf 'Then test: adguardvpn-gnome-ctl status\n'
printf 'This did NOT modify the existing /opt installation or corporate VPN.\n'
