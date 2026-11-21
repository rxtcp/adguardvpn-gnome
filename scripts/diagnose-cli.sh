#!/usr/bin/env bash
set -euo pipefail

if ! command -v adguardvpn-cli >/dev/null 2>&1; then
    printf 'adguardvpn-cli was not found in PATH.\n' >&2
    exit 1
fi

printf 'CLI path: %s\n' "$(command -v adguardvpn-cli)"
adguardvpn-cli --version

# A root-owned symlink does not make its user-writable target safe to run as
# root. Print ownership of the entire path, including parent directories.
if command -v readlink >/dev/null 2>&1 && command -v namei >/dev/null 2>&1; then
    cli_target="$(readlink -f "$(command -v adguardvpn-cli)")"
    printf '\nCLI executable ownership and directory chain:\n'
    namei -l "$cli_target"
fi

# Display only the fields relevant to the privileged-helper design.
# Deliberately avoid printing account, route, DNS, and credential settings.
adguardvpn-cli config show | awk '
    /^[[:space:]]*(Mode|Tunnel routing mode):/ {print}
'

