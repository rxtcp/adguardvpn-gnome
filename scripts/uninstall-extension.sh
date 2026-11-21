#!/usr/bin/env bash
set -euo pipefail

extension_uuid='adguardvpn-toggle@chatgpt.local'

if ! command -v gnome-extensions >/dev/null 2>&1; then
    printf 'Missing required command: gnome-extensions\n' >&2
    exit 1
fi

gnome-extensions disable "$extension_uuid" || true
gnome-extensions uninstall "$extension_uuid"
printf 'Uninstalled %s. Log out and log back in to finish.\n' "$extension_uuid"

