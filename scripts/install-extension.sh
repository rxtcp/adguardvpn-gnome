#!/usr/bin/env bash
set -euo pipefail

extension_uuid='adguardvpn-toggle@chatgpt.local'
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
project_dir="$(dirname -- "$script_dir")"

for program in gnome-extensions zip; do
    if ! command -v "$program" >/dev/null 2>&1; then
        printf 'Missing required command: %s\n' "$program" >&2
        exit 1
    fi
done

archive_dir="$(mktemp -d)"
trap 'rm -f -- "$archive_dir/extension.zip"; rmdir -- "$archive_dir"' EXIT
archive_path="$archive_dir/extension.zip"

(
    cd -- "$project_dir/extension"
    zip -q "$archive_path" extension.js metadata.json README.md icons/planet-symbolic.svg
)

if gnome-extensions info "$extension_uuid" >/dev/null 2>&1; then
    gnome-extensions disable "$extension_uuid" || true
fi

gnome-extensions install --force "$archive_path"
printf 'Installed %s. Log out and log back in, then enable it if needed.\n' "$extension_uuid"

