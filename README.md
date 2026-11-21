# AdGuard VPN Quick Toggle for GNOME

Unofficial GNOME Shell Quick Settings integration for the official AdGuard VPN CLI,
with an optional passwordless systemd/Polkit controller for Fedora Workstation.

**Status:** Working on one real Fedora Workstation installation with AdGuard VPN
CLI v1.8.3. GNOME version-specific compatibility and other Linux distributions
have not yet been independently tested. This is a community project, not an
official AdGuard or GNOME extension.

## Features

- Toggle AdGuard VPN from GNOME Quick Settings with a globe icon.
- Show the active or last connected location as `US -> MIAMI`.
- Browse countries and scroll through cities; display available ping measurements.
- Connect to the global fastest location using AdGuard VPN CLI's `connect -f`.
- Use the ⚡ button next to a country to connect to the city with its lowest reported ping.
- Do not edit existing corporate OpenVPN or NetworkManager connection profiles.
  System-wide routing and DNS still need to be verified when both VPNs are on.
- When the protected systemd controller is installed, detect connection state
  from the current AdGuard service journal (the CLI may not see a `--no-fork`
  process through its PID-file-based `status` command).
- English user interface.

See [extension/README.md](extension/README.md) for UI details and troubleshooting.

## Installation

1. Install and authenticate the official `adguardvpn-cli` separately. The
   vendor's proprietary executable is **not included** in this repository.
2. Install the GNOME Shell extension:

   ```bash
   npm ci
   ./scripts/install-extension.sh
   ```

   Building requires Node.js 22.18 or newer, npm and zip. The installer compiles
   the TypeScript sources and installs the generated JavaScript modules. Node.js
   and npm are build dependencies; the running extension uses GNOME's GJS.

3. Log out of GNOME and log back in, then enable the extension if needed:

   ```bash
   gnome-extensions enable adguardvpn-toggle@chatgpt.local
   ```

To remove the extension, run `./scripts/uninstall-extension.sh`.

The scripts only manage the user's GNOME extension. They do not request root privileges or modify sudoers, Polkit, NetworkManager, or VPN routes.

## Passwordless connections

The optional helper has been manually tested on Fedora with CLI v1.8.3:
connect, status, route through TUN and disconnect were confirmed in a live
session. It has **not** undergone an independent security audit or automated
end-to-end network tests. It uses a signed, protected copy of the official
AdGuard CLI, a separate root-only login profile, a narrowly scoped Polkit
action for one active local user, and an on-demand transient systemd service.
It does not grant passwordless access to `sudo`, arbitrary `systemctl`
commands, the existing user-writable CLI, or the CLI's configuration commands.

**Important Fedora ownership finding:** The installed CLI may be symlinked from `/usr/local/bin` to a user-owned executable inside a user-writable `/opt/adguardvpn_cli` directory. Never grant passwordless root execution of that executable. The installer copies and verifies the binary and its detached signature, then installs a root-owned snapshot separately.

See [docs/privileged-helper.md](docs/privileged-helper.md) for the exact installation, login, verification, rollback and limitations. Do not install broad `NOPASSWD` sudoers rules.

Quick start **after reading the helper security notes**:

```bash
sudo ./scripts/install-helper.sh "$USER"
sudo ./scripts/login-helper.sh
```

The login command authenticates the **separate, protected profile once**; it is
not required again on ordinary updates. Disconnect any existing user-profile
AdGuard VPN session before starting the protected service. On the same active
local GNOME session:

```bash
adguardvpn-gnome-ctl connect --location Miami
adguardvpn-gnome-ctl status
adguardvpn-gnome-ctl disconnect
```

The controller is opt-in. The extension also works without it, although TUN
connect/disconnect may then require administrator authorization.

To uninstall the privileged helper, run `sudo ./scripts/uninstall-helper.sh`.
It leaves the private root-owned AdGuard login data in place for deliberate
manual cleanup.

## Verification

The extension is written in strict TypeScript. The original behavior was
recorded in [docs/behavior-contract.md](docs/behavior-contract.md) and tested
before the refactoring. See [docs/development.md](docs/development.md) for the
module layout, test boundaries and GNOME smoke-test procedure.

Run the deterministic extension tests, helper tests and archive checks:

```bash
npm ci
python3 -m pip install -r requirements-dev.txt
npm run test:coverage
PYTHONDONTWRITEBYTECODE=1 python3 -m coverage run -m unittest discover -s tests -v
python3 -m coverage report
for script in scripts/*.sh helper/client.sh; do bash -n "$script"; done
```

The GitHub Actions workflow runs these checks on pushes and pull requests.
It requires 100% line, branch and function coverage of the compiled extension,
and 100% statement and branch coverage of the Python controller. The tests cover
parsing, preferences, navigation, connection switching, startup/status grace
periods, cancellation, failures, privileged validation and the installed ZIP's
complete module graph. GNOME, subprocesses and the clock are simulated; these
checks do **not** replace real testing against GNOME, Polkit and a VPN tunnel.

## Publishing and security

- Do not commit AdGuard credentials, login state, secrets, private keys, real corporate routes, or logs.
- The AdGuard VPN CLI binary is proprietary and is not included in this repository.
- This project is not affiliated with or endorsed by AdGuard.
- Review shell scripts and Polkit privileges before running them as root.
- Verify behaviour after each CLI/GNOME update. The project currently targets
  one manually tested Fedora environment, not every advertised GNOME version.

## License

This project's original source code and documentation are released under the
[MIT License](LICENSE). The proprietary AdGuard VPN CLI is distributed
separately by its vendor and is **not** covered by this project's license.

