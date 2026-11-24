# AdGuard VPN Quick Toggle for GNOME

Unofficial GNOME Shell Quick Settings integration for the official AdGuard VPN CLI,
with an optional passwordless systemd/Polkit controller for Fedora Workstation.

**Status:** Working on one real Fedora Workstation installation with AdGuard VPN
CLI v1.8.3. GNOME version-specific compatibility and other Linux distributions
have not yet been independently tested. This is a community project, not an
official AdGuard or GNOME extension.

The new **Site Routing** system component is experimental. Its automated tests
include isolated Linux routing/firewall checks; real Fedora boot and dual-VPN
acceptance remain pending. See [Site Routing](#site-routing-experimental).

## Features

- Toggle AdGuard VPN from GNOME Quick Settings with a globe icon.
- Show the active or last connected location as `US -> MIAMI`.
- Browse countries and scroll through cities; display available ping measurements.
- Connect to the global fastest location using AdGuard VPN CLI's `connect -f`.
- Use the ⚡ button next to a country to connect to the city with its lowest reported ping.
- Keep existing OpenVPN/NM profiles unchanged during ordinary toggle use.
  Optional Site Routing migration changes only separately reviewed host entries.
  System-wide routing and DNS still need verification with both VPNs on.
- When the protected systemd controller is installed, detect connection state
  from the current AdGuard service journal (the CLI may not see a `--no-fork`
  process through its PID-file-based `status` command).
- English user interface.
- Experimental exact-host assignments to saved NM VPNs, protected AdGuard or a
  physical gateway through standard extension preferences and an optional service.

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

For removal, follow [Uninstallation](#uninstallation) below.

The extension installation/removal scripts only manage the user's GNOME
extension. They do not request root privileges or modify sudoers, Polkit,
NetworkManager, or VPN routes.

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

The removal procedure, including optional deletion of saved login data, is
described in [Uninstallation](#uninstallation).

## Site Routing (experimental)

Open **Site Routing…** in the toggle menu to assign an exact FQDN or HTTP(S) URL
host to a saved NM VPN (including inactive OpenVPN/WireGuard), protected AdGuard,
or Direct. It never starts the selected VPN automatically. If the target is
unavailable, known destination IPs remain blocked. Shared IPs, unknown cached
addresses, application DoH/DoT and DNS changes before synchronization limit this
IP-based guarantee; DNS query privacy is not separately guaranteed.

The VPN's own server/control connection needs a separately verified underlay.
If AdGuard is needed only for explicitly assigned sites, see the optional
[TUN/NONE setup](docs/vpn-underlay-prerequisite.md#site-only-adguard-routing-with-tunnone).
Unassigned traffic follows ordinary system routing in that setup.
For system-wide AdGuard, the optional
[marked TUN/AUTO setup](docs/vpn-underlay-prerequisite.md#marked-openvpn-transport-with-tunauto)
requires both patched packages and an approved NetworkManager uplink. Live
Fedora acceptance remains open.

This requires a **separate** optional system component. After installing the
extension, review [docs/site-routing.md](docs/site-routing.md), then run from
the repository root on the Fedora test machine:

```bash
sudo dnf install python3-gobject python3-dns python3-idna iproute nftables
sudo ./scripts/install-site-routing.sh
gnome-extensions prefs adguardvpn-toggle@chatgpt.local
```

The AdGuard target additionally needs the authenticated protected helper above;
NM and Direct do not. Site Routing has its own Polkit authorization: every
rule/migration change requires confirmation, while automatic restoration of
approved rules does not. It remains running when the preferences window or
extension closes. Empty rules make no network changes. Existing manual host
policies require an exact diff, private backup and separate migration approvals.

An ordinary legacy conflict or a destination write failure blocks the affected
IPs while independently verified rules continue. Tunnel recreation is retried
automatically once NetworkManager confirms the replacement interface. **Check**
reconciles approved routes and shows a timestamp,
provider reason and the last migration refusal. Legacy retirement always
rechecks the replacement and requires exact live matches for the saved entries.

Rerunning the Site Routing installer restores known-address protection through
the manager while keeping the early guard and NetworkManager running.

Installation, updating, errors, migration and rollback are described in
[docs/site-routing.md](docs/site-routing.md). The
[acceptance record](docs/site-routing-acceptance.md) identifies outstanding real
Fedora tests, especially disconnects, AdGuard TUN/AUTO and early boot. Do not
treat this feature as release-accepted or absolute leak protection.

## Uninstallation

Run the commands below from the repository root, in a terminal in your local
GNOME session. Remove the components you installed using the matching procedure.

### Remove Site Routing first, if installed

Remove its rules in extension preferences and review any migration rollback
before removing the helper or extension. If you enabled marked TUN/AUTO, follow
its [rollback](docs/vpn-underlay-prerequisite.md#roll-back-tunauto-integration)
first. Then:

```bash
sudo ./scripts/uninstall-site-routing.sh
```

The default procedure refuses removal if rules/protection remain and restarts
the manager. To explicitly release **all users'** managed destinations back to
ordinary system routing instead:

```bash
sudo ./scripts/uninstall-site-routing.sh --release-rules
```

This removes only owned routing/firewall objects and system integration; it
does not restore previously retired manual NM entries. Use the UI rollback
first if needed. A cleanup failure retains guards and service files and stops
uninstallation. Follow the reported recovery instructions before continuing.
The uninstaller removes and reloads the NetworkManager drop-in before stopping
the early guard. Private state/backups at `/var/lib/adguardvpn-site-routing` are retained.
See [the full removal procedure](docs/site-routing.md#uninstall-and-retained-data).

### Remove both the extension and passwordless helper

1. Disable the extension as your normal desktop user. This stops its background
   status checks before removing the helper:

   ```bash
   gnome-extensions disable adguardvpn-toggle@chatgpt.local
   ```

2. Remove the optional privileged helper:

   ```bash
   sudo ./scripts/uninstall-helper.sh
   ```

   The script disconnects the protected VPN and stops its transient systemd
   service, then removes the helper, its protected CLI copy and its Polkit
   policy/rule. If it reports `Could not safely disconnect. Uninstall stopped.`,
   resolve the disconnect error before continuing. The private profile at
   `/var/lib/adguardvpn-gnome` is retained; see the optional cleanup below.

3. Remove the extension as your normal desktop user, without `sudo`:

   ```bash
   ./scripts/uninstall-extension.sh
   ```

4. Log out of GNOME and log back in to finish unloading the extension.

### Remove only the extension

First disconnect the VPN using the toggle. If using a terminal instead, run
`adguardvpn-gnome-ctl disconnect` for a protected connection, or
`adguardvpn-cli disconnect` for a direct CLI connection. Removing the extension
alone does not stop a running VPN session.

```bash
./scripts/uninstall-extension.sh
```

Run this as your normal desktop user, then log out of GNOME and log back in.
An installed passwordless helper remains installed until separately removed.
An installed Site Routing service also remains active, including its guards;
removing only the extension does not release those rules.

### Remove only the passwordless helper

Disable the extension, then remove the helper:

```bash
gnome-extensions disable adguardvpn-toggle@chatgpt.local
sudo ./scripts/uninstall-helper.sh
```

After the helper uninstaller completes successfully, re-enable the extension:

```bash
gnome-extensions enable adguardvpn-toggle@chatgpt.local
```

The extension detects the remaining user CLI when re-enabled and resumes direct
CLI operation; connections may request administrator authorization again.
If Site Routing is retained, assignments to protected AdGuard become
`provider-missing` and known IPs remain blocked until reassigned or removed.

### Optional cleanup of saved settings and login data

The uninstall scripts retain the extension's saved location and the helper's
separate AdGuard login profile. For complete removal of this project's saved
data, first finish the applicable uninstall steps above, then remove only the
data you no longer want:

```bash
# Saved extension location for the current desktop user; no sudo.
rm -f -- "${XDG_CONFIG_HOME:-$HOME/.config}/adguardvpn-gnome-toggle/location"
```

After successfully uninstalling the helper, you can also delete its private
profile. This permanently removes that profile's AdGuard credentials and
configuration; reinstalling the helper will require logging in again:

```bash
sudo rm -rf -- /var/lib/adguardvpn-gnome
```

After successfully uninstalling Site Routing, you may also permanently delete
its separate journal and migration backups:

```bash
sudo rm -rf -- /var/lib/adguardvpn-site-routing
```

The original AdGuard VPN CLI installation and its normal user profile remain
installed. Uninstalling this project does not uninstall AdGuard VPN itself.

## Verification

The extension is written in strict TypeScript. The original behavior was
recorded in [docs/behavior-contract.md](docs/behavior-contract.md) and tested
before the refactoring. See [docs/development.md](docs/development.md) for the
module layout, test boundaries and GNOME smoke-test procedure.

AI agents contributing to this repository must follow the instructions in
[AGENTS.md](AGENTS.md).

Run the deterministic extension tests, helper tests and archive checks:

```bash
npm ci
# Use the system Python with native Gio/GLib bindings installed.
python3 -m venv --system-site-packages .tmp/python-env
.tmp/python-env/bin/python -m pip install -r requirements-dev.txt
npm run test:coverage
PYTHONDONTWRITEBYTECODE=1 .tmp/python-env/bin/python -m coverage run -m unittest discover -s tests -v
.tmp/python-env/bin/python -m coverage report
for script in scripts/*.sh helper/client.sh; do bash -n "$script"; done
```

The GitHub Actions workflow runs these checks on pushes and pull requests.
It requires 100% line, branch and function coverage of the compiled extension,
and 100% statement and branch coverage of the Python controllers and routing
bootstrap. Native Gio/GLib bindings are required (`python3-gobject` on Fedora,
`python3-gi` on Ubuntu). The tests cover
parsing, preferences, navigation, connection switching, startup/status grace
periods, cancellation, failures, privileged validation and the installed ZIP's
complete module graph. A separate CI job also exercises real `ip`/`nft` inside
a disposable network namespace. UI, bus and vendor processes remain simulated;
these checks do **not** replace actual GNOME/Polkit/VPN and Fedora boot testing.

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

