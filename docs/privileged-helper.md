# Optional passwordless helper: experimental implementation

The protected helper has been tested manually on one Fedora Workstation
installation with AdGuard VPN CLI v1.8.3: connect, status, TUN routing and
disconnect worked. It has **not** undergone an independent security audit or
automated integration testing. Review privileged scripts before installing
and verify routes/DNS on your own machine.

## Threat model and background

- AdGuard VPN CLI's TUN mode needs administrator rights and can internally invoke `sudo` with dynamically constructed arguments.
- Some AdGuard VPN configurations use `SCRIPT` routing mode, which executes a user-supplied routing script. Running the full CLI as root against writable user configuration can therefore expand a narrow VPN permission into arbitrary root code execution.
- A broad `NOPASSWD` sudoers exception, a passwordless rule for `/usr/bin/env`, or unrestricted `systemd1.manage-units` access would be unsafe.
- A root-owned symlink is not enough: on one Fedora installation, `/usr/local/bin/adguardvpn-cli` resolves to `/opt/adguardvpn_cli/adguardvpn-cli`, while both the target executable and its parent directory are owned by the normal user and writable by that user. A privileged helper invoking that target would allow arbitrary root code execution.
- The correct design depends on the AdGuard VPN CLI release, mode, routing configuration, and how its existing user login state is accessed.

## Enforced security boundaries

1. Keep location browsing and ping processing unprivileged. When the protected
   service is installed, its status command runs through the narrow Polkit
   controller and inspects the current systemd journal invocation.
2. Expose only fixed `connect` and `disconnect` operations through an optional root-owned helper, with strictly validated location identifiers and no shell evaluation.
3. Use a dedicated Polkit action to authorize explicitly opted-in, active local users. Never silently authorize every account.
4. Never execute user-writable scripts or binaries with elevated privileges. If the CLI requires scripting, establish a root-owned, reviewed routing configuration first.
5. Use an explicit, trusted path to the installed AdGuard VPN CLI. Do not load executable code from a user's home directory or search an untrusted `PATH` as root.
   The target executable, its containing directory, and all other writable ancestors must be protected from the user authorized to invoke the helper. Prefer a separately managed, verified root-owned copy over altering the ownership of a vendor-managed install in place.
6. Leave the normal AdGuard user profile and corporate VPN configuration
   unchanged. The protected controller uses a **separate** root-owned AdGuard
   login state; never include either profile's credentials in this repository.
7. Limit logs and avoid exposing tokens, environment variables, internal addresses, or full command lines with sensitive parameters.
8. Install only after the user reviews the privilege policy; include a complete uninstall path.

## Read-only compatibility check

On the Fedora system that will run the helper, execute:

```bash
./scripts/diagnose-cli.sh
```

The diagnostic script prints the CLI executable path, version, path ownership, VPN mode, and tunnel routing mode. You can also run the following commands individually:

```bash
command -v adguardvpn-cli
adguardvpn-cli --version
adguardvpn-cli config show | grep -E '^[[:space:]]*(Mode|Tunnel routing mode):'
namei -l "$(readlink -f "$(command -v adguardvpn-cli)")"
```

Do **not** upload your whole AdGuard data directory, login configuration, credentials, or corporate routing scripts. If the routing mode is `SCRIPT`, mention that fact without sharing confidential route details.

## Installation and initial authentication

This is an opt-in feature; only the regular GNOME extension is installed by
`install-extension.sh`. No passwordless Polkit policy exists until the
administrator explicitly installs the helper.

1. Verify that the official detached signature exists:

   ```bash
   ls -l /opt/adguardvpn_cli/adguardvpn-cli.sig
   ```

   The installer copies the original binary and signature to a private staging
   directory **before verifying**. It downloads the public AdGuard key, then
   requires a valid detached signature **and** upstream fingerprint
   `28645AC9776EC4C00BCE2AFC0FE641E7235E2EC6`. It will not install without
   verification. If your network blocks the keyserver, supply a downloaded
   public key using `--key-file /path/to/public-key.asc` (the same pinned
   fingerprint is still required).
2. Install for the intended local GNOME username:

   ```bash
   sudo ./scripts/install-helper.sh "$USER"
   ```

   `$USER` must be the local account that should control the VPN from GNOME.
   This command
   copies the verified official binary to a **root-owned separate directory**,
   creates a private root profile, and installs a Polkit policy authorized only
   for that local user's **active desktop session**. It does not grant
   passwordless access to generic sudo, systemctl, env or arbitrary CLI flags.
3. Log in once to the separate profile:

   ```bash
   sudo ./scripts/login-helper.sh
   ```

   The script executes AdGuard's normal interactive `login`, selects TUN and
   AUTO routing, and stores the credentials only in the root-owned profile.
   It does **not** copy credentials or exclusions from the normal user profile.
4. Manually disconnect the existing AdGuard user-profile VPN session before
   switching to the helper. Leave the corporate OpenVPN running if needed, but
   verify split routing and DNS on the first protected connection.
5. Test from a **local GNOME desktop terminal**:

   ```bash
   adguardvpn-gnome-ctl status
   adguardvpn-gnome-ctl connect --location Miami
   adguardvpn-gnome-ctl status
   adguardvpn-gnome-ctl disconnect
   ```

   `connect` starts an on-demand **transient systemd service** with
   `adguardvpn-cli connect --no-fork -y`. Starting that process is not proof
   that the VPN handshake completed; check `status` and actual network routes.
6. Reload the GNOME extension (logging out/in if needed). When it detects
   `adguardvpn-gnome-ctl`, it uses the protected service for status,
   connect and disconnect; city/ping listings still use the user CLI.

## Installed files

- `/usr/libexec/adguardvpn-gnome/adguardvpn-cli`: verified, root-owned snapshot.
- `/usr/libexec/adguardvpn-gnome/control`: root-owned Python argument validator.
- `/usr/local/bin/adguardvpn-gnome-ctl`: `pkexec` client.
- `/usr/share/polkit-1/actions/org.gnome.adguardvpn.control.policy`: default-deny action.
- `/etc/polkit-1/rules.d/49-adguardvpn-gnome.rules`: permission for one active local user.
- `/var/lib/adguardvpn-gnome`: root-only AdGuard login/configuration.
- `adguardvpn-gnome.service`: transient systemd unit created on connection,
  not a permanent automatically enabled boot service.

### Fedora 1.8.3 finding: no-fork PID status

A live Fedora test showed a working systemd process with `VPN_SS_CONNECTED` in
the current invocation's journal, but a separate root-profile CLI `status`
reported disconnected and CLI `disconnect` reported the process was not
running. This is consistent with `--no-fork` bypassing the background PID file
expected by AdGuard's separate CLI commands (the exact upstream implementation
is proprietary).

The controller now checks the latest `VPN_SS_CONNECTED` or
`VPN_SS_DISCONNECTED` event **scoped to the current systemd InvocationID**.
This avoids reporting a stale successful connection from a previous run. A
newly started service without an event shows **status unavailable**, not a false
connected state. `disconnect` first attempts the CLI, then stops the known
systemd unit even if the CLI PID lookup failed. SIGTERM shutdown was observed
to produce the normal AdGuard disconnect event and restore the default route.

For `connect --fastest`, the dedicated profile currently exposes the label
`FASTEST` while connected; until the actual city can be extracted reliably,
the GNOME extension does not overwrite its saved last named city with the
literal string `FASTEST`.

## Updating and rollback

The protected executable intentionally does **not** track changes in the
user-writable `/opt` installation. After updating AdGuard VPN CLI normally,
disconnect and rerun `sudo ./scripts/install-helper.sh "$USER"` to update the
verified protected copy.

The installer enforces root ownership and `0700` permissions on the **outer**
`/var/lib/adguardvpn-gnome` directory. It does not require every descendant
created by the AdGuard CLI to have the same owner/mode. The outer directory
prevents unprivileged users from traversing or modifying its contents. This
fixes an overly strict early installer version which refused a legitimate
`/var/lib/adguardvpn-gnome/data` entry. It does not change that entry's rights.

To remove the opt-in feature:

```bash
sudo ./scripts/uninstall-helper.sh
```

This disconnects and removes the protected controller and its policies, but
leaves the private login data at `/var/lib/adguardvpn-gnome` for manual review
and deletion later. The original AdGuard CLI, GNOME extension and corporate
VPN are left intact. The extension falls back to its prior direct-CLI behavior
after reload.

## Compatibility checkpoint

The chosen implementation isolates the root-owned CLI profile and validates
the executable. Do not simply `chown` the current CLI installation as a
workaround: it may break vendor updates and would not address user-writable
configuration. Its `pkexec` policy, systemd transient process behavior,
AdGuard login and route cleanup have been exercised once on Fedora; repeat
these checks for each release and before calling it production-ready.

AdGuard AUTO routing can change system routes and DNS even when this project
does not edit your corporate OpenVPN settings. Root-profile exclusions may
differ from the normal AdGuard profile. Verify corporate access with the helper
connected and disconnect if the split routing breaks. A second AdGuard login
may also count toward the provider's session/device limit.

The protected process is not autostarted after reboot. A direct systemctl stop
or a system shutdown may terminate the service without the helper's explicit
`disconnect`, relying on normal AdGuard process signal handling for cleanup.
Test this behavior on the target Fedora release.

Official references: [AdGuard release signature](https://github.com/AdguardTeam/AdGuardVPNCLI#verify-releases),
[AdGuard TUN modes](https://adguard-vpn.com/kb/adguard-vpn-for-linux/settings/),
[systemd-run](https://www.freedesktop.org/software/systemd/man/latest/systemd-run.html),
[Polkit pkexec](https://polkit.pages.freedesktop.org/polkit/pkexec.1.html).

