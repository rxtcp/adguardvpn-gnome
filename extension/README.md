# AdGuard VPN Quick Toggle — GNOME

Local GNOME Shell extension for Fedora Workstation.

## Features

- **AdGuard VPN** toggle in GNOME Quick Settings.
- Custom globe icon for the toggle, server menu header, and top panel. The corporate OpenVPN icon is not changed.
- Status updates every eight seconds via `adguardvpn-cli status`, or the optional protected controller if installed.
- While a protected connection is starting, display `Connecting…` instead of an
  ambiguous `Status unknown`. If the service cannot provide a trustworthy
  status after the startup grace period, show `Status unavailable` rather than
  falsely claiming that the VPN is connected. The saved default is updated
  only when the protected service confirms the connected location.
- Compact server labels without unnecessary prefixes or terminal escape codes.
- Country code and city on the toggle, such as `US -> MIAMI`. The server menu header shows `Default: US -> MIAMI`.
- The last connected location and country code are saved across GNOME sessions. Older preferences containing only a city name are supported.
- With no saved history, the initial location is the United States (`connect -l US`). After a successful connection, the last connected location becomes the default.
- Selecting a city does not change the saved default until the connection succeeds. Active CLI connections are also detected via `adguardvpn-cli status` while the extension is running.
- Country and city names come directly from `adguardvpn-cli list-locations`, with no translation.
- Select a country, then a city, using the same scrollable view. The **Back to countries** button stays visible above long city lists.
- A lightning button (⚡) next to each country checks the latest available latency measurements and connects to that country's city with the lowest reported ping.
- The **⚡ Connect to fastest server** action uses AdGuard VPN CLI's built-in `connect -f` option to select the fastest location globally.
- City lists show available ping measurements in milliseconds and sort measured cities from lowest to highest latency. Locations without ping data appear at the end. Country-specific fastest selection reports an error if no valid ping values are available.
- Both country and city lists support mouse-wheel and touchpad scrolling. The scroll area adapts to screen height and resets to the top when navigating or reopening the menu.
- Connect and disconnect using the normal CLI or the optional protected systemd/Polkit controller.
- In direct CLI mode, if the CLI needs a password or reports an error, a terminal opens. In protected mode, errors are shown as GNOME notifications.
- A system panel indicator is displayed while the VPN is connected.

The extension itself does not modify NetworkManager, sudoers, or Polkit settings. The optional helper has a separately reviewed, privileged installer.

**Why sudo may still request a password:** The normal AdGuard VPN CLI uses `sudo` for privileged TUN operations. The project now includes an *experimental*, opt-in protected helper; see `../docs/privileged-helper.md`. Never configure `NOPASSWD: ALL`.

## Installation

Check your GNOME Shell version (the metadata lists GNOME 45–51; these versions
have **not** all been individually tested):

```bash
gnome-shell --version
```

From the repository root, install the extension with:

```bash
./scripts/install-extension.sh
```

Log out of GNOME and log in again. Then enable the extension:

```bash
gnome-extensions enable adguardvpn-toggle@chatgpt.local
```

Open GNOME Quick Settings from the Wi-Fi/sound/power area at the top right. The **AdGuard VPN** toggle should appear.

If the toggle is missing, install the **Extensions** application (`sudo dnf install gnome-extensions-app`) and verify that the extension is enabled.

## Troubleshooting

```bash
gnome-extensions info adguardvpn-toggle@chatgpt.local
journalctl --user -b | grep -i 'AdGuard VPN'
adguardvpn-cli status
```

If permissions are an issue, run `adguardvpn-cli connect` manually in a terminal once and follow AdGuard's prompts. The extension deliberately does not configure unrestricted root access.

The extension was tested manually on one Fedora GNOME desktop, including the
protected connection toggle. Wider compatibility has not been verified.
Publishing to extensions.gnome.org is a **separate** review and submission
process; merely making a GitHub repository public does not submit it there.
