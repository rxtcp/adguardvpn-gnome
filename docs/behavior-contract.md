# Behavior preserved by the refactoring

This contract was recorded against commit `670492a`, before changing production
code. `tests/extension` exercises the original extension through a simulated
GNOME environment, with deterministic subprocesses, filesystem and clock.

| Area | Existing behavior |
| --- | --- |
| Executables | Prefer the CLI on PATH, then `/opt/adguardvpn_cli/adguardvpn-cli`; prefer the installed protected controller over PATH. Only connect, disconnect and status use the protected controller. |
| Preferences | Default to `US`. Read legacy city text and JSON `{location, iso}`. Reject empty, oversized and control-character locations. Save only after a successful direct connection or a confirmed protected status. |
| Locations | Strip terminal control sequences, parse multi-space/tab columns, deduplicate by country code and city, accept decimal points/commas and optional `ms`. Keep missing latency as null. |
| Navigation | Preserve country order. Sort measured cities by ascending latency, then name; put unmeasured cities last. Back remains outside the scrolling area. Reset scroll on navigation and reopening. |
| Connection | Use the saved location for the toggle; disconnect before switching. Selecting the current city does not reconnect. Global fastest uses `connect -f`; country fastest refreshes latency and requires a measured city. |
| Protected commands | Translate `-l` to `--location`, `-f` to `--fastest`; reject unsupported operations. Never send listing commands to the privileged helper. |
| Status | Poll every eight seconds. Parse explicit connected/disconnected output. `FASTEST` confirms a connection without inventing a city. Unknown status retains the last confirmed check/indicator state. |
| Grace periods | For 30 seconds after an accepted connection show `Connecting…` and suppress repeated toggle clicks. Unknown status shows `Checking VPN…` for 12 seconds, then `Status unavailable`. |
| Failures | Protected errors produce notifications. Direct errors open an available terminal, passing location as a positional argument, then notify. A failed disconnect prevents a subsequent connect. |
| Concurrency | Suppress duplicate connection, status, listing and country-fastest operations. Discard a status result while an action or latency lookup is in progress. |
| Processes | Capture stdout/stderr, enforce per-command timeout, force exit on cancellation, release timeout and cancellation handlers on completion. |
| Lifecycle | Disable removes the poll timer, cancels subprocesses and destroys the toggle and indicator. Completion after disable must not update the UI. |
| Privileged helper | Keep Python and its fixed paths/environment, argument allowlist, root/ownership/permission checks, locking, atomic selection persistence, current-invocation journal status and systemd stop fallback. |

The characterization tests intentionally preserve textual status parsing even
when the CLI exit status is nonzero, and preserve the last confirmed indicator
when status becomes unknown. These are existing observable behaviors.

These automated tests do not claim compatibility with every GNOME version or
replace a real GNOME/Polkit/TUN smoke test.
