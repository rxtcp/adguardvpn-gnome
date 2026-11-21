# Development and verification

## Source layout

| Path | Responsibility |
| --- | --- |
| `src/extension.ts` | GNOME enable/disable and panel integration. |
| `src/domain/` | Typed values, CLI output parsing, location grouping/sorting and preference validation. No GNOME imports. |
| `src/platform/` | Executable discovery, GLib preference files, bounded/cancellable Gio subprocesses and terminal fallback. |
| `src/application/connection-controller.ts` | Connect, disconnect and switch sequencing, with direct/protected error handling. |
| `src/application/status-monitor.ts` | Eight-second polling, confirmed connection state and startup/status grace periods. |
| `src/application/location-selection.ts` | Saved default, country resolution and display labels. |
| `src/application/server-catalog.ts` | Unprivileged listing and country-specific latency selection. |
| `src/ui/` | GNOME toggle/indicator, menu header, navigation and scrollable server buttons. |
| `extension/` | Metadata, documentation and icon copied into the build. |
| `helper/control.py` | Existing self-contained privileged entry point, kept in Python. |

The helper deliberately remains a single independently installed program: its
root ownership checks, fixed executable paths and import boundary do not gain
new runtime dependencies as part of this UI refactoring.

The TypeScript compiler uses `strict`, `noUncheckedIndexedAccess`,
`noImplicitOverride`, unused-symbol checks and `noEmitOnError`. GNOME API types
come from pinned `@girs` development dependencies. Generated JavaScript retains
the `gi://` and `resource:///` imports and ordinary relative ES module imports;
there is no Node.js runtime or bundler inside GNOME. The types describe GNOME
51; this is a compile-time check, not a claim of live compatibility across all
versions in `metadata.json`. Declaration dependencies use `skipLibCheck`;
application source remains strictly checked.

## Test-first history

1. The behavior contract and 40 JavaScript/23 Python characterization tests
   were committed while `extension/extension.js` was still the unchanged
   production entry point from `670492a`.
2. The extension was split into TypeScript modules. The same assertions run
   against the compiled entry point; the test loader resolves module imports
   instead of exposing functions from the original monolith.
3. Additional failure, lifecycle, boundary and archive tests enforce full
   coverage of executable extension code and the Python controller in CI.

The extension tests use Node's test runner and VM ES modules, with a fresh
simulated GNOME environment for each scenario. They execute the actual compiled
extension, callbacks, subprocess orchestration and lifecycle. Assertions focus
on arguments, results, notifications, visible state and persisted preferences.
Deferred subprocess completion and a controlled monotonic clock test races,
timeouts and exact grace-period boundaries without sleeping or using a VPN.

The Python tests mock privileged calls. Filesystem tests use temporary paths;
they verify path trust, argument validation, atomic replacement, environment,
current-invocation journal queries, systemd failures and lock dispatch. Archive
tests run the real installer with a fake `gnome-extensions` command, inspect the
ZIP and resolve every relative JavaScript import inside it.

Shell scripts receive syntax checks and the extension install/uninstall path
has integration tests. The privileged installer is not executed as root by the
suite; coverage percentages describe the extension and Python controller,
not privileged shell installation, external GNOME libraries or the vendor CLI.

```bash
npm ci
npm run typecheck
npm test
npm run test:coverage
python3 -m pip install -r requirements-dev.txt
PYTHONDONTWRITEBYTECODE=1 python3 -m coverage run -m unittest discover -s tests -v
python3 -m coverage report
```

## Desktop smoke test

After `./scripts/install-extension.sh`, log out/in and enable the extension.
Check the toggle, globe icon and country/city navigation, including scrolling
and the Back button. Connect directly, switch locations, select global/country
fastest, disconnect, then disable/re-enable the extension. Verify saved defaults
after a new login and inspect the Shell journal for errors.

Repeat with the optional protected helper: startup must show `Connecting…`,
must suppress repeated toggle clicks, and must save the new default only after
confirmed status. Check TUN, routing and DNS with the real service. Preserve
the existing helper installation and authentication procedure documented in
[privileged-helper.md](privileged-helper.md).

Automated tests do not establish GNOME ABI compatibility, Polkit authorization,
real CLI output on every release, or live network/tunnel behavior.
