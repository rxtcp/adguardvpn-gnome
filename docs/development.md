# Development and verification

## Source layout

| Path | Responsibility |
| --- | --- |
| `src/extension.ts` | GNOME enable/disable and panel integration. |
| `src/prefs.ts` | Standard, separate GNOME extension preferences entry. |
| `src/domain/` | Typed values, CLI output parsing, location grouping/sorting and preference validation. No GNOME imports. |
| `src/platform/` | Executable discovery, GLib preference files, bounded/cancellable Gio subprocesses and terminal fallback. |
| `src/application/connection-controller.ts` | Connect, disconnect and switch sequencing, with direct/protected error handling. |
| `src/application/status-monitor.ts` | Eight-second polling, confirmed connection state and startup/status grace periods. |
| `src/application/location-selection.ts` | Saved default, country resolution and display labels. |
| `src/application/server-catalog.ts` | Unprivileged listing and country-specific latency selection. |
| `src/ui/` | GNOME toggle/indicator, menu header, navigation and scrollable server buttons. |
| `src/domain/site-routing*.ts` | Typed Site Routing models, exact host parsing and validation of unknown API responses. |
| `src/platform/routing-client.ts` | Cancellable asynchronous system D-Bus JSON client. |
| `src/application/routing-controller.ts` | Preferences operations, confirmation and stale-response suppression. |
| `src/ui/site-routing/` | GTK4/libadwaita page, accessible rule rows and complete migration dialogs. |
| `extension/` | Metadata, documentation and icon copied into the build. |
| `helper/control.py` | Existing self-contained privileged entry point, kept in Python. |
| `site_routing/` | Independent Python policy manager: planning, DNS, discovery, owned kernel policy, persistence, migration and D-Bus authorization. |
| `routing_system/` | Protected bootstrap, early guard/daemon units and separate bus/Polkit integration. |

The helper deliberately remains a single independently installed program: its
root ownership checks, fixed executable paths and import boundary do not gain
new runtime dependencies as part of this UI refactoring.

Site Routing deliberately has a separate installed package, state directory
and dependency boundary. Its optional installer supplies native Gio/GLib,
dnspython and idna through Fedora packages. The original helper remains
self-contained. See [site-routing.md](site-routing.md) for the trust boundary,
guard-before-allow sequence, known-IP limits and installation/removal.

`kernel_plan.py` isolates ordinary unapproved destination overlaps while
planning owned objects; `kernel_changes.py` applies destinations independently
and retains partial-write intent. `kernel.py` owns system inspection and the
shared firewall boundary. Shared ownership/firewall failures remain global
stops. `reconciliation_status.py` maps per-address outcomes and migration
context; `reconciliation_log.py` records meaningful root-journal transitions.

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
has integration tests. Site Routing removal is also exercised with an inert
command harness: nonempty state, explicit release, retained guards on failure,
missing installation and untrusted launcher checks. Privileged installers are
not executed as root by the unit suite; coverage percentages describe the
compiled extension and all Python helpers/manager/bootstrap,
not privileged shell installation, external GNOME libraries or the vendor CLI.

```bash
npm ci
npm run typecheck
npm test
npm run test:coverage
# System Python must provide Gio/GLib (Fedora: python3-gobject; Ubuntu: python3-gi).
python3 -m venv --system-site-packages .tmp/python-env
.tmp/python-env/bin/python -m pip install -r requirements-dev.txt
PYTHONDONTWRITEBYTECODE=1 .tmp/python-env/bin/python -m coverage run -m unittest discover -s tests -v
.tmp/python-env/bin/python -m coverage report
```

The native GVariant tests use real Gio/GLib types with an injected fake bus;
they never contact the host system bus. Other Python tests inject clocks,
resolvers, executors and kernel adapters, with real private temporary files.
They include partial writes, pending-object recovery, missing IPv6, shared-IP
conflicts, ambiguous discovery, Polkit refusal, shutdown races, DNS retention
and stale migration backups. `.coveragerc` includes all three Python packages;
new manager code must not be hidden behind helper-only coverage.

The `routing-namespace` CI job additionally runs the actual Linux `ip` and `nft`
programs with synthetic interfaces in a disposable network namespace. Its test
entry is `tests/site_routing_namespace.py`, intentionally outside ordinary
`test_*.py` discovery. It refuses root execution without a distinct parent
namespace marker. Each case creates a fresh child namespace using Python
3.12+ `os.unshare`. To reproduce on a disposable Linux test host with `iproute2`,
`nftables` and system `idna` installed:

```bash
parent_namespace="$(readlink /proc/self/ns/net)"
sudo env SITE_ROUTING_PARENT_NETNS="$parent_namespace" unshare --net \
    /usr/bin/python3 -m unittest discover -s tests -p site_routing_namespace.py -v
```

Do not invoke the test directly in the host namespace. The runtime may also
deny namespace/netlink capabilities; use CI or an authorized disposable host
in that case. This test needs no internet peers or proprietary VPN client.
It does not establish the real Fedora acceptance criteria.

Recovery regressions use the actual manager and kernel backend with a
deterministic kernel adapter, including a protected migration alongside an
independent domain, stale public `active` at retirement, changed TUN source/index,
priority changes without dropping stable lookups, partial cleanup and retained
UI state. Diagnostic tests check fresh provider/routes, timestamp and refusal
reason. Root logs identify domain/target/stage and operation category without
raw stderr, URLs, private route arguments or profile settings.

The [VPN underlay prerequisite](vpn-underlay-prerequisite.md) documents
the optional marked OpenVPN packages. The namespace tests characterize
unmarked AUTO lookup and capture marked IPv4 and IPv6 packets and a terminal
deny after route loss. The `openvpn-adapter` CI job applies both patches to
their pinned upstream versions and builds the patched binaries. The live
dual-VPN acceptance run remains open.

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

For Site Routing, execute and record the full
[Fedora acceptance matrix](site-routing-acceptance.md). In particular, verify
boot ordering and measured traffic during disconnects with both real VPNs,
SELinux enforcing and IPv6 enabled before release. The early systemd ordering
and passing namespace job alone do not satisfy AC-11.
