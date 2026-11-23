# Site Routing acceptance record

The [specification](site-routing-spec.md) requires a complete bench run and
separate confirmation of AC-03, AC-04, AC-06 and AC-11 on real Fedora before
release. A preliminary [Fedora run was reported in review](https://github.com/rxtcp/adguardvpn-gnome/pull/4#issuecomment-7106099077)
and **did not pass acceptance**. It confirmed one offline deny with stale NM
activation, and identified incomplete route recovery/migration and a possible
VPN control-plane underlay problem. Socket egress was not captured, and the
cause of all OpenVPN reconnects/DNS failures remains unproved.

This implementation remains experimental. The table distinguishes executable
test evidence from remaining live work. No workstation VPN or routing
configuration was changed by the implementation tools.

**Blocking prerequisite:** [SR-UNDERLAY-01](vpn-underlay-prerequisite.md).
Site rules do not install VPN server-endpoint exceptions. The intended control
flow underlay, multiple/current remotes and address changes require separate
proof before claiming dual-VPN acceptance.

## Automated evidence

The extension test runner executes compiled TypeScript with deterministic GNOME
and D-Bus adapters. Python tests use temporary state, fake system processes and
real Gio/GLib variants with an injected bus. CI enforces 100% extension
line/branch/function and Python statement/branch coverage, including the new
manager and installed bootstrap; it does not exclude the privileged code.

The separate `routing-namespace` CI job runs the real `ip` and `nft` programs
inside a new root Linux network namespace, using synthetic dummy interfaces
and documentation addresses. It verifies IPv4/IPv6 route selection, terminal
denies after tunnel removal, an independent nftables deny against an earlier
foreign lookup, interface-index replacement, owned cleanup and deny-only
restoration. Separate synthetic corporate/AdGuard interfaces now cover a legacy
conflict beside an independent destination, an actual missing-device write,
continued independent egress and recovery on a new source/interface. Each case
creates its own child namespace and refuses the parent namespace. These are Linux
policy tests, not an OpenVPN, AdGuard or Fedora boot smoke test.

The control-flow lookup reproduction deliberately still selects AdGuard ahead
of physical main-table host routes for two synthetic server endpoints. A green
test documents that prerequisite; it does not certify control-plane protection.

| Criterion | Automated evidence | Required live Fedora check |
| --- | --- | --- |
| AC-01 | Prefs add flow, IDNA, strict API and owner persistence. | Add through actual GTK and Polkit dialog. |
| AC-02 | Both families planned, kernel route lookup verified in namespace. | Confirm actual selected VPN egress. |
| AC-03 | Interface removed in namespace; RPDB and independent egress guard deny fallback. | One offline deny was reported; **critical** repeated disconnect and recovery captures remain required. |
| AC-04 | Activated-without-tunnel has an explicit reason; Check re-reconciles and timestamps its provider/routes. | Reported stale activation was correctly blocked; **critical** synchronized recovery retest remains required. |
| AC-05 | UUID survives profile rename and new interface/index; namespace reconnect. | Reconnect real VPN with a different interface name. |
| AC-06 | Dynamic foreign table/priority coexistence, distinct synthetic tunnels and control-flow lookup reproduction. | **Blocked by SR-UNDERLAY-01:** verify actual AdGuard/NM socket egress and reconnects on Fedora. |
| AC-07 | A/AAAA/CNAME TTL, retained old IPs, DNS errors, rate and size limits. | Controlled DNS change with both VPNs and caches. |
| AC-08 | Shared IP and IPv4-mapped IPv6 conflicts never select a winner. | Two test names sharing addresses, different assignments. |
| AC-09 | Physical interface and gateway discovery, explicit route arguments. | Confirm direct egress while both VPNs are active. |
| AC-10 | Removed/private provider retains known addresses with no allow path. | Remove a disposable saved NM profile. |
| AC-11 | Persisted intent, pending-object recovery, early restore order, worker/daemon lifecycle. | **Critical:** restart manager/NM and reboot Fedora; measure early-start traffic. |
| AC-12 | Only exact owned objects deleted; unrelated namespace rule retained. | Confirm unrelated connections after GUI removal. |
| AC-13 | Empty manager/restore path makes no network writes. | Compare actual empty-install networking. |
| AC-14 | Invalid input/UUID/kernel fields rejected before privileged work. | Exercise UI against installed daemon. |
| AC-15 | Actual bus sender, narrow actions and interactive modify flags verified. | Confirm active/inactive/other-user Polkit behavior. |
| AC-16 | Per-address failures preserve independent paths, pending intent and actionable operation reasons; restored service starts unverified. | Retest with synchronized manager/NM logs and actual sockets. |
| AC-17 | Exact diff/backup; fresh pre/post-retirement proof; refusal reason/stage; independent-rule recovery and rollback. | Reported migration remained protected; repeat retirement/rollback only with a verified replacement. |
| AC-18 | Missing IPv6 path blocks the whole assignment; real IPv6 deny/route tests. | Disable/break IPv6 on the target and inspect actual traffic. |

## Reproduce release validation

Use a disposable Fedora Workstation with a local GNOME session, SELinux enforcing,
an independently managed NM test VPN and an authenticated protected AdGuard
profile. Keep credentials and personal/corporate routes outside this repository.
Install using [site-routing.md](site-routing.md); exercise the matrix with
IPv4/IPv6 enabled and both VPNs independently available.

Record Fedora/GNOME/NetworkManager/CLI versions, nftables/firewall coexistence,
the tested revisions and observed results. For AC-03/04/06/11, observe traffic
from a separate controlled peer or capture point across disconnects and boot;
a post-boot `ip route get` alone cannot establish the absence of an earlier
window. Validate that the guard/NM ordering has no unit cycle on the target,
that SELinux permits the fixed protected-process inspection, and that shutdown
or startup failure leaves protection explicit. Networking in an initramfs
requires additional early protection or a documented failed acceptance result.

Test both uninstall refusal with retained rules and explicit release; restore
legacy settings using the migration rollback before removal when needed.
Do not mark this record complete or publish a release until all rows have live
results and the critical scenarios pass. Attach sanitized evidence only.
