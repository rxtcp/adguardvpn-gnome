# Site Routing acceptance record

The [specification](site-routing-spec.md) requires a complete bench run and
separate confirmation of AC-03, AC-04, AC-06 and AC-11 on real Fedora before
release. That live acceptance has **not** been performed. This implementation
remains experimental; the table distinguishes executable test evidence from
the remaining platform work. No workstation VPN or routing configuration was
changed during implementation.

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
restoration. The test refuses to run in the parent namespace. These are Linux
policy tests, not an OpenVPN, AdGuard or Fedora boot smoke test.

| Criterion | Automated evidence | Required live Fedora check |
| --- | --- | --- |
| AC-01 | Prefs add flow, IDNA, strict API and owner persistence. | Add through actual GTK and Polkit dialog. |
| AC-02 | Both families planned, kernel route lookup verified in namespace. | Confirm actual selected VPN egress. |
| AC-03 | Interface removed in namespace; RPDB and independent egress guard deny fallback. | **Critical:** disconnect target with second VPN and physical default available. |
| AC-04 | Activated NM snapshot without a real tunnel produces no path. | **Critical:** reproduce stale activated state and observe traffic. |
| AC-05 | UUID survives profile rename and new interface/index; namespace reconnect. | Reconnect real VPN with a different interface name. |
| AC-06 | Dynamic foreign table/priority coexistence, fixed protected-process TUN discovery tests. | **Critical:** reconnect actual AdGuard TUN/AUTO alongside NM VPN. |
| AC-07 | A/AAAA/CNAME TTL, retained old IPs, DNS errors, rate and size limits. | Controlled DNS change with both VPNs and caches. |
| AC-08 | Shared IP and IPv4-mapped IPv6 conflicts never select a winner. | Two test names sharing addresses, different assignments. |
| AC-09 | Physical interface and gateway discovery, explicit route arguments. | Confirm direct egress while both VPNs are active. |
| AC-10 | Removed/private provider retains known addresses with no allow path. | Remove a disposable saved NM profile. |
| AC-11 | Persisted intent, pending-object recovery, early restore order, worker/daemon lifecycle. | **Critical:** restart manager/NM and reboot Fedora; measure early-start traffic. |
| AC-12 | Only exact owned objects deleted; unrelated namespace rule retained. | Confirm unrelated connections after GUI removal. |
| AC-13 | Empty manager/restore path makes no network writes. | Compare actual empty-install networking. |
| AC-14 | Invalid input/UUID/kernel fields rejected before privileged work. | Exercise UI against installed daemon. |
| AC-15 | Actual bus sender, narrow actions and interactive modify flags verified. | Confirm active/inactive/other-user Polkit behavior. |
| AC-16 | DNS/apply/guard failures and stale UI completions never fabricate active status. | Actual command/service failure and visible error. |
| AC-17 | Exact diff, typed NM backup, separate confirmations, stale-write refusal and rollback. | Migrate and roll back disposable host policies; check NM reapplication. |
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
