# SR-UNDERLAY-01: verified VPN control-plane routing

**Status: opt-in TUN/AUTO adapter; live Fedora acceptance pending.** The adapter
scopes the external OpenVPN transport to a reviewed NetworkManager base profile.
The installed distribution packages need the two compatibility patches below.
For site-only AdGuard routing, the protected TUN can instead run in `NONE` mode.

## Marked OpenVPN transport with TUN/AUTO

The adapter is for a directly connected OpenVPN client launched by NetworkManager
on one administrator-approved Ethernet or Wi-Fi profile. The administrator
selects both profiles by UUID. Site Routing does not activate either VPN.
Other profiles use the distribution launch path. The adapter currently uses
userspace OpenVPN and refuses HTTP/SOCKS proxy profiles.

1. On a disposable Fedora bench, build and install the Fedora RPMs with both
   repository patches applied. Use the source packages for the matching Fedora
   builds of [NetworkManager-openvpn 1.12.0](https://github.com/NetworkManager/NetworkManager-openvpn/tree/1.12.0)
   and [OpenVPN 2.6.14](https://github.com/OpenVPN/openvpn/tree/v2.6.14).
   Add the corresponding [NetworkManager-openvpn patch](../packaging/NetworkManager-openvpn-1.12.0-site-routing.patch)
   or [OpenVPN patch](../packaging/openvpn-2.6.14-site-routing.patch) as a source RPM
   patch and apply it during the RPM prep step (`-p1`). Increase the local
   release number so the rebuilt RPMs can be distinguished from stock packages.
   Install the matching RPMs using the package manager and retain the stock
   packages for rollback. The OpenVPN build must use Linux `SO_MARK` and
   libcap-ng. The patched NM launcher requires `[SiteRouting-SO_MARK]` in the
   resolved OpenVPN binary's `--version` output before accepting opted-in launches.

2. Install Site Routing normally. Disconnect the test OpenVPN profile and leave
   protected AdGuard in `TUN/AUTO`. Choose the approved physical test connection.
   Record the profile's current static routes, route-table and policy rules for rollback.
   Reserve table 39990 for this connection and check both families for competing
   rules at priorities 1–11. Priority 0 belongs to Linux's local table. Site
   Routing's exact per-site rules may precede the marked rules.

   With stable, verified on-link gateways, add defaults to the dedicated table
   while keeping the profile's ordinary defaults in place. Use the address
   family or families available on this uplink. In particular, preserve the
   ordinary route that protected AdGuard itself uses to reach its servers.

   ```bash
   sudo nmcli connection modify uuid "$UPLINK_UUID" +ipv4.routes "0.0.0.0/0 $IPV4_GATEWAY table=39990 onlink=true"
   sudo nmcli connection modify uuid "$UPLINK_UUID" +ipv6.routes "::/0 $IPV6_GATEWAY table=39990 onlink=true"
   ```

   If the uplink gateways change through DHCP or RA, an administrator can
   instead put its NM-managed routes in table 39990 via `ipv4.route-table` and
   `ipv6.route-table`. This can move an existing default out of `main`. Use this
   arrangement only when the deployment provides ordinary IP and DNS
   connectivity separately, including the AdGuard server path. Site Routing
   never changes those settings automatically.

3. Install the following JSON at
   `/etc/adguardvpn-site-routing/openvpn-underlay.json`. The parent directory
   must be root-owned and non-writable by other users. The file must be a
   regular root-owned file with mode `0600`. Replace the example UUIDs with the
   OpenVPN and approved physical profile UUIDs.

   ```json
   {
     "vpn": "00000000-0000-4000-8000-000000000001",
     "uplink": "00000000-0000-4000-8000-000000000002"
   }
   ```

4. Apply the marked rules. The early guard restores them on subsequent boots.
   Activate the approved physical profile with its revised route settings.
   Activate OpenVPN manually using that device as its base. For example:

   ```bash
   sudo /usr/bin/python3 -I -B /usr/libexec/adguardvpn-site-routing/launch.py apply-underlay
   nmcli connection up uuid "$VPN_UUID" ifname "$UPLINK_INTERFACE"
   ```

   The launcher checks NetworkManager's actual base activation, its device and
   usable defaults in the dedicated table before passing `--mark` and
   `--bind-dev` to OpenVPN. Both are applied before the first route lookup.
   Recreated sockets retain the capability to set them and OpenVPN aborts if
   either setting fails. An uplink that reappears on another interface name
   needs a fresh NM VPN activation to bind to the newly verified device.

For the reserved mark `0x53495445` in both families, priority 10 looks up
table 39990 and priority 11 returns `unreachable` if no route matches. The
physical profile owns its routes and removes them on deactivation. The
protected service owns only the two exact marked rules per family (protocol
197). Site Routing keeps its known-address policy in front of those rules. If a
server address also belongs to a known Site Routing assignment incompatible
with the approved uplink, that connection remains blocked, including during
tunnel loss. No server address or port is added to the routing policy.

This protects the OpenVPN transport. Bootstrap DNS (for example via
`systemd-resolved`) and DNS for pushed route names still use the applicable
resolver policy. Verify both independently. Verify actual socket egress with
the [bench record](#collect-a-synchronized-redacted-bench-record) before
deploying the marked profile.

### Roll back TUN/AUTO integration

Disconnect the opted-in OpenVPN and verify the process has stopped. Remove or
archive the private JSON, then remove the exact marked rules:

```bash
sudo /usr/bin/python3 -I -B /usr/libexec/adguardvpn-site-routing/launch.py remove-underlay
```

Restore the physical NM profile's previous routing settings. A stock package
rollback can then restore the original launcher and OpenVPN binary. Uninstall
of Site Routing refuses while the opt-in configuration or owned marked policy
still exists. The removal command leaves the dedicated table to NetworkManager.

## Site-only AdGuard routing with TUN/NONE

Use this option if the intended underlay for OpenVPN is already selected by
ordinary system routing and you want unassigned traffic to keep following that
routing. In `NONE`, AdGuard brings up its TUN without taking over the default
route. System-wide AdGuard routing is lost in this mode. Site Routing still
needs the optional routing service and the authenticated protected helper.
The setting applies to the separate protected profile only. DNS settings are
separate and should be checked on the Fedora bench.

1. Disconnect the protected VPN with `adguardvpn-gnome-ctl disconnect` and
   confirm it is disconnected. Leave it stopped during configuration.
2. In a terminal, use the following function with the installed, signed,
   root-owned helper copy. Review the current mode first. Use `NONE` only if
   site-only routing is appropriate for this machine.

   ```bash
   protected_adguard_config() {
       sudo /usr/bin/env -i \
           HOME=/var/lib/adguardvpn-gnome \
           XDG_CONFIG_HOME=/var/lib/adguardvpn-gnome/config \
           XDG_DATA_HOME=/var/lib/adguardvpn-gnome/data \
           XDG_CACHE_HOME=/var/lib/adguardvpn-gnome/cache \
           USER=root LOGNAME=root LANG=C.UTF-8 \
           PATH=/usr/sbin:/usr/bin:/sbin:/bin \
           /usr/libexec/adguardvpn-gnome/adguardvpn-cli config "$@"
   }
   protected_adguard_config show
   protected_adguard_config set-tun-routing-mode NONE
   ```

3. Reconnect protected AdGuard and OpenVPN. In **Check**, confirm each assigned
   site uses its target and verify actual OpenVPN server egress using the bench
   record below. Check the failover remote and confirm an unassigned site uses
   the intended ordinary path. An address that is also a known site IP still
   has that site's policy, so this option requires distinct server and protected
   site IPs.
4. To restore the previous routing mode, disconnect the protected VPN again,
   run `protected_adguard_config set-tun-routing-mode AUTO` if `AUTO` was the
   previous value, and reconnect. The helper login script selects `AUTO` again
   if rerun. To remove Site Routing in `NONE` mode, account for the fact that
   removed assignments return to ordinary routing. See [removal](site-routing.md#uninstall-and-retained-data).

The isolated test models the vendor mode by removing its default policy with
the TUN still present. It captures IPv4 and IPv6 UDP on the ordinary uplink for
two remotes per family, including a changed address and port, and verifies
that assigned sites keep their selected route or remain blocked after tunnel
loss. It uses synthetic interfaces and no vendor executable.

Reference: [AdGuard CLI routing modes](https://adguard-vpn.com/kb/adguard-vpn-for-linux/settings/#vpn-tunnel-routing-mode-none-auto-or-script).

## Evidence and scope

The [Fedora review finding](https://github.com/rxtcp/adguardvpn-gnome/pull/4#issuecomment-7106099077)
reported an OpenVPN UDP flow whose ordinary kernel lookup selected protected
AdGuard's table before the physical main table. Both current server endpoints
were affected. Actual socket egress was not packet-captured, so interface binding,
socket marks and namespace context remain relevant. OpenVPN restart and pushed
route-name DNS failures were also observed; their causes have not been proved
to be the same.

The namespace regression now uses separate synthetic corporate and AdGuard
interfaces. It reproduces table 880 before main, a source-port exemption that
does not match the synthetic control flow, and two server addresses with
physical host routes in main. A lookup for each control flow still selects the
AdGuard interface. This is an executable reproduction of the prerequisite,
**not a passing control-plane protection test**. Per-site conflict isolation,
device-loss recovery and verified egress are tested independently.

The ordinary provider model identifies an NM UUID and verified inner tunnel
addresses. The optional marked launcher uses the separate trusted NM activation
and a root-owned decision about the intended base. The mark follows all socket
recreations for the direct transport. Actual server selection and packet
egress still need capture on the supported bench.

## Requirements for retaining TUN/AUTO

1. Establish the intended underlay from trusted NM activation state and an
   explicit, reviewed policy. Preserve stable NM identities through physical
   network changes; do not treat main or a fixed interface name as proof.
2. Discover and verify the actual selected server flow and all configured
   failover candidates. Handle UDP/TCP, ephemeral source ports, IPv4/IPv6,
   multiple remotes, remote reselection and DNS address changes. Honor observed
   interface/source binding, marks and network namespaces. No production server
   IP or port may be hard-coded.
3. Apply only the authorized control-plane scope. A broad destination exception
   can also affect applications sharing a server IP; its interaction with site
   rules, other users and deliberate VPN chains needs a specified policy.
4. Preserve known-site denies when the target tunnel is absent. Supporting a
   manually initiated VPN control connection must not automatically activate
   that VPN or release its site traffic to another connection.
5. Keep exact ownership, guard-before-allow, private intent, reviewed rollback
   and narrow Polkit authorization. An API change requires separate review;
   clients must not gain arbitrary IP/interface/table/PID/command parameters.
6. Verify actual socket egress and recovery on the supported Fedora bench with
   both VPNs, including multiple remotes and a changed remote address/port.
   Repeat disconnect, stale-activation, reconnect and reboot acceptance.

The marked adapter addresses the routing and launcher part of these
requirements for the documented direct OpenVPN topology. The final acceptance
step remains open for patched RPMs with protected AdGuard on Fedora.

## Collect a synchronized, redacted bench record

On an authorized disposable Fedora setup, collect the following together:

- NM profile UUID, activation/base connection, current state and actual kernel
  interface/index/source addresses. Distinguish activated-without-tunnel from
  a verified tunnel.
- Preferences **Check** output: checked-at time, provider reason, known address
  counts, observed per-address routes, migration stage and last refusal.
- Precise-time manager, NM and OpenVPN journal events. The manager records the
  affected canonical domain, stable target ID, state, migration stage, binding
  change flag and bounded operation reason. It omits raw command arguments,
  settings, keys, full URLs and packet contents.
- Each actual control socket's destination, protocol, source/remote port,
  source/interface binding, mark and namespace. Query the route with the same
  flow selectors; a bare destination lookup is not sufficient.
- A simultaneous packet capture at controlled interfaces/peers. Route lookup
  is evidence of normal kernel selection, not proof of a particular socket's
  actual egress. Correlate tunnel recreation, DNS changes and packet timing.

For example, the local manager journal can be read with:

```bash
sudo journalctl -u adguardvpn-site-routing.service -b \
    --since '5 minutes ago' -o short-precise
```

Keep captures and complete diagnostics off the public repository. Redact real
domains, endpoints, UUIDs and internal routes before sharing an extract. Do not
install ad-hoc endpoint exceptions or delete legacy NM policies as a diagnostic
step; use the reviewed migration/rollback flow only after replacement proof.

Reference contracts: [NM active connections](https://networkmanager.dev/docs/api/latest/gdbus-org.freedesktop.NetworkManager.Connection.Active.html)
and [OpenVPN socket/remote options](https://openvpn.net/community-docs/community-articles/openvpn-2-7-manual/).
