# SR-UNDERLAY-01: verified VPN control-plane routing

**Status: TUN/AUTO remains open.** For deployments that only need AdGuard for
explicitly assigned sites, the protected AdGuard TUN can run in `NONE` routing
mode. This removes the conflicting AdGuard default policy while Site Routing
continues to select the TUN for known, assigned IPs. The automated namespace
test covers this topology; the Fedora acceptance run remains pending.

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

The current provider model identifies an NM UUID and verified inner tunnel
addresses. It does not establish a current server socket, all selected remotes,
their marks/bindings or an approved underlay connection. Saved remote names
alone are insufficient proof of those facts. Assuming that every VPN should
bypass every other VPN could break an intentional VPN chain. Site rules do not
silently rewrite NM settings, vendor exclusions or unrelated server routes.

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

An integration point for AUTO is a socket mark set by the VPN launcher before
its first route lookup, combined with policy for an explicitly selected
underlay. Standalone OpenVPN exposes `--mark`. The upstream
[NetworkManager OpenVPN launcher](https://github.com/NetworkManager/NetworkManager-openvpn/blob/main/src/nm-openvpn-service.c)
constructs its own argument list and does not forward that option from a saved
VPN profile. The daemon cannot assume a marked socket is available on the
current Fedora setup. Applying an address-only exception or inferring the
process from an ephemeral port would allow other traffic or miss reconnects.

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
