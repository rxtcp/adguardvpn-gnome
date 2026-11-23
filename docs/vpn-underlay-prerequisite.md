# SR-UNDERLAY-01: verified VPN control-plane routing

**Status: open; blocks dual-VPN release acceptance.** Site Routing v1 manages
known addresses of sites inside a selected connection. It does not install
exceptions for the VPN's own server/control connection. This prerequisite is
tracked separately from recovery of per-site routes. AC-06 and the complete
AC-03/04/11 coexistence run must not be declared successful until it is resolved.

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

## Requirements for closing this prerequisite

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
