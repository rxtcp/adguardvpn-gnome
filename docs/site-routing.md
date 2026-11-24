# Site Routing: experimental implementation

Site Routing assigns an exact hostname to a saved NetworkManager VPN, the
protected AdGuard VPN, or a verified physical gateway. The independent system
service keeps applying approved rules after preferences and GNOME Shell close.
It never starts a VPN automatically. An unavailable target blocks the rule's
known destination IPs instead of selecting another connection.

**Release status:** automated unit, native GVariant and isolated Linux network
namespace tests are available. The complete Fedora acceptance run, including
reboot and AdGuard TUN/AUTO coexistence, has not been performed for this feature.
Treat it as experimental. See [the acceptance record](site-routing-acceptance.md)
and [the original specification](site-routing-spec.md).

A preliminary [Fedora review run](https://github.com/rxtcp/adguardvpn-gnome/pull/4#issuecomment-7106099077)
confirmed one offline-deny snapshot but did not pass dual-VPN acceptance.
[SR-UNDERLAY-01](vpn-underlay-prerequisite.md) tracks the VPN server/control
connection while AdGuard controls the default policy in TUN/AUTO. If AdGuard
is only needed for assigned sites, the optional
[TUN/NONE setup](vpn-underlay-prerequisite.md#site-only-adguard-routing-with-tunnone)
preserves ordinary routing for other traffic, including OpenVPN's server
connection if its endpoint is not covered by a site rule.

## What protection means

Rules operate on the A/AAAA addresses resolved by the controller. They affect
traffic to those IPs from the whole machine, including other applications and
users. A shared IP can affect unrelated hostnames. Assigning the same IP to
different targets blocks that IP and reports a conflict.
The same IP also stays blocked when another rule requires it to be blocked,
for example because that rule's IPv6 path is missing. A dependent hostname is
reported as a shared-IP conflict, never as `active` while the IP is denied.

This is not absolute domain isolation. Application DoH/DoT, unknown cached
answers and new DNS addresses before synchronization are outside the guarantee.
Only the exact hostname is covered; its subdomains need separate rules. A URL
path is not a routing boundary: `https://one.example/private/path` creates a rule
for the entire `one.example` host. IP literals, wildcards, network ranges and
credentials in URLs are rejected. International names are normalized to IDNA.
For names containing Unicode joining characters, enter their canonical `xn--`
form; the UI refuses a conversion that could silently remove those characters.

The service queries A and AAAA, follows CNAME answers and uses the smallest
answer/CNAME TTL. It refreshes after expiry and network/provider events, with
a ten-second recovery timer and a five-second minimum between attempts for
each rule. TTLs are bounded to 5–3600 seconds; failures retry after 30 seconds.
Old answers remain protected until the rule is explicitly removed. This avoids
releasing a cached address during DNS failure, but can retain obsolete addresses.

There are at most 128 rules, 256 retained addresses per rule and 4096 tracked
addresses globally. Limit errors are explicit; reducing a retained set requires
reviewing and removing the rule, which releases its protection.

An active NM provider's advertised DNS servers are preferred. When unavailable,
including an inactive VPN, the system resolver is used. AdGuard uses the active
system resolver; its proprietary private configuration is not parsed or edited.
A failure from selected VPN DNS does not trigger a silent resolver fallback.
The path and confidentiality of DNS queries are not independently guaranteed.

## Install

First install the extension using the [main README](../README.md#installation).
For the AdGuard target, also install and authenticate the existing
[protected helper](privileged-helper.md). Direct and NM rules do not need that
helper. This feature does not use an ordinary user-profile AdGuard connection
as a privileged provider.

On the Fedora test machine, review the scripts and policy, then run these from
the repository root:

```bash
sudo dnf install python3-gobject python3-dns python3-idna iproute nftables
sudo ./scripts/install-site-routing.sh
```

This installs the routing daemon, the early guard, a NetworkManager ordering
drop-in, D-Bus integration and a separate Polkit policy. It enables the two
services and starts them. It does not restart NetworkManager, connect a VPN or
change routes for an empty configuration. The extension installer alone does
not install this system component.

Open **Site Routing…** in the toggle's menu, or run:

```bash
gnome-extensions prefs adguardvpn-toggle@chatgpt.local
```

Enter a URL or exact FQDN, review the normalized host, select a target and press
**Add**. Saved inactive NM profiles are assignable. Names are display labels;
assignments follow UUIDs through profile and interface renames. WireGuard must
also have peer AllowedIPs covering every known destination.

Each add, reassignment, deletion or migration step requires a fresh Polkit
administrator authorization. Background restoration of previously approved
rules does not request another password. Reading one's own rules in the active
local session does not request a password. These permissions are separate from
the optional passwordless AdGuard connect/disconnect permission.

**Edit** changes the target and keeps the hostname fixed. To change a hostname,
create another rule and explicitly remove the old one. **Remove** warns that
the known addresses return to ordinary system routing, potentially through
another VPN or the physical connection. **Check** shows known addresses and
any eligible migration diff and the observed kernel routes. Check first
reconciles the approved rules using cached DNS, then reports the checked-at
time and provider snapshot. It distinguishes NM activated-without-tunnel from
a disconnected profile and shows the last migration refusal. External NM/kernel
state can still change between system calls or after the check; a timestamp is
not a claim of an atomic whole-system capture.

The list refreshes asynchronously every five seconds and includes per-family
counts and the last successful DNS update. A restarted manager initially shows
restoration in progress, rather than publishing a saved `active` label before
rechecking the routes.

If rule cleanup fails, removal reports the failure and keeps the previous rule
visible with its protection and pending intent. Independently verified rules
continue. Resolve the reported condition before retrying removal.

| State | Meaning |
| --- | --- |
| `active` | Every known destination has a verified route through the target. |
| `blocked-offline` | No verified target path for every required family, or WG peer coverage is incomplete. Known IPs are blocked. |
| `resolving` | DNS resolution is in progress. |
| `dns-error` | Resolution failed; previous addresses and their protection are retained. |
| `conflict` | Targets disagree about an IP or an unmanaged destination policy needs review. |
| `apply-error` | Application failed. Read the detail; if guard installation failed, protection is explicitly unconfirmed. |
| `provider-missing` | The saved provider was removed or is no longer accessible. Known addresses stay blocked. |

Ordinary unmanaged destination overlaps and per-destination command/verification
failures quarantine the affected IPs. Independently verified destinations retain
their allow paths; unchanged paths keep a lookup while policy priorities move.
Missing interfaces and partial writes retain known-IP guards and pending owned
objects, which reconciliation retries after the tunnel returns with a new
source address/name/index. A shared firewall failure, unsafe priority allocation
or foreign object in a reserved owned table remains a conservative global stop.

`active` verifies routing, not that a particular remote application is healthy
or that every future DNS answer is already known. IPv4 is not left partly active
when a known AAAA destination cannot be protected through its target.

## Existing manual NM host policies

The daemon does not automatically adopt or delete foreign routes or rules.
An overlapping destination policy blocks application and requires review.

1. Use **Check** to inspect the complete diff. Only exact host routes and simple
   destination rules that match accessible saved NM settings are eligible.
   Tables, priorities, selectors and, for routes, interface/gateway/source/metric
   must match. Broader networks, ambiguous defaults and complex selectors
   require manual administrator review.
2. **Install protected replacement** authorizes the reviewed plan, retaining
   existing NM entries and saving a private, hashed backup of non-secret settings.
3. Verify the protected target and both VPNs. **Remove listed legacy entries**
   requires a separate confirmation. It freshly verifies every replacement
   route through the saved target's table before and after retiring entries,
   including the kernel's selected source address, even if a prior snapshot was
   `active`, and deletes only the reviewed entries. Only the migration's
   destinations are denied during that transaction; independent allow paths
   are preserved when their current kernel route can be reverified.
4. **Roll back migration** restores only a matching before/after NM configuration
   and the reviewed kernel objects, then removes the replacement rule. This
   explicitly returns the hostname to its previous routing behavior.

If NM settings changed after preview, automatic overwrite is refused. Partial
failure retains the backup and guards and offers retry/rollback. A missing
profile requires administrator review; the service does not invent a replacement
profile. Reassignment is a separate operation. Changing or removing the saved
assignment invalidates its overlap approval while preserving the backup. No
`GetSecrets` call is made and diagnostic responses do not expose
whole profiles, private URL paths or credentials. Do not publish diagnostics
containing your real domains or routes.

A refused retirement keeps its existing stage (for example, `protected`) and
records the reason in **Check**. A target disappearing during removal records
`failed` with the backup and guards retained. Restoration of a verified tunnel
allows automatic site-route recovery and a separately confirmed retry. An
unsupported migration preview does not hide current provider/route diagnostics.

The system journal records canonical domain, stable target ID, state, migration
stage, route-binding changes and bounded operation reasons. Raw stderr, command
arguments, profile settings/diffs, credentials, packet contents and URL paths
are not logged. These records still identify private domains; redact them
before sharing. See [the synchronized capture plan](vpn-underlay-prerequisite.md#collect-a-synchronized-redacted-bench-record).

## Update

Update the checkout, rebuild/reinstall the extension and rerun
`sudo ./scripts/install-site-routing.sh`. The routing installer preserves the
private journal, stops only its manager and restores guards before restarting
that manager. AdGuard authentication remains a separate helper procedure.

## Uninstall and retained data

If removing all components, remove Site Routing **before** the protected helper
and extension. Disabling or uninstalling the extension alone leaves its system
rules and protection running.

Prefer removing rules with the UI first, reviewing any migration rollback, then:

```bash
sudo ./scripts/uninstall-site-routing.sh
```

By default this refuses to uninstall while rules or known-address protection
remain and restarts the manager after that refusal. To explicitly release
**all users'** Site Routing rules and return those destinations to ordinary
system routing instead:

```bash
sudo ./scripts/uninstall-site-routing.sh --release-rules
```

That option is a deliberate administrative change in routing, not a migration
rollback. It does not restore retired manual NM entries; use the UI rollback
before uninstalling if those are wanted. Only owned routes, RPDB rules, nftables
table and integration files are removed. If cleanup cannot be verified, the
script stops and retains the guards and service files. Review the failure and
restart `adguardvpn-site-routing.service` for recovery; do not delete the journal
or flush firewall/routing tables to bypass the refusal.

After successful removal, the journal, previous state and migration backups
remain in the private directory `/var/lib/adguardvpn-site-routing`. If no longer
needed, permanently remove them:

```bash
sudo rm -rf -- /var/lib/adguardvpn-site-routing
```

This directory is independent of `/var/lib/adguardvpn-gnome`, which contains
the protected AdGuard login. Continue with the main README's helper/extension
removal instructions. Neither uninstaller removes the vendor CLI or its normal
user profile.

## System boundary and recovery

The root-owned launcher at `/usr/libexec/adguardvpn-site-routing/launch.py` is
run with `/usr/bin/python3 -I -B`; it verifies its installed package before
importing it. State is private, versioned, locked and atomically replaced with
a verified previous copy. Corruption is an error, never an empty configuration.
The independent state directory also keeps existing helper updates compatible.

The D-Bus API accepts only six structured operations: list providers/rules,
add/update/remove a rule and diagnose it. The server derives ownership from
the unique bus caller; clients cannot supply UIDs, interface names, executables,
table IDs or shell text. System commands have fixed paths and argument arrays.

The backend journals known-address intent and pending objects before writes.
It installs a dual-family nftables destination/interface-index guard before
allowing routes, chooses unused tables and priorities after examining the live
policy, and installs terminal unreachable rules behind each owned lookup.
Kernel snapshots request numeric IDs, so administrator-defined table/protocol
aliases cannot hide an occupied table or change an approved object's identity.
Every destination is checked using kernel route lookup and actual interface
index/source state before its egress is allowed. Direct uses a physical gateway,
not an assumption that the main table bypasses VPNs. Only exact owned objects
are cleaned up; a foreign object in an owned table stops reconciliation.

The manager uses `CAP_NET_ADMIN` for its policy and `CAP_SYS_PTRACE` to inspect
TUN descriptors of the fixed, verified protected AdGuard process. There is no
client-selected PID or ptrace operation. The early guard needs only
`CAP_NET_ADMIN`, has no DNS dependency, and orders NetworkManager after restoring
persisted known-address denies. Restarted managers begin with that deny-only
guard; discovery and reconciliation happen afterwards.

The ordering is implemented but real Fedora boot protection is unverified.
Networking already established in an initramfs, a firewall reload by another
administrator, or a service/guard startup failure needs separate platform
validation. Do not declare AC-11 satisfied from unit ordering or a namespace
test alone. Root administrators remain able to replace the policy.
