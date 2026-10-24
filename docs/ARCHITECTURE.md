# trestle architecture

## Source layout

```
src/common/   shared by client and daemon
  md5.c         RFC 1321 MD5 (naming only, FIPS-safe because it is not a crypto provider)
  config.c      INI parser, [global] / [network:NAME], conf.d merge, validation
  request.c     CNI / Netavark argument and JSON validation, error formatting
  proto.c       wire protocol and SCM_RIGHTS fd passing
  naming.c      tbr/trv names, aliases, .trestle host names
  util.c, log.c
src/client/   trestle (plugin binary)
src/server/   trestled
  main.c        socket, signals, reload, sd_notify
  handler.c     request flow: identify, authorize, attach/detach/check/create
  checks.c      SO_PEERCRED, /proc/<pid>/exe, ACL, netns validation, setns
  netlink.c     rtnetlink (links, bridge, veth, addresses, routes) – no libnl
  bridge.c      bridge creation/removal, NetworkManager/networkd/libvirt detection
  state.c       IPAM leases, attachment records, bridge ownership markers
  dnsout.c      /etc/hosts block, dnsmasq hosts file, aardvark-dns
  nft.c         nftables ruleset generation and atomic application (inet + bridge tables)
  gc.c          stale state sweep, CNI GC
  dhcp.c        DHCPv4 client (ipam = dhcp)
  keeper.c      per-container DHCP lease keeper process
```

## Invocation modes

The client decides the mode from its environment:

| Condition | Mode | Handled |
|---|---|---|
| `CNI_COMMAND` set | CNI | ADD, DEL, CHECK → daemon; VERSION → locally |
| first argument `create`, `setup`, `teardown` | Netavark plugin API 1.0.0 | daemon |
| `info` or no argument | Netavark | locally |
| program name `trestlectl` | admin | daemon (`status`, `list`, `leases`, `gc`, `detach`) |

Before contacting the daemon the client validates everything it can (command,
`CNI_CONTAINERID`, `CNI_IFNAME`, `CNI_NETNS`, `CNI_PATH`, `cniVersion`,
network name, container name, interface name, static IP/MAC syntax, and that
stdin is exactly one JSON object). Errors are printed in the caller's format:
`{"cniVersion":..,"code":N,"msg":..}` or `{"error":..}`.

## Wire protocol

`SOCK_STREAM` unix socket. Request: 12 byte header
(`magic "TRST"`, `version 1`, `flags`, `length`) + JSON. If flag bit 0 is set,
exactly one file descriptor (the container network namespace) is attached to
the first byte with `SCM_RIGHTS`. Response: header (`magic "TRSP"`,
`exit_code`, `length`) + the bytes the client prints on stdout.

```json
{
  "version": 1, "mode": "netavark", "command": "setup",
  "argv": ["/usr/libexec/netavark/trestle", "setup", "/run/user/1000/netns/netns-…"],
  "env": {}, "netns_path": "/run/user/1000/netns/netns-…",
  "netns_fd": true, "rootless": true,
  "stdin": "{ …NetworkPluginExec JSON… }"
}
```

The daemon re-validates all of it and never trusts the client's own
validation, the `rootless` flag or the claimed paths.

## NetworkManager

`nm.c`. When `bridge_ensure()` is about to create a bridge it asks
`nm_should_unmanage()`: is `networkmanager` enabled, is nmcli executable,
does no NetworkManager profile (keyfiles in `/etc`, `/run`, `/usr/lib`
`NetworkManager/system-connections`, or `ifcfg-*` with `DEVICE=`) name the
interface, and does `nmcli -t -f RUNNING general` say `running`? If so,
right after creating the bridge it runs `nmcli device set <bridge> managed
no`, retrying for up to 3 s because NetworkManager notices new links
asynchronously. A failure is logged and does not fail the request. A
bridge named by a profile is left to NetworkManager and, as before, never
deleted by trestle.

## firewalld

`firewalld.c`. For networks with `firewalld_zone`, `bridge_ensure()` asks
`firewall-cmd --get-zone-of-interface=<bridge>` on every attach and runs
`--zone=<zone> --change-interface=<bridge>` when the bridge is not in that
zone. The binding is runtime only (the bridge itself is temporary), and
`firewall-cmd --reload` drops runtime bindings; checking on every attach,
plus once for all existing bridges at daemon start and on SIGHUP, restores
it. Before a bridge is deleted it is removed from the zone if it is still
in ours. Exit status 252 (firewalld not running) is silently ignored.

## Port security

`nft.c` builds two tables in one atomic `nft -f` transaction: `inet
<nft_table>` (firewall, masquerade, layer-3 isolation) and `bridge
<nft_table>` (anti-spoofing, layer-2 isolation). The bridge table's sets
are generated from the attachment records, so they are always exactly the
current attachments; the ruleset is re-applied after every attach, detach,
GC removal and DHCP address change, under the state lock (the daemon's own
re-applications at start and reload take the lock too).

```
prerouting (bridge, prio -200)   frames entering the bridge from a port
  iifname @open_ports  accept         networks with anti_spoofing = no
  iifname @ports       jump port_in   known trestle ports
  iifname "trv*"       drop           unknown trestle-named ports (fail closed)
port_in
  iifname . ether saddr != @port_mac drop      MAC spoofing
  VLAN tags, DHCP server (udp sport 67), IPv6 RA/redirect, DHCPv6 server: drop
  iifname @mac_only_ports accept      no IPAM by trestle: only MAC checked
  ARP:  sender MAC must match; sender IP in @port_ip (DHCP ports: 0.0.0.0 probes)
  IPv4: iifname . ip saddr @port_ip; DHCP ports: 0.0.0.0:68 -> :67
  IPv6: only @v6_ports (allow_ipv6); everything else dropped
forward (bridge)
  iifname @iso_ports oifname @iso_ports iifname . oifname != @iso_peers drop
inet forward
  iifname BR oifname BR ip saddr . ip daddr != @iso_<BR> drop   (routed hairpin)
```

`iso_peers` holds the ordered pairs of ports of the same user
(`isolation = user`; empty for `container`). A new port is entered into the
sets before it is enslaved and brought up, so there is no unprotected
window. Bridges trestle creates get a fixed MAC (from md5 of the bridge name)
so the gateway MAC does not change as ports come and go.

## Stale state

`gc.c`. A *sweep* (daemon start under the state lock, a forked child every
`gc_interval`, `trestlectl gc`) removes attachments whose host veth no
longer exists, releases leases no attachment owns, and restarts DHCP
keepers that are gone, finding the container netns again by the
`st_dev`/`st_ino` stored in the record (`/run/netns`, then
`/proc/*/ns/net`). *CNI GC* (cniVersion 1.1.0) removes the calling uid's
`cni` attachments on the network that are not in `cni.dev/valid-attachments`,
including their veth. *STATUS* reports code 50 when the network's pool is
exhausted (the client reports 50 when trestled is unreachable).

## DHCP (ipam = dhcp)

`dhcp.c` is a small RFC 2131 client. Packets go through a UDP socket created
inside the container netns (`setns` round trip), bound to the container
interface and port 68, with the container's MAC as `chaddr` and client
identifier, so the LAN server sees a normal client. On attach the request
handler runs DISCOVER/OFFER/REQUEST/ACK (`dhcp_timeout`), configures address,
default route and DNS servers, records the lease and starts the keeper:
`trestled --dhcp-keeper NET CID` with the netns on fd 3, through
`systemd-run --scope --unit=trestle-dhcp-<veth>` when systemd runs (so it is
outside trestled's cgroup and survives restarts). The keeper renews at T1
(unicast), rebinds at T2 (broadcast), re-acquires after a NAK or expiry,
updates the container and the record (and with that the anti-spoofing sets
and DNS outputs), exits when its veth or record disappears and sends
DHCPRELEASE on SIGTERM (teardown).

## Concurrency

The main process only accepts connections. Each connection is handled in a
forked child (at most 64 at a time, and at most `max_requests_per_user` for
one non-root uid), so a client that connects and stalls cannot block other
requests; a child that has not received the whole request within
`request_timeout` is ended. Children
read and authorize their request in parallel, then take an exclusive
`flock` on `<state_dir>/state.lock` for the part that changes state (links,
IPAM, records, DNS outputs). Configuration reloads happen in the main
process and apply to the next connection.

## Network namespace handling

* Rootless Netavark: the namespace path lives in the caller's private mount
  namespace. The client opens it; the daemon receives the fd.
* The daemon checks the fd is a network namespace (`NS_GET_NSTYPE`), that it
  is not the daemon's own namespace, and, for non-root callers, that the
  user namespace owning it was created by the caller (`NS_GET_USERNS` +
  `NS_GET_OWNER_UID`).
* Root callers (Kubernetes) may pass only the path; the daemon opens it.
* The veth peer is created straight into the target namespace
  (`IFLA_NET_NS_FD`). To configure it the daemon `setns()`es into the
  namespace just long enough to open a netlink socket, then returns.
* Teardown only needs the host side: deleting it destroys the peer.

## Naming

| Object | Name |
|---|---|
| bridge | `tbr` + `md5(network)[0:12]` or `bridge =` |
| host veth | `trv` + `md5("<network>:<user>:<container>")[0:12]` |
| host veth alias | `trestle:<user>.<container>.<network>` |
| container interface | `CNI_IFNAME` / `network_options.interface_name` |
| DNS / hosts name | `<user>.<container>.<network>.trestle` (lower case, invalid characters → `-`) |
| CNI container name | `<K8S_POD_NAMESPACE>-<K8S_POD_NAME>`, else `K8S_POD_NAME`, else first 12 chars of `CNI_CONTAINERID` |

All names are 15 characters (Linux `IFNAMSIZ` − 1). If a `trv` name already
exists, the request fails rather than reusing it.

## State (`/var/lib/trestle`)

The directory is `0711` while it holds the socket (default), else `0700`;
all files below it are `0600` and all subdirectories `0700`.

```
trestle.sock                          the daemon's socket (default location)
ipam/<network>/<a.b.c.d>              lease, contains the container id
ipam/<network>/.last                  round-robin cursor
attachments/<network>/<container-id>  key=value record (user, uid, veth, ip, mac, aliases, mode)
bridges/<bridge>                      trestle created this bridge
wildcard/<network>                    network created from [network:*]: its bridge address/prefix (or "-")
dhcp/<veth>.pid                       DHCP lease keeper of an attachment
trestled.lock                         single instance lock
state.lock                            serializes state changes between request handlers
```

Every file is written with write-to-temp + `fsync` + `rename`. Records are the
source of truth for the hosts block, the dnsmasq file and aardvark-dns, which
are regenerated from them after every change. That makes restarts and
partial failures self-healing.

DEL/teardown is authorized against the record: a non-root user can only
detach containers whose record carries their uid.

## IPAM

`subnet = G/P` gives the bridge address `G`; the pool is every host address
of the subnet except `G`. Requests for static addresses (Netavark
`static_ips`, CNI `IP=` / `runtimeConfig.ips`) must be inside the subnet,
must not be reserved, and fail if another container holds them. Repeated ADDs
for the same container id return the same lease.

For Podman, `create` sets `ipam_options.driver` to `none` (default) so that
trestle is the only allocator for the shared bridge. With
`podman_ipam = host-local` Podman allocates and trestle enforces uniqueness.

## DNS

* `/etc/hosts`: one block between `# BEGIN trestle managed entries` and
  `# END trestle managed entries`, rewritten atomically. Owner, mode and
  SELinux label of the original are preserved.
* dnsmasq: an `addn-hosts` file per network, optional SIGHUP via pid file.
* aardvark-dns: a config file per network in `aardvark_dir` (Netavark format:
  first line the gateway, then `id ipv4 ipv6 names`). trestled starts
  aardvark-dns (through `systemd-run --scope` when available) or sends it
  SIGHUP. Status blocks then list the bridge address as DNS server.

## The [network:*] catch-all

A request for a network without its own section uses the `[network:*]`
template (`netset.c`). The ACL check uses the template's `users`. When a
container is attached, or Podman creates the network, the name is recorded
in `wildcard/<network>` while the state lock is held, and with `subnet_pool`
it gets the first `/subnet_prefix` of the pool that overlaps no explicit
network and no other recorded network. The ruleset and the hosts block are
always built from the explicit networks plus these records, so every
request handler sees the same set; a new record triggers an nftables
reload. Records are kept when the bridge is removed so a network name keeps
its subnet.

## Hook scripts

`create_script`, `setup_script` and `teardown_script` (per network) are run
by the request handler while it holds the state lock:

| Event | When | Container data |
|---|---|---|
| create | whenever trestle creates the bridge (first container to attach; Netavark `create` creates nothing) | no |
| setup | after a successful attach (links, address, record, DNS) | yes, plus netns as fd 3 |
| teardown | before the host veth is deleted | yes (from the attachment record) |

Before running, trestled checks the script is root-owned and not writable
by group/others (same for its directory). The child gets its own process
group, default signal handling, `/dev/null` on stdin, a pipe on
stdout/stderr (logged line by line, 64 KiB max), only fd 3 (netns) besides
0-2, and an environment built from `PATH`, `LANG` and `TRESTLE_*` only.
After `script_timeout` the process group is killed. With
`script_on_error = fail` a failing create aborts the request and a failing
setup is rolled back (record, veth, lease, DNS, new bridge) before the error
is returned. Teardown failures are always only logged.

The client allows for hook time when waiting for the daemon's answer
(`request_timeout` + 30 s + the longest hook time configured).

## nftables

When any network sets `firewall` or `masquerade`, trestled loads one table
`inet trestle` atomically (`table …; delete table …; table … { … }` through
`nft -f -`) at start and on SIGHUP:

```
chain out_<bridge>   rules for traffic from containers  (nft_rule, allow_outbound_to, policy)
chain in_<bridge>    rules for traffic to containers    (nft_rule, allow_inbound_from, allow_inbound, policy)
chain forward        hook forward: established/related accept, invalid drop, jumps per bridge
chain postrouting    hook postrouting: ip saddr <subnet> oifname != <bridge> masquerade
```

Other firewalls (firewalld, other tables) are evaluated independently; a
drop there still wins.
