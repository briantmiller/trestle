# trestle

trestle is a CNI and Netavark network plugin that lets **rootless containers
attach to a host bridge**. Rootless Podman normally cannot create interfaces
on the host, so its containers are limited to user-mode networking. trestle
puts a small root daemon behind an unprivileged plugin: the daemon checks
who is asking, creates a veth pair on a host bridge and moves the peer into
the container's network namespace.

The same plugin also works as a regular CNI plugin for Kubernetes
(containerd / CRI-O).

```
 podman (rootless) ─► netavark ─► trestle ──unix socket──► trestled (root)
 kubelet ─► containerd/CRI-O ─► trestle ─┘    + netns fd     ├─ bridge  tbr…
                                                             ├─ veth    trv…  ⇄ container eth0
                                                             ├─ IPAM or DHCP, default route
                                                             ├─ /etc/hosts, dnsmasq, aardvark-dns
                                                             └─ nftables (anti-spoofing, isolation,
                                                                          filter, masquerade)
```

## Components

| Component | Path | Role |
|---|---|---|
| `trestle` | `/usr/libexec/trestle/trestle`, symlinked into `/usr/libexec/netavark` and `/usr/libexec/cni` | Plugin executed by the runtime. Validates arguments, `CNI_*` variables and stdin JSON. Passes the request and (for rootless callers) the netns file descriptor to the daemon, and prints its answer. |
| `trestled` | `/usr/sbin/trestled`, `trestled.service` | Root daemon. Authorizes the request and does the network work. |
| `trestlectl` | `/usr/bin/trestlectl` (symlink to the client) | Admin tool: `status`, `list`, `leases`, `gc`, `detach`. |
| `trestle.conf` | `/etc/trestle/trestle.conf`, `/etc/trestle/conf.d/*.conf` | Permitted networks, users, addressing, DNS and firewall options. |

## What happens on a request

1. **Who is calling?** uid/pid from `SO_PEERCRED`, user name from passwd.
2. **Is it the real client?** `/proc/<pid>/exe` must be the configured
   `client_binary`.
3. **Is the network permitted?** It needs a `[network:NAME]` section, or
   falls back to the `[network:*]` catch-all section, and the user must
   match its `users` list (`alice`, `@group`, `*`, `!deny`). Networks from
   the catch-all each get their own bridge and a subnet from its
   `subnet_pool`.
4. **Bridge.** `tbr` + first 12 hex chars of `md5(network)`, or the
   configured `bridge`. Created if missing; existing bridges are reused.
   Before creating it, trestle checks whether a NetworkManager profile names
   it; if none does and NetworkManager is running, the new bridge is marked
   unmanaged (`nmcli device set <bridge> managed no`). With
   `firewalld_zone = trusted` the bridge is also put into that firewalld
   zone, so the default zone's rules don't block DNS and other traffic
   from the containers to the host.
5. **veth.** Host side `trv` + first 12 hex chars of
   `md5("network:user:container")`, enslaved to the bridge, with alias
   `trestle:user.container.network`. The peer is created directly inside the
   container netns with the name the runtime asked for (`CNI_IFNAME` /
   `interface_name`). Two users can run containers with the same name
   without clashing.
6. **Addressing** (if `subnet = 10.0.0.1/24`): `10.0.0.1` on the bridge,
   `10.0.0.2-254` for containers, default route via the bridge. With
   `ipam = dhcp` (LAN bridges) trestled gets a lease from the LAN's DHCP
   server for the container's MAC and keeps it renewed.
7. **Port security** (default `anti_spoofing = yes`): the container may only
   send with its own MAC and IP; rogue DHCP servers and router
   advertisements are dropped. Optional `isolation = user | container`
   separates tenants on a shared bridge.
8. **Names** (optional): `user.container.network.trestle` in `/etc/hosts`,
   a dnsmasq hosts file, and/or aardvark-dns for Netavark.

9. **Hooks** (optional): per-network `create_script`, `setup_script` and
   `teardown_script` run with `TRESTLE_*` environment variables (network,
   bridge, container id/name, user, interface names, MACs, IP, and the
   container netns as fd 3). See `man trestle.conf` and
   `docs/examples/hook-example.sh`.

Teardown reverses all of this. Leftovers from crashes (attachments whose
veth is gone, orphaned leases) are swept at start, every `gc_interval` and
with `trestlectl gc`; Kubernetes can also use CNI 1.1.0 `GC` and `STATUS`. A bridge is removed only if trestle created
it, it has no other ports, and NetworkManager, systemd-networkd and libvirt
do not claim it.

## Quick start (Podman, rootless)

```ini
# /etc/trestle/trestle.conf
[global]
ip_forward = yes

[network:lab]
users = alice, @developers
subnet = 10.42.0.1/24
masquerade = yes
firewall = yes
allow_inbound = tcp:8080, icmp
aardvark_dns = yes
```

```sh
sudo trestled -t                      # check the configuration
sudo systemctl enable --now trestled
# as alice:
podman network create -d trestle lab
podman run --rm -it --network lab alpine ip addr
```

## Quick start (Kubernetes)

```sh
sudo ln -s /usr/libexec/trestle/trestle /opt/cni/bin/trestle
cat <<'EOF' | sudo tee /etc/cni/net.d/10-trestle.conflist
{ "cniVersion": "1.0.0", "name": "lab",
  "plugins": [ { "type": "trestle", "capabilities": { "ips": true, "mac": true } },
               { "type": "loopback" } ] }
EOF
```

Add `root` (or `*`) to `users` because the CRI runtime runs plugins as root.
See `docs/examples/`.

## Building

Dependencies: a C11 compiler, GNU make, pkg-config, json-c ≥ 0.13. At run
time: Linux ≥ 4.11 (nsfs ioctls), nftables (`nft`) for firewall features,
aardvark-dns for `aardvark_dns`.

```sh
make                     # build/trestle, build/trestled
make check               # unit tests
sudo make integration-test   # end-to-end test with netns, users, nftables
sudo make install        # PREFIX=/usr by default
make selinux             # SELinux module (selinux-policy-devel)
make rpm                 # RPM (packaging/rpm/trestle.spec)
make deb                 # Debian package (debian/)
# Arch Linux: packaging/arch/PKGBUILD
```

MD5 is implemented inside trestle and used only for interface names, so it
works on hosts running in FIPS mode.

## Documentation

* `man trestle`, `man trestled`, `man trestlectl`, `man trestle.conf`
* [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md): protocol, state, naming
* [docs/SECURITY.md](docs/SECURITY.md): threat model and hardening
* [docs/examples/](docs/examples/)

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).

Maintainer: Brian Miller <brianthomasmiller@gmail.com>
