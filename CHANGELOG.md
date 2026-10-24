# Changelog

## 0.2 - 2026-10-24

* **Anti-spoofing** (`anti_spoofing`, default on): an nftables `bridge`
  table binds every container port to its MAC and IPv4 address; ARP, IP and
  MAC spoofing, DHCP servers, IPv6 router advertisements/redirects, DHCPv6
  servers and VLAN tagged frames from containers are dropped, as is traffic
  from `trv*` ports trestle does not know. `allow_ipv6` lets IPv6 through.
* **Isolation** (`isolation = none | user | container`): containers of
  different users (or all containers) cannot reach each other on a shared
  bridge, at layer 2 and when routed through the host.
* **Stale state cleanup**: attachments whose veth is gone, orphaned leases
  and lost DHCP keepers are cleaned up at start, every `gc_interval`
  (default 300 s) and with `trestlectl gc`.
* **CNI 1.1.0**: `GC` (`cni.dev/valid-attachments`, limited to the caller's
  own CNI attachments) and `STATUS` (code 50 when the daemon is down or the
  pool is exhausted).
* **trestlectl**: `status`, `list`, `leases`, `gc [--dry-run]`, `detach`,
  `--json`.
* **ipam = dhcp**: containers on LAN bridges get their address from the LAN
  DHCP server; trestled acts as the client for the container's MAC and a
  keeper process renews and releases the lease.
* The socket moved from `/tmp/trestle.sock` to
  `/var/lib/trestle/trestle.sock` (root-owned directory, now `0711`), so
  it can no longer be squatted; `trestled.service` uses `PrivateTmp=yes`.
  `socket = /tmp/trestle.sock` (with `PrivateTmp=no`) still works. SELinux
  type `trestle_tmp_t` is now `trestle_sock_t`.
* Bridges trestle creates get a fixed MAC address, so the gateway MAC no
  longer changes when containers come and go.
* `make fuzz` gains a DHCP parser target; new `tests/integration/features.sh`.

## 0.1 - 2026-10-23

Initial release.

* `trestle` client: CNI 0.3.0–1.0.0 (ADD, DEL, CHECK, VERSION) and
  Netavark plugin API 1.0.0 (create, setup, teardown, info).
* Rootless support: the container netns is passed to the daemon as a file
  descriptor.
* `trestled` daemon: peer credential and client binary checks, per-network
  user/group ACLs with deny entries, bridge and veth management over
  rtnetlink, IPv4 IPAM with static addresses, MTU, STP, VLAN filtering,
  uplinks.
* Name publication in `/etc/hosts`, dnsmasq hosts files and aardvark-dns.
* nftables filtering and masquerading per network.
* Bridges trestle creates are marked unmanaged in NetworkManager
  (`nmcli device set <bridge> managed no`) unless a NetworkManager profile
  names them (`networkmanager`, `nmcli_binary`).
* `firewalld_zone` per network puts the bridge into a firewalld zone
  (runtime, re-applied after `firewall-cmd --reload`); `firewall_cmd`.
* Safe bridge removal (only bridges trestle created and no other manager
  claims).
* `[network:*]` catch-all section for networks without their own section,
  with a `subnet_pool` / `subnet_prefix` giving each network its own subnet,
  and `%n` (network name) in `dnsmasq_hosts`.
* Per-network hook scripts (`create_script`, `setup_script`,
  `teardown_script`, `script_timeout`, `script_on_error`) with `TRESTLE_*`
  environment variables and the container netns passed as fd 3.
* systemd unit, SELinux module, man pages, RPM / Debian / Arch packaging,
  unit and integration tests.
* Input hardening from a security review (see `docs/SECURITY.md`): client
  binary checked before the request is read; whole-request deadline and
  `max_requests_per_user`; strict framing (one fd, no unknown flags, no NUL
  bytes); strict JSON (no `\u0000`, no trailing data, wrong-typed members
  rejected); no truncation of `CNI_ARGS` values; container ids must start
  with a letter or digit; strict MAC and IP prefix parsing; control
  characters rejected in paths and `CNI_ARGS` and escaped in logs.
* `make fuzz` (libFuzzer harnesses) and `make security-test` (hostile client
  against a live daemon).
