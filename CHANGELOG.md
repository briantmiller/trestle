# Changelog

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
