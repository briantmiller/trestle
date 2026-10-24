# trestle security notes

trestled runs as root and acts on requests from unprivileged users, so every
request is treated as hostile until proven otherwise.

## Trust boundaries

| Check | Mechanism | Protects against |
|---|---|---|
| Caller identity | `SO_PEERCRED` (kernel supplied uid/pid, translated to the init user namespace) | Users claiming to be someone else. A rootless Netavark running as "uid 0" in a user namespace is seen as the real user. |
| Network permission | `[network:NAME]` + `users` ACL, deny entries win | Users attaching to networks they should not use |
| Client binary | `/proc/<pid>/exe` == `client_binary` | Ad-hoc scripts talking to the socket directly |
| Input validation | All arguments, env vars and JSON re-validated in the daemon; strict character sets for names; size limits (1 MiB) | Injection into interface names, file paths, hosts file, nftables |
| Namespace ownership | fd must be a netns, not the host netns, and (non-root) owned by a user namespace of the caller | Moving interfaces into the host or another user's container |
| Ownership of attachments | teardown/DEL/CHECK compare the record's uid | One user detaching another user's container |
| Naming | veth name includes the user name | Collisions between users |
| Spoofing between containers | `anti_spoofing` (default on): nftables bridge table binds each port to its MAC and IPv4 address; rogue DHCP servers, IPv6 RA/redirects, VLAN tags and unknown `trv*` ports dropped | A container impersonating another container or the gateway (ARP/IP/MAC spoofing, rogue DHCP) |
| Tenant separation | `isolation = user \| container` at layer 2 and for routed hairpin traffic | Users reaching each other's containers on a shared bridge |
| Denial of service | whole request within `request_timeout` (not just each read); at most 64 handlers, `max_requests_per_user` (default 8) per non-root uid | One user keeping all handlers busy with stalled or dripping connections |
| Server identity (client side) | peer uid root, socket owned by root, socket directory chain root-only; `/proc/<pid>/exe` (or process name inside a user namespace) only when the directory is not root-only or with `verify_server = strict`; optional SELinux type | A local user squatting the socket path (only possible when `socket` points into a world-writable directory such as `/tmp`) |

### Input handling rules

* The client binary check runs before a single byte of the request is
  read, so arbitrary processes never reach the parsers.
* Framing: magic, version, no unknown flag bits, length at most 1 MiB, exactly
  one file descriptor iff the fd flag is set, no NUL bytes in the body.
* JSON (the request and the embedded CNI / Netavark document): exactly one
  object, no trailing data, no `\u0000` escapes anywhere (they would cut
  values or keys at that point in C), json-c depth limit 32.
* Every member is type-checked; a present member with the wrong type
  (`"static_ips": "10.0.0.5"`, `"version": "1"`) is an error, never ignored.
* Nothing is truncated to fit: over-long values (`CNI_ARGS` entries, IP
  strings, names) are rejected, so a cut value can never turn into a different
  valid one.
* Names that become file names (network, container id) must start with a
  letter or digit and only contain `[A-Za-z0-9_.-]`: no `.`, `..`, hidden or
  option-like (`-x`) names. Interface names reject `/`, `:`, quotes,
  backslashes, blanks and control characters.
* `CNI_NETNS`, `CNI_ARGS`, `CNI_PATH` and the Netavark netns path must not
  contain control characters; `CNI_ARGS` must be `KEY=VALUE;...`.
* MAC addresses are parsed character by character (exactly `xx:xx:...`, hex
  only, unicast); IPs are `inet_pton` IPv4 with an optional `/0`-`/32`.
* Invalid aliases are dropped one by one, not passed on.
* No shell is ever used; helper programs (`nft`, `nmcli`, `firewall-cmd`,
  `aardvark-dns`, hooks) get fixed argument vectors, and the nftables ruleset
  is built only from validated configuration.
* Log messages escape control characters (`\x0a`), so client-supplied text
  cannot forge log lines or journald priority prefixes.

### trestlectl and CNI GC

`trestlectl` is the client binary under another name, so it passes the same
client binary check. Non-root users may `status` (networks they may use),
`list` (their own attachments) and `detach` their own containers; `leases`
and `gc` are root only. CNI GC only ever removes `cni` attachments of the
calling uid, so the kubelet's GC cannot touch rootless Podman containers on
the same network.

### Testing

* `make fuzz` (clang): libFuzzer + ASan/UBSan harnesses for the CNI and
  Netavark parsers, the daemon's request decoding, the wire framing, the
  configuration parser + nftables generator and the hosts-file editor
  (`tests/fuzz/`, `FUZZ_TIME=` seconds per target).
* `make security-test` (root): starts a private daemon and runs about 100
  hostile requests each as an allowed user, an unpermitted user and root
  (`tests/security/`): malformed frames, wrong / extra / foreign file
  descriptors, corrupt and deeply nested JSON, NUL bytes, wrong types,
  path traversal, shell metacharacters and newlines in every field, slow
  clients. It checks the daemon survives, answers each with an error and
  leaves no interfaces, files, leases or DNS entries behind. Build the daemon
  with `-fsanitize=address,undefined` to also catch memory errors.

### Limits of the client binary check

The binary check proves the connecting process runs the trestle client, not
that a container runtime started it. A user can run the client by hand with
crafted input. That is acceptable because everything the client can make the
daemon do is limited by the same ACL, namespace ownership and record
ownership rules. It stops casual misuse and makes auditing easier, but it is
not the security boundary on its own. Note also that PIDs can be reused; the
check happens right after the connection is accepted.

### Where the socket lives

Netavark runs plugins with a private `/run` (and so `/var/run`), so the
socket cannot be there. Since 0.2 it is `/var/lib/trestle/trestle.sock`, in
the root-owned state directory:

* nobody but root can create, replace or remove anything in that directory,
  so the path cannot be squatted, not even while trestled is stopped;
* the directory is `0711` (it is `0700` when the socket is configured
  elsewhere): clients can reach the socket by its name, but cannot list the
  directory; every file in it is `0600` and every subdirectory `0700`, so
  leases and records stay private;
* the daemon's `/tmp` is private (`PrivateTmp=yes`);
* `socket_group` + `socket_mode = 0770` restrict access to a group;
* the client refuses a socket not served by root or not owned by root, and
  checks that the socket's directory and all directories above it are
  root-owned and not writable by others. That is what makes the socket
  trustworthy, so the client no longer looks at the server's
  `/proc/<pid>/exe` (which rootless clients mostly cannot read anyway; the
  process-name fallback could be faked by anyone) and container runtimes
  need no SELinux access to trestled's `/proc` entries;
* with SELinux, `server_selinux_type = trestled_t` additionally checks the
  server's label, which the kernel reports even across user namespaces.

The 0.1 location `/tmp/trestle.sock` still works (`socket = /tmp/trestle.sock`
plus `PrivateTmp=no` in a drop-in for `trestled.service`). There a local user
could create the file while trestled is stopped. Because the directory is
writable by others, the client falls back to checking the server binary
(`server_binary`) and refuses to talk to anything else; trestled removes the
file at start. Under SELinux the client domain then also needs read access
to trestled's `/proc` entries (the policy no longer grants it), or use
`server_selinux_type` and `verify_server = no`.
trestled logs a warning when the socket directory is world writable.

## Hook scripts

Hook scripts run as root with data that partly comes from unprivileged
users (container names, aliases, Kubernetes pod names). trestle only passes
values that passed its strict name checks (letters, digits, `_`, `.`, `-`),
never through a shell, and only as environment variables; scripts must
still quote them (`"$TRESTLE_CONTAINER_NAME"`). Scripts and their directory
must be root-owned and not group/world writable, or trestled refuses to run
them. Scripts inherit the systemd sandbox of trestled (`ProtectHome`,
`ProtectSystem=full`, `MemoryDenyWriteExecute`, ...), and with SELinux they
run in `trestled_t`; label them `trestle_script_exec_t` (default for
`/etc/trestle/hooks`).

## Hardening

* systemd unit: limited capability bounding set, `NoNewPrivileges`,
  `ProtectHome`, `ProtectSystem=full` (+ `/etc` writable for the hosts file),
  restricted address families, `MemoryDenyWriteExecute`.
* SELinux module (`selinux/`): confined `trestled_t` domain; container runtime
  and unconfined domains may connect. Other domains can be granted access
  with the `trestle_client()` interface.
* Build flags: PIE, full RELRO, stack protector, `_FORTIFY_SOURCE=2`.
* No third-party crypto. MD5 is used only to derive interface names.
* Netlink is spoken directly; the only runtime library is json-c.

## Reporting

Please report security problems privately to Brian Miller <brianthomasmiller@gmail.com>.
