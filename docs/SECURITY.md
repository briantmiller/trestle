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
| Server identity (client side) | peer uid root, socket owned by root, `/proc/<pid>/exe` (or process name inside a user namespace), optional SELinux type | A local user squatting `/tmp/trestle.sock` |

### Limits of the client binary check

The binary check proves the connecting process runs the trestle client, not
that a container runtime started it. A user can run the client by hand with
crafted input. That is acceptable because everything the client can make the
daemon do is limited by the same ACL, namespace ownership and record
ownership rules. It stops casual misuse and makes auditing easier, but it is
not the security boundary on its own. Note also that PIDs can be reused; the
check happens right after the connection is accepted.

### The socket in /tmp

Netavark runs plugins with a private `/run`, so the socket must be in `/tmp`.
Because `/tmp` is world writable:

* trestled deletes whatever exists at the path when it starts, and recreates
  the socket if it disappears or is replaced while running (checked every 30 s);
* `/tmp` has the sticky bit, so other users cannot remove root's socket;
* the client refuses a socket that is not served by root;
* `socket_group` + `socket_mode = 0770` restrict access to a group;
* with SELinux, set `server_selinux_type = trestled_t`.

A user could still create `/tmp/trestle.sock` while trestled is stopped. The
client's server verification then refuses to talk to it.

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

Please report security problems privately to Brian <brian@email.com>.
