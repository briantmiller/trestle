# Using trestle with rootless Podman

## 1. Configure and start the daemon

```ini
# /etc/trestle/conf.d/50-dev.conf
[network:dev]
users = alice
subnet = 10.42.0.1/24
aardvark_dns = yes
masquerade = yes
firewall = yes
allow_inbound = tcp:8080, icmp
```

```sh
sudo trestled -t
sudo systemctl enable --now trestled      # or: sudo systemctl reload trestled
```

`ip_forward = yes` in `[global]` (or your own sysctl) is required for traffic
to leave the host.

## 2. Create the Podman network (as alice)

The driver name is the plugin name, `trestle`. Netavark finds the plugin
through the symlink in `/usr/libexec/netavark`. If your Podman uses a
different plugin directory, add it in `containers.conf`:

```toml
[network]
netavark_plugin_dirs = ["/usr/libexec/netavark"]
```

```sh
podman network create -d trestle dev
podman network inspect dev     # network_interface = tbr…, ipam driver none
```

The network name must match a `[network:NAME]` section. If the
user is not permitted, `create` fails with a clear message. Creating the
network only checks this; the bridge appears when the first container
starts on it and disappears with the last one.

## 3. Run containers

```sh
podman run -d --name web --network dev docker.io/library/nginx
podman inspect web --format '{{.NetworkSettings.Networks.dev.IPAddress}}'
ip -br link | grep trv                     # host side, alias trestle:alice.web.dev
getent hosts alice.web.dev.trestle         # with hosts_file = yes
```

Other containers on `dev` resolve `web` through aardvark-dns on 10.42.0.1.

## 4. Static addresses

```sh
podman run --network dev --ip 10.42.0.50 …
```

If Podman does not pass static IPs for networks with IPAM driver `none`, set
`podman_ipam = host-local` for that network. Podman then allocates the
address and trestle rejects addresses already used by another user.

## Hooks

```ini
[network:dev]
setup_script = /etc/trestle/hooks/dev.sh
teardown_script = /etc/trestle/hooks/dev.sh
```

`dev.sh` receives `setup`/`teardown` as `$1` and variables such as
`TRESTLE_CONTAINER_NAME`, `TRESTLE_USER`, `TRESTLE_HOST_IFNAME`,
`TRESTLE_IP`. See `hook-example.sh` next to this file.

## Troubleshooting

```sh
journalctl -u trestled -f
trestlectl list                     # your containers on trestle networks
sudo trestlectl status              # networks, attachments, free addresses
sudo trestlectl gc --dry-run        # leftovers from crashes
TRESTLE_DEBUG=1 /usr/libexec/trestle/trestle info
sudo trestled -t      # shows the nftables ruleset that will be loaded
sudo nft list table bridge trestle  # anti-spoofing / isolation drop counters
```

| Message | Meaning |
|---|---|
| `network 'x' is not permitted by trestle` | no `[network:x]` section |
| `user 'u' is not permitted to use network 'x'` | `users` does not match |
| `host interface trv… already exists` | the same user already runs a container with that name on that network |
| `refusing to talk to /var/lib/trestle/trestle.sock` | the socket is not served by trestled (daemon down and someone else created the file?) |
| `cannot connect to trestled` | daemon not running |
| container loses connectivity after changing its MAC or adding an address | anti-spoofing: a container may only use the MAC and IP trestle gave it (`anti_spoofing = no` to allow) |
| `no DHCP lease within 10 s` | `ipam = dhcp`, but no DHCP server answers on the bridge (uplink? `dhcp_timeout`) |
| containers can't resolve each other (aardvark-dns) | with firewalld, set `firewalld_zone = trusted` for the network; the default zone blocks DNS to the bridge |
