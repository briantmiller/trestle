#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
#
# End-to-end tests for the 0.2 features: anti-spoofing, isolation, stale
# state cleanup (sweep and CNI GC/STATUS), trestlectl and ipam = dhcp.
# Must run as root. Uses dnsmasq as the LAN DHCP server when available.
#
#   tests/integration/features.sh <build-dir>
#
set -u
BUILD=${1:-}
if [ -z "$BUILD" ]; then BUILD="$(cd "$(dirname "$0")/../.." && pwd)/build"; fi
IT=${TRESTLE_FX_DIR:-/tmp/trestle-fx}
U1=trestle-fx-a
U2=trestle-fx-b
PASS=0
FAIL=0
SERVER_PID=
PIDS_NS=

say()  { printf '\n### %s\n' "$*"; }
ok()   { PASS=$((PASS + 1)); printf '  ok   %s\n' "$*"; }
bad()  { FAIL=$((FAIL + 1)); printf '  FAIL %s\n' "$*"; }
check() { local d=$1; shift; if "$@" >/dev/null 2>&1; then ok "$d"; else bad "$d"; fi; }
contains() { local d=$1 hay=$2 needle=$3; if [[ "$hay" == *"$needle"* ]]; then ok "$d"; else bad "$d (got: ${hay:0:300})"; fi; }
lacks() { local d=$1 hay=$2 needle=$3; if [[ "$hay" != *"$needle"* ]]; then ok "$d"; else bad "$d (found: $needle)"; fi; }

if [ "$(id -u)" != 0 ]; then echo "must run as root"; exit 77; fi
for t in ip unshare su useradd nft nsenter ping python3; do
	command -v $t >/dev/null || { echo "missing tool: $t"; exit 77; }
done
DNSMASQ=$(command -v dnsmasq || true)

sockpath() { sed -n 's/^socket = //p' "$IT/trestle.conf"; }
start_server() {
	"$IT/bin/trestled" -f -c "$IT/trestle.conf" >>"$IT/server.log" 2>&1 &
	SERVER_PID=$!
	for _ in $(seq 100); do [ -S "$(sockpath)" ] && break; sleep 0.1; done
}
stop_server() {
	[ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null && wait "$SERVER_PID" 2>/dev/null
	SERVER_PID=
	rm -f "$(sockpath)"
}

cleanup() {
	stop_server
	for p in $PIDS_NS; do kill "$p" 2>/dev/null; done
	for f in "$IT"/state/dhcp/*.pid; do [ -f "$f" ] && kill "$(cat "$f")" 2>/dev/null; done
	[ -f "$IT/dnsmasq.pid" ] && kill "$(cat "$IT/dnsmasq.pid")" 2>/dev/null
	for ns in fxa fxb fxc fxd fxe fxg fxk1 fxk2 fxo fxs1 fxs2 fxt1 fxt2; do ip netns del $ns 2>/dev/null; done
	for l in $(ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | cut -d@ -f1 | grep -E '^(trv|tbr|trfx)'); do
		ip link del "$l" 2>/dev/null
	done
	nft delete table inet trestlefx 2>/dev/null
	nft delete table bridge trestlefx 2>/dev/null
	for u in $U1 $U2; do userdel -r $u 2>/dev/null; done
	[ -n "${TRESTLE_FX_LOGS:-}" ] && cp "$IT/server.log" "$IT/dnsmasq.log" "$TRESTLE_FX_LOGS/" 2>/dev/null
	rm -rf "$IT"
}
trap cleanup EXIT
cleanup

useradd -m $U1; useradd -m $U2
mkdir -p "$IT/bin" "$IT/state"
chmod 755 "$IT"
install -m 0755 "$BUILD/trestle" "$BUILD/trestled" "$IT/bin/"
ln -s "$IT/bin/trestle" "$IT/bin/trestlectl"
printf '127.0.0.1 localhost\n' > "$IT/hosts"

ip link add trfx-lan type bridge
ip addr add 192.168.77.1/24 dev trfx-lan
ip link set trfx-lan up

cat > "$IT/trestle.conf" <<EOF
[global]
socket = $IT/state/trestle.sock
client_binary = $IT/bin/trestle
server_binary = $IT/bin/trestled
state_dir = $IT/state
hosts_path = $IT/hosts
log_level = debug
nft_table = trestlefx
networkmanager = no
gc_interval = 10
ip_forward = yes

[network:sec]
users = root
subnet = 10.233.0.1/24

[network:open]
users = root
subnet = 10.235.0.1/24
anti_spoofing = no

[network:iso]
users = root, $U1, $U2
subnet = 10.234.0.1/24
isolation = user

[network:solo]
users = root
subnet = 10.236.0.1/24
isolation = container

[network:tiny]
users = root
subnet = 10.237.0.1/30

[network:lan]
users = root, $U1
bridge = trfx-lan
ipam = dhcp
dhcp_timeout = 15
hosts_file = yes
EOF
chmod 644 "$IT/trestle.conf"
export TRESTLE_CONFIG=$IT/trestle.conf
start_server

cni() { # cmd id netns ifname args net
	printf '{"cniVersion":"1.1.0","name":"%s","type":"trestle"}' "$6" |
		CNI_COMMAND=$1 CNI_CONTAINERID=$2 CNI_NETNS=$3 CNI_IFNAME=$4 CNI_PATH=/opt/cni/bin CNI_ARGS=$5 "$IT/bin/trestle"
}
ctl() { "$IT/bin/trestlectl" "$@" 2>&1; }
ipof() { grep -o '"address":"[0-9.]*' <<<"$1" | cut -d'"' -f4; }
veth() { printf 'trv%s' "$(printf '%s' "$1" | md5sum | cut -c1-12)"; }
counter() { # chain comment -> packets
	nft list chain bridge trestlefx "$1" 2>/dev/null | grep "$2" | grep -o 'packets [0-9]*' | awk '{print $2}' | head -1
}
nsping() { ip netns exec "$1" ping -c1 -W1 "$2" >/dev/null 2>&1; }
# a process is gone when /proc has no entry or only a zombie (this test may
# run where nobody reaps orphans)
gone() { [ ! -d "/proc/$1" ] || grep -q ') Z' "/proc/$1/stat" 2>/dev/null; }

# ---------------------------------------------------------------- socket
say "socket in the state directory"
check "socket created in the state directory" test -S "$IT/state/trestle.sock"
contains "state directory is 0711 (reachable, not listable)" "$(stat -c %a "$IT/state")" "711"
if su $U1 -s /bin/sh -c "ls $IT/state" >/dev/null 2>&1; then bad "users cannot list the state directory"; else ok "users cannot list the state directory"; fi
out=$(su $U1 -s /bin/sh -c "TRESTLE_CONFIG=$IT/trestle.conf $IT/bin/trestlectl status" 2>&1)
contains "users reach the socket" "$out" "NETWORK"
if su $U1 -s /bin/sh -c "touch $IT/state/x.sock" 2>/dev/null; then bad "users cannot create files next to the socket"; else ok "users cannot create files next to the socket"; fi

# ---------------------------------------------------------------- anti-spoofing
say "anti-spoofing"
ip netns add fxa; ip netns add fxb; ip netns add fxc
A=$(cni ADD fxa1 /var/run/netns/fxa eth0 "K8S_POD_NAME=a" sec); IPA=$(ipof "$A")
B=$(cni ADD fxb1 /var/run/netns/fxb eth0 "K8S_POD_NAME=b" sec); IPB=$(ipof "$B")
contains "two pods attached" "$IPA $IPB" "10.233.0."
check "bridge table loaded" nft list table bridge trestlefx
contains "pod MAC bound to its port" "$(nft list set bridge trestlefx port_mac)" "$(veth sec:root:a)"
contains "pod IP bound to its port" "$(nft list set bridge trestlefx port_ip)" "$IPA"
check "legitimate traffic passes (a -> b)" nsping fxa "$IPB"
check "legitimate traffic passes (a -> gateway)" nsping fxa 10.233.0.1

ip -n fxa addr add 10.233.0.99/24 dev eth0
ip -n fxb neigh flush all
if ip netns exec fxa ping -c1 -W1 -I 10.233.0.99 "$IPB" >/dev/null 2>&1; then bad "spoofed source IP is dropped"; else ok "spoofed source IP is dropped"; fi
[ "$(( $(counter ip_in 'IP spoofing') + $(counter arp_in 'ARP sender IP spoofing') ))" -gt 0 ] && ok "spoofing drops are counted" || bad "spoofing drops are counted"
ip -n fxa addr del 10.233.0.99/24 dev eth0

MACA=$(ip -n fxa -br link show eth0 | awk '{print $3}')
ip -n fxa link set eth0 address 02:de:ad:be:ef:01
ip -n fxa neigh flush all; ip -n fxb neigh flush all
if nsping fxa "$IPB"; then bad "spoofed MAC is dropped"; else ok "spoofed MAC is dropped"; fi
[ "$(counter port_in 'MAC spoofing')" -gt 0 ] && ok "MAC spoofing counted" || bad "MAC spoofing counted"
ip -n fxa link set eth0 address "$MACA"
ip -n fxa neigh flush all
check "traffic passes again with the real MAC" nsping fxa "$IPB"

# forged ARP reply: "<b's IP> is at <a's MAC>"
before=$(counter arp_in 'ARP sender IP spoofing')
ip netns exec fxa python3 - "$MACA" "$IPB" <<'P'
import socket, struct, sys
mac = bytes.fromhex(sys.argv[1].replace(':', ''))
ip = socket.inet_aton(sys.argv[2])
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
s.bind(('eth0', 0))
arp = struct.pack('!HHBBH6s4s6s4s', 1, 0x0800, 6, 4, 2, mac, ip, b'\xff' * 6, ip)
for _ in range(3):
    s.send(b'\xff' * 6 + mac + b'\x08\x06' + arp)
P
after=$(counter arp_in 'ARP sender IP spoofing')
[ "$after" -gt "$before" ] && ok "forged ARP reply is dropped" || bad "forged ARP reply is dropped ($before -> $after)"
lacks "victim's neighbour entry not poisoned" "$(ip neigh show "$IPB" dev $(printf 'tbr%s' "$(printf sec | md5sum | cut -c1-12)"))" "$MACA"

# rogue DHCP server in a container
before=$(counter port_in 'DHCP server')
ip netns exec fxa python3 - <<'P'
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
s.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b'eth0')
s.bind(('0.0.0.0', 67))
for _ in range(3):
    s.sendto(b'\x02' + b'\x00' * 299, ('255.255.255.255', 68))
P
after=$(counter port_in 'DHCP server')
[ "$after" -gt "$before" ] && ok "DHCP server traffic from a container is dropped" || bad "DHCP server traffic from a container is dropped"

# a trv* port trestle does not know about
SECBR=tbr$(printf sec | md5sum | cut -c1-12)
ip link add trvdeadbeef0001 type veth peer name eth0 netns fxc
ip link set trvdeadbeef0001 master "$SECBR" up
ip -n fxc addr add 10.233.0.50/24 dev eth0; ip -n fxc link set eth0 up
if nsping fxc 10.233.0.1; then bad "unknown trv port is dropped"; else ok "unknown trv port is dropped"; fi
ip link del trvdeadbeef0001

# the gateway MAC must not change when ports come and go
contains "trestle bridge has a fixed MAC" "$(cat /sys/class/net/$SECBR/addr_assign_type)" "3"

# anti_spoofing = no keeps the old behaviour
ip netns add fxo
O=$(cni ADD fxo1 /var/run/netns/fxo eth0 "K8S_POD_NAME=o" open)
ip -n fxo addr add 10.235.0.99/24 dev eth0
check "anti_spoofing = no: spoofed source allowed" ip netns exec fxo ping -c1 -W1 -I 10.235.0.99 10.235.0.1
cni DEL fxo1 /var/run/netns/fxo eth0 "K8S_POD_NAME=o" open >/dev/null

# ---------------------------------------------------------------- isolation
say "isolation"
userns() { # user -> pid of a process in a new user+net namespace
	su "$1" -s /bin/sh -c "setsid unshare -U -r -n sleep 900 </dev/null >/dev/null 2>&1 & echo \$!"
}
mkjson() { # id name net ifname
	printf '{"container_id":"%s","container_name":"%s","port_mappings":[],"network":{"dns_enabled":false,"driver":"trestle","id":"n1","internal":false,"ipv6_enabled":false,"name":"%s","network_interface":"","options":null,"ipam_options":{"driver":"none"},"subnets":[]},"network_options":{"interface_name":"%s"}}' "$1" "$2" "$3" "${4:-eth0}"
}
nv() { # user pid cmd id name net
	mkjson "$4" "$5" "$6" > "$IT/nv-$4.json"; chmod 644 "$IT/nv-$4.json"
	su "$1" -s /bin/sh -c "TRESTLE_CONFIG=$IT/trestle.conf $IT/bin/trestle $3 /proc/$2/ns/net < $IT/nv-$4.json"
}
nvip() { grep -o '"ipnet":"[0-9.]*' <<<"$1" | cut -d'"' -f4; }
P1=$(userns $U1); P2=$(userns $U1); P3=$(userns $U2); PIDS_NS="$P1 $P2 $P3"
sleep 0.3
I1=$(nvip "$(nv $U1 $P1 setup iso1aaaa web1 iso)")
I2=$(nvip "$(nv $U1 $P2 setup iso2bbbb web2 iso)")
I3=$(nvip "$(nv $U2 $P3 setup iso3cccc web3 iso)")
contains "three rootless containers on the isolated network" "$I1 $I2 $I3" "10.234.0."
upi() { nsenter -t "$1" -n ping -c1 -W1 "$2" >/dev/null 2>&1; }
check "same user: container -> container" upi $P1 "$I2"
if upi $P1 "$I3"; then bad "other user's container is unreachable"; else ok "other user's container is unreachable"; fi
if upi $P3 "$I1"; then bad "...in both directions"; else ok "...in both directions"; fi
check "isolated containers still reach the gateway" upi $P3 10.234.0.1
nsenter -t $P1 -n ip route add "$I2/32" via 10.234.0.1
nsenter -t $P1 -n ip route add "$I3/32" via 10.234.0.1
nsenter -t $P1 -n ip neigh flush all
check "same user through the host (routed hairpin)" upi $P1 "$I2"
if upi $P1 "$I3"; then bad "routing through the host does not bypass isolation"; else ok "routing through the host does not bypass isolation"; fi

ip netns add fxs1; ip netns add fxs2
S1=$(ipof "$(cni ADD fxs1 /var/run/netns/fxs1 eth0 K8S_POD_NAME=s1 solo)")
S2=$(ipof "$(cni ADD fxs2 /var/run/netns/fxs2 eth0 K8S_POD_NAME=s2 solo)")
if nsping fxs1 "$S2"; then bad "isolation = container: same user blocked too"; else ok "isolation = container: same user blocked too"; fi
check "isolation = container: gateway reachable" nsping fxs1 10.236.0.1

# ---------------------------------------------------------------- trestlectl
say "trestlectl"
out=$(ctl status)
contains "status lists networks" "$out" "iso"
contains "status shows isolation" "$out" "user"
out=$(ctl list)
contains "root sees every attachment" "$out" "web3"
contains "root sees CNI pods" "$out" "fxa1"
out=$(ctl list --json)
check "list --json is JSON" python3 -c "import json,sys; json.loads(sys.argv[1])" "$out"
out=$(su $U1 -s /bin/sh -c "TRESTLE_CONFIG=$IT/trestle.conf $IT/bin/trestlectl list" 2>&1)
contains "user sees own attachments" "$out" "web1"
lacks "user does not see other users' attachments" "$out" "web3"
lacks "user does not see root's pods" "$out" "fxa1"
out=$(su $U1 -s /bin/sh -c "TRESTLE_CONFIG=$IT/trestle.conf $IT/bin/trestlectl leases" 2>&1)
contains "leases is root only" "$out" "only root"
out=$(su $U1 -s /bin/sh -c "TRESTLE_CONFIG=$IT/trestle.conf $IT/bin/trestlectl gc" 2>&1)
contains "gc is root only" "$out" "only root"
out=$(su $U1 -s /bin/sh -c "TRESTLE_CONFIG=$IT/trestle.conf $IT/bin/trestlectl detach iso iso3cccc" 2>&1)
contains "user cannot detach another user's container" "$out" "another user"
out=$(su $U1 -s /bin/sh -c "TRESTLE_CONFIG=$IT/trestle.conf $IT/bin/trestlectl detach iso iso2bbbb" 2>&1)
contains "user detaches own container" "$out" "detached iso iso2bbbb"
check "...its veth is gone" bash -c "! ip link show $(veth iso:$U1:web2)"
out=$(ctl leases)
contains "leases lists addresses" "$out" "$I1"
out=$(ctl list -n nosuchnet)
lacks "unknown network lists nothing" "$out" "trv"
out=$(ctl detach sec ../x)
contains "detach validates its arguments" "$out" "invalid"

# ---------------------------------------------------------------- stale state
say "stale state cleanup"
ip netns add fxg
G=$(cni ADD gc1 /var/run/netns/fxg eth0 K8S_POD_NAME=g1 sec); IG=$(ipof "$G")
ip link del "$(veth sec:root:g1)"          # host crash / runtime that never called DEL
printf 'ghost' > "$IT/state/ipam/sec/10.233.0.200"
out=$(ctl gc --dry-run)
contains "dry run finds the stale attachment" "$out" "sec gc1"
contains "dry run finds the orphaned lease" "$out" "10.233.0.200 ghost"
check "dry run changes nothing" test -f "$IT/state/attachments/sec/gc1"
contains "list marks it stale" "$(ctl list -n sec)" "STALE"
out=$(ctl gc)
contains "gc removes the stale attachment" "$out" "removed attachments: 1"
check "...its record" bash -c "! test -e $IT/state/attachments/sec/gc1"
check "...its lease" bash -c "! grep -rlx gc1 $IT/state/ipam/sec"
check "...the orphaned lease" bash -c "! test -e $IT/state/ipam/sec/10.233.0.200"
lacks "...and its anti-spoofing entry" "$(nft list set bridge trestlefx port_ip)" "$IG"
check "live attachments untouched" test -f "$IT/state/attachments/sec/fxa1"
if su $U1 -s /bin/sh -c "cat $IT/state/attachments/iso/iso1aaaa" >/dev/null 2>&1; then bad "records stay private"; else ok "records stay private"; fi
if su $U1 -s /bin/sh -c "ls $IT/state/ipam/sec" >/dev/null 2>&1; then bad "leases stay private"; else ok "leases stay private"; fi

G=$(cni ADD gc2 /var/run/netns/fxg eth0 K8S_POD_NAME=g2 sec)
ip link del "$(veth sec:root:g2)"
for _ in $(seq 25); do [ -e "$IT/state/attachments/sec/gc2" ] || break; sleep 1; done
check "periodic sweep (gc_interval) removes stale state" bash -c "! test -e $IT/state/attachments/sec/gc2"

G=$(cni ADD gc3 /var/run/netns/fxg eth0 K8S_POD_NAME=g3 sec)
stop_server
ip link del "$(veth sec:root:g3)"
start_server
check "sweep at daemon start" bash -c "! test -e $IT/state/attachments/sec/gc3"
check "live attachment survives the restart" test -f "$IT/state/attachments/sec/fxa1"

say "CNI GC and STATUS (CNI 1.1.0)"
ip netns add fxk1; ip netns add fxk2
cni ADD k1 /var/run/netns/fxk1 eth0 K8S_POD_NAME=k1 sec >/dev/null
cni ADD k2 /var/run/netns/fxk2 eth0 K8S_POD_NAME=k2 sec >/dev/null
out=$(printf '{"cniVersion":"1.1.0","name":"sec","type":"trestle","cni.dev/valid-attachments":[{"containerID":"k1","ifname":"eth0"},{"containerID":"fxa1","ifname":"eth0"},{"containerID":"fxb1","ifname":"eth0"}]}' |
	CNI_COMMAND=GC CNI_PATH=/opt/cni/bin "$IT/bin/trestle"; echo "rc=$?")
contains "GC succeeds without output" "$out" "rc=0"
check "GC removed the attachment not in the list" bash -c "! test -e $IT/state/attachments/sec/k2"
check "...and its veth" bash -c "! ip link show $(veth sec:root:k2)"
check "GC kept the listed attachment" test -f "$IT/state/attachments/sec/k1"
out=$(printf '{"cniVersion":"1.1.0","name":"iso","type":"trestle","cni.dev/valid-attachments":[]}' |
	CNI_COMMAND=GC CNI_PATH=/opt/cni/bin "$IT/bin/trestle"; echo "rc=$?")
check "root's CNI GC leaves rootless Netavark attachments alone" test -f "$IT/state/attachments/iso/iso1aaaa"
out=$(printf '{"cniVersion":"1.0.0","name":"sec","type":"trestle"}' | CNI_COMMAND=GC CNI_PATH=/x "$IT/bin/trestle")
contains "GC needs cniVersion 1.1.0" "$out" '"code":1'
out=$(printf '{"cniVersion":"1.1.0","name":"sec","type":"trestle"}' | CNI_COMMAND=STATUS "$IT/bin/trestle"; echo "rc=$?")
contains "STATUS ready" "$out" "rc=0"
ip netns add fxt1; ip netns add fxt2
cni ADD t1 /var/run/netns/fxt1 eth0 K8S_POD_NAME=t1 tiny >/dev/null
out=$(printf '{"cniVersion":"1.1.0","name":"tiny","type":"trestle"}' | CNI_COMMAND=STATUS "$IT/bin/trestle")
contains "STATUS reports an exhausted network (code 50)" "$out" '"code":50'
out=$(echo '{"cniVersion":"1.1.0"}' | CNI_COMMAND=VERSION "$IT/bin/trestle")
contains "VERSION includes 1.1.0" "$out" '"1.1.0"'
stop_server
out=$(printf '{"cniVersion":"1.1.0","name":"sec","type":"trestle"}' | CNI_COMMAND=STATUS "$IT/bin/trestle")
contains "STATUS with the daemon down: code 50" "$out" '"code":50'
start_server

# ---------------------------------------------------------------- DHCP
say "ipam = dhcp"
if [ -z "$DNSMASQ" ]; then
	echo "  skip (dnsmasq not installed)"
else
	"$DNSMASQ" --keep-in-foreground --conf-file=/dev/null --interface=trfx-lan --bind-interfaces --port=0 \
		--dhcp-range=192.168.77.100,192.168.77.150,255.255.255.0,2m --dhcp-option=3,192.168.77.1 \
		--dhcp-option=6,192.168.77.53 --dhcp-leasefile="$IT/dnsmasq.leases" --dhcp-authoritative \
		--log-dhcp --log-facility="$IT/dnsmasq.log" --pid-file="$IT/dnsmasq.pid" --user=root &
	sleep 0.5
	ip netns add fxd
	D=$(cni ADD dh1 /var/run/netns/fxd eth0 K8S_POD_NAME=dhcpweb lan)
	ID=$(ipof "$D")
	contains "lease from the LAN DHCP server" "$ID" "192.168.77.1"
	contains "gateway from the lease" "$D" '"gateway":"192.168.77.1"'
	contains "DNS servers from the lease" "$D" '"nameservers":["192.168.77.53"]'
	contains "container got the address" "$(ip -n fxd -4 addr show eth0)" "$ID/24"
	contains "container got the default route" "$(ip -n fxd route)" "default via 192.168.77.1"
	DV=$(veth lan:root:dhcpweb)
	KP=$(cat "$IT/state/dhcp/$DV.pid" 2>/dev/null)
	check "lease keeper running" test -n "$KP" -a -d "/proc/$KP"
	contains "the DHCP server saw the container's MAC" "$(cat "$IT/dnsmasq.leases")" "$(ip -n fxd -br link show eth0 | awk '{print $3}')"
	contains "container name sent as host name" "$(cat "$IT/dnsmasq.leases")" "dhcpweb"
	contains "leased address bound to the port (anti-spoofing)" "$(nft list set bridge trestlefx port_ip)" "\"$DV\" . $ID"
	contains "hosts entry with the leased address" "$(cat "$IT/hosts")" "$ID	root.dhcpweb.lan.trestle"
	check "container reaches the LAN" nsping fxd 192.168.77.1
	ip -n fxd addr add 192.168.77.222/24 dev eth0
	if ip netns exec fxd ping -c1 -W1 -I 192.168.77.222 192.168.77.1 >/dev/null 2>&1; then bad "address the server did not lease is dropped"; else ok "address the server did not lease is dropped"; fi
	ip -n fxd addr del 192.168.77.222/24 dev eth0

	stop_server
	start_server
	check "keeper survives a daemon restart" test -d "/proc/$KP"

	kill -9 "$KP"; sleep 0.5
	ctl gc >/dev/null
	KP2=$(cat "$IT/state/dhcp/$DV.pid" 2>/dev/null)
	check "gc restarts a lost keeper" test -n "$KP2" -a "$KP2" != "$KP" -a -d "/proc/$KP2"

	echo "  (waiting up to 80 s for the lease renewal at T1)"
	n0=$(grep -c "DHCPACK(trfx-lan) $ID" "$IT/dnsmasq.log")
	for _ in $(seq 80); do
		[ "$(grep -c "DHCPACK(trfx-lan) $ID" "$IT/dnsmasq.log")" -gt "$n0" ] && break
		sleep 1
	done
	[ "$(grep -c "DHCPACK(trfx-lan) $ID" "$IT/dnsmasq.log")" -gt "$n0" ] && ok "lease renewed by the keeper" || bad "lease renewed by the keeper"
	contains "renewal kept the address" "$(ip -n fxd -4 addr show eth0)" "$ID/24"

	P4=$(userns $U1); PIDS_NS="$PIDS_NS $P4"; sleep 0.3
	out=$(nv $U1 $P4 setup dhrootless dhcpuser lan)
	contains "rootless Netavark container gets a DHCP lease" "$out" '"ipnet":"192.168.77.1'
	contains "...with the DHCP DNS servers" "$out" '"dns_server_ips":["192.168.77.53"]'
	nv $U1 $P4 teardown dhrootless dhcpuser lan >/dev/null

	cni DEL dh1 /var/run/netns/fxd eth0 K8S_POD_NAME=dhcpweb lan >/dev/null
	sleep 0.5
	check "keeper stopped on DEL" gone "$KP2"
	contains "lease released on DEL" "$(cat "$IT/dnsmasq.log")" "DHCPRELEASE(trfx-lan) $ID"
	lacks "hosts entry removed" "$(cat "$IT/hosts")" "dhcpweb"
	check "user bridge left alone" ip link show trfx-lan
fi

# ---------------------------------------------------------------- server check
say "client verification of the server"
userctl() { su $U1 -s /bin/sh -c "TRESTLE_CONFIG=$IT/trestle.conf $IT/bin/trestlectl status" 2>&1; }
cp "$IT/trestle.conf" "$IT/trestle.conf.orig"
stop_server
sed -i "s|^server_binary = .*|server_binary = /usr/bin/false|" "$IT/trestle.conf"
start_server
contains "root-only socket directory: the server binary is not checked" "$(ctl status)" "NETWORK"
contains "...also not for rootless users" "$(userctl)" "NETWORK"
stop_server
sed -i "s|^\[global\]|[global]\nverify_server = strict|" "$IT/trestle.conf"
start_server
contains "verify_server = strict still checks the binary" "$(ctl status)" "refusing to talk to"
stop_server
cp "$IT/trestle.conf.orig" "$IT/trestle.conf"
mkdir -p "$IT/pub"; chmod 1777 "$IT/pub"
sed -i "s|^socket = .*|socket = $IT/pub/trestle.sock|; s|^server_binary = .*|server_binary = /usr/bin/false|" "$IT/trestle.conf"
start_server
contains "socket in a world-writable directory: the binary is checked" "$(ctl status)" "refusing to talk to"
contains "daemon warns about the world-writable socket directory" "$(cat "$IT/server.log")" "is world writable (sticky)"
stop_server
sed -i "s|^server_binary = .*|server_binary = $IT/bin/trestled|" "$IT/trestle.conf"
start_server
contains "...and accepted when it is trestled" "$(ctl status)" "NETWORK"
stop_server
cp "$IT/trestle.conf.orig" "$IT/trestle.conf"
start_server
check "back on the default layout" test -S "$IT/state/trestle.sock"

# ---------------------------------------------------------------- teardown
say "teardown"
cni DEL fxa1 /var/run/netns/fxa eth0 K8S_POD_NAME=a sec >/dev/null
cni DEL fxb1 /var/run/netns/fxb eth0 K8S_POD_NAME=b sec >/dev/null
cni DEL k1 /var/run/netns/fxk1 eth0 K8S_POD_NAME=k1 sec >/dev/null
cni DEL t1 /var/run/netns/fxt1 eth0 K8S_POD_NAME=t1 tiny >/dev/null
cni DEL fxs1 /var/run/netns/fxs1 eth0 K8S_POD_NAME=s1 solo >/dev/null
cni DEL fxs2 /var/run/netns/fxs2 eth0 K8S_POD_NAME=s2 solo >/dev/null
nv $U1 $P1 teardown iso1aaaa web1 iso >/dev/null
nv $U2 $P3 teardown iso3cccc web3 iso >/dev/null
check "no trestle veths left" bash -c "! ip -o link show | grep -q ': trv'"
check "port sets empty" bash -c "! nft list set bridge trestlefx ports | grep -q trv"
out=$(ctl list)
lacks "trestlectl list empty" "$out" "trv"
grep -E "ERROR|AddressSanitizer|runtime error" "$IT/server.log" | head -5
stop_server
echo
echo "features: $PASS passed, $FAIL failed"
[ $FAIL -eq 0 ]
