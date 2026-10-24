#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
#
# End-to-end test for trestle. Must run as root on a kernel with bridge,
# veth and user namespace support. It creates temporary users, network
# namespaces, bridges and an nftables table, and removes them afterwards.
#
#   tests/integration/run.sh <build-dir>
#
set -u

BUILD=${1:-}
if [ -z "$BUILD" ]; then BUILD="$(cd "$(dirname "$0")/../.." && pwd)/build"; fi
IT=${TRESTLE_IT_DIR:-/tmp/trestle-it}
U1=trestle-it-a       # allowed user
U2=trestle-it-b       # allowed through @trestle-it-grp
U3=trestle-it-c       # not allowed
GRP=trestle-it-grp
PASS=0
FAIL=0
SERVER_PID=

say()  { printf '\n### %s\n' "$*"; }
ok()   { PASS=$((PASS + 1)); printf '  ok   %s\n' "$*"; }
bad()  { FAIL=$((FAIL + 1)); printf '  FAIL %s\n' "$*"; }
check() { local d=$1; shift; if "$@" >/dev/null 2>&1; then ok "$d"; else bad "$d"; fi; }
contains() { local d=$1 hay=$2 needle=$3; if [[ "$hay" == *"$needle"* ]]; then ok "$d"; else bad "$d (got: $hay)"; fi; }

if [ "$(id -u)" != 0 ]; then echo "must run as root"; exit 77; fi
for t in ip unshare su useradd nft; do
	command -v $t >/dev/null || { echo "missing tool: $t"; exit 77; }
done

# firewalld checks run when a firewalld is reachable (override the client
# with TRESTLE_IT_FIREWALL_CMD)
FWC=${TRESTLE_IT_FIREWALL_CMD:-/usr/bin/firewall-cmd}
FWOK=0
if [ -x "$FWC" ] && "$FWC" --state >/dev/null 2>&1; then FWOK=1; fi
fwzone() { "$FWC" --get-zone-of-interface="$1" 2>/dev/null; }

cleanup() {
	[ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null && wait "$SERVER_PID" 2>/dev/null
	[ -f "$IT/fake-aardvark.pid" ] && kill "$(cat "$IT/fake-aardvark.pid")" 2>/dev/null
	pkill -f "$IT/fakeserver.py" 2>/dev/null
	for ns in trit1 trit2 trit3 tritc1 tritc2 tritc3 tritc4 tritc5 tritc6; do ip netns del $ns 2>/dev/null; done
	for l in $(ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | cut -d@ -f1 | grep -E '^(trv|tbr)|^trit-br'); do
		ip link del "$l" 2>/dev/null
	done
	nft delete table inet trestleit 2>/dev/null
	for u in $U1 $U2 $U3; do userdel -r $u 2>/dev/null; done
	groupdel $GRP 2>/dev/null
	rm -rf "$IT"
}
trap cleanup EXIT
cleanup

# ---------------------------------------------------------------- setup
groupadd $GRP
useradd -m $U1; useradd -m -G $GRP $U2; useradd -m $U3
mkdir -p "$IT/bin" "$IT/state" "$IT/aardvark"
chmod 755 "$IT"
install -m 0755 "$BUILD/trestle" "$BUILD/trestled" "$IT/bin/"
printf '127.0.0.1 localhost\n' > "$IT/hosts"

# fake aardvark-dns: daemonizes, writes aardvark.pid, logs SIGHUPs
cat > "$IT/bin/aardvark-dns" <<'EOF'
#!/bin/sh
dir=$2
setsid sh -c 'echo $$ > "$1/aardvark.pid"; echo $$ > "$1/../fake-aardvark.pid"; trap "echo hup >> $1/../hups" HUP; trap "exit 0" TERM; while :; do sleep 1; done' x "$dir" >/dev/null 2>&1 &
sleep 0.3
exit 0
EOF
chmod 755 "$IT/bin/aardvark-dns"

# fake nmcli: NetworkManager "running", logs every call
cat > "$IT/bin/nmcli" <<EOF
#!/bin/sh
echo "\$*" >> $IT/nmcli.log
[ "\$1" = "-t" ] && echo running
exit 0
EOF
chmod 755 "$IT/bin/nmcli"

cat > "$IT/trestle.conf" <<EOF
[global]
socket = $IT/trestle.sock
socket_mode = 0777
client_binary = $IT/bin/trestle
server_binary = $IT/bin/trestled
state_dir = $IT/state
hosts_path = $IT/hosts
log_level = debug
nft_table = trestleit
aardvark_binary = $IT/bin/aardvark-dns
aardvark_dir = $IT/aardvark
networkmanager = yes
firewall_cmd = $FWC
nmcli_binary = $IT/bin/nmcli

[network:itnet]
users = root, $U1, @$GRP, !nobody
firewalld_zone = trusted
subnet = 10.231.0.1/24
mtu = 1400
hosts_file = yes
dnsmasq_hosts = $IT/itnet.hosts
aardvark_dns = yes
firewall = yes
masquerade = yes
allow_inbound = tcp:80, icmp
create_script = $IT/hooks/hook.sh
setup_script = $IT/hooks/hook.sh
teardown_script = $IT/hooks/hook.sh
script_timeout = 10

[network:itfail]
users = root
subnet = 10.232.0.1/24
setup_script = $IT/hooks/fail.sh
teardown_script = $IT/hooks/fail.sh
script_on_error = fail

[network:*]
users = root, $U1
firewalld_zone = trusted
subnet_pool = 10.240.0.0/16
subnet_prefix = 24
hosts_file = yes
firewall = yes
masquerade = yes
EOF
# a wrapped daemon (valgrind) is a different binary, so skip that check
if [ -n "${TRESTLE_IT_WRAPPER:-}" ]; then sed -i "s|^\[global\]|[global]\nverify_server = no|" "$IT/trestle.conf"; fi
chmod 644 "$IT/trestle.conf"
export TRESTLE_CONFIG=$IT/trestle.conf

# hook scripts: record their environment, and look inside the container
# network namespace through the fd they receive
mkdir -p "$IT/hooks/out"
chmod 755 "$IT/hooks"
cat > "$IT/hooks/hook.sh" <<EOF
#!/bin/sh
f=$IT/hooks/out/\$1-\${TRESTLE_CONTAINER_ID:-network}.env
env | sort > "\$f"
if [ "\$1" = setup ] && [ -n "\$TRESTLE_NETNS_FD" ]; then
	nsenter --net=/proc/self/fd/\$TRESTLE_NETNS_FD ip -4 -o addr show dev "\$TRESTLE_CONTAINER_IFNAME" >> "\$f" 2>&1
fi
echo "hook \$1 done for \$TRESTLE_NETWORK"
EOF
printf '#!/bin/sh\necho "refusing $TRESTLE_CONTAINER_NAME" >&2\nexit 7\n' > "$IT/hooks/fail.sh"
chmod 755 "$IT/hooks/hook.sh" "$IT/hooks/fail.sh"
HO=$IT/hooks/out

# a stale file at the socket path must be removed by the server
touch "$IT/trestle.sock"

# TRESTLE_IT_WRAPPER can run the daemon under e.g. valgrind
${TRESTLE_IT_WRAPPER:-} "$IT/bin/trestled" -f -c "$IT/trestle.conf" >"$IT/server.log" 2>&1 &
SERVER_PID=$!
for _ in $(seq 100); do [ -S "$IT/trestle.sock" ] && break; sleep 0.1; done

say "daemon start"
check "socket created" test -S "$IT/trestle.sock"
contains "socket mode 0777" "$(stat -c %a "$IT/trestle.sock")" "777"
check "nftables table applied" nft list table inet trestleit
contains "masquerade rule" "$(nft list table inet trestleit)" "masquerade"

CNI='{"cniVersion":"1.0.0","name":"itnet","type":"trestle"}'
cni() { # cmd id netns ifname args [conf]
	echo "${6:-$CNI}" | CNI_COMMAND=$1 CNI_CONTAINERID=$2 CNI_NETNS=$3 CNI_IFNAME=$4 CNI_PATH=/opt/cni/bin \
		CNI_ARGS=$5 "$IT/bin/trestle"
}
BR=tbr$(printf itnet | md5sum | cut -c1-12)

# ---------------------------------------------------------------- CNI as root
say "CNI (root, Kubernetes style)"
ip netns add trit1; ip netns add trit2; ip netns add trit3
out=$(cni ADD pod1 /var/run/netns/trit1 eth0 "K8S_POD_NAMESPACE=default;K8S_POD_NAME=web")
contains "ADD returns CNI result" "$out" '"ips":[{"address":"10.231.0.2/24","gateway":"10.231.0.1","interface":1}]'
contains "create hook ran when the bridge was created" "$(cat $HO/create-network.env 2>/dev/null)" "TRESTLE_BRIDGE_CREATED=1"
contains "create hook got bridge name" "$(cat $HO/create-network.env 2>/dev/null)" "TRESTLE_BRIDGE=tbr"
SE=$(cat $HO/setup-pod1.env 2>/dev/null)
contains "setup hook: network" "$SE" "TRESTLE_NETWORK=itnet"
contains "setup hook: container id" "$SE" "TRESTLE_CONTAINER_ID=pod1"
contains "setup hook: container name" "$SE" "TRESTLE_CONTAINER_NAME=default-web"
contains "setup hook: k8s pod" "$SE" "TRESTLE_K8S_POD_NAME=web"
contains "setup hook: k8s namespace" "$SE" "TRESTLE_K8S_POD_NAMESPACE=default"
contains "setup hook: user" "$SE" "TRESTLE_USER=root"
contains "setup hook: ip" "$SE" "TRESTLE_IP_CIDR=10.231.0.2/24"
contains "setup hook: gateway" "$SE" "TRESTLE_GATEWAY=10.231.0.1"
contains "setup hook: container ifname" "$SE" "TRESTLE_CONTAINER_IFNAME=eth0"
contains "setup hook: mode" "$SE" "TRESTLE_MODE=cni"
contains "setup hook: fqdn" "$SE" "TRESTLE_FQDN=root.default-web.itnet.trestle"
contains "setup hook can enter container netns via fd" "$SE" "inet 10.231.0.2/24"
contains "hook output logged" "$(cat $IT/server.log)" "setup_script[itnet]: hook setup done for itnet"
VETH=trv$(printf 'itnet:root:default-web' | md5sum | cut -c1-12)
contains "setup hook: host ifname" "$(cat $HO/setup-pod1.env 2>/dev/null)" "TRESTLE_HOST_IFNAME=$VETH"
contains "host veth named trv+md5(network:user:container)" "$out" "\"name\":\"$VETH\""
check "bridge $BR exists" ip link show "$BR"
contains "NetworkManager checked before creating the bridge" "$(cat $IT/nmcli.log 2>/dev/null)" "-t -f RUNNING general"
contains "new bridge marked unmanaged in NetworkManager" "$(cat $IT/nmcli.log 2>/dev/null)" "device set $BR managed no"
contains "bridge address" "$(ip -4 addr show "$BR")" "10.231.0.1/24"
contains "veth enslaved to bridge" "$(ip link show "$VETH")" "master $BR"
contains "veth alias" "$(ip link show "$VETH")" "alias trestle:root.default-web.itnet"
if [ $FWOK = 1 ]; then
	contains "bridge put into firewalld zone trusted" "$(fwzone $BR)" "trusted"
	"$FWC" --reload >/dev/null    # drops runtime interface bindings
	if [ "$(fwzone $BR)" = trusted ]; then bad "firewalld reload removed the binding (sanity)"
	else ok "firewalld reload removed the binding (sanity)"; fi
fi
contains "MTU applied" "$(ip netns exec trit1 ip link show eth0)" "mtu 1400"
contains "container address" "$(ip netns exec trit1 ip -4 addr show eth0)" "10.231.0.2/24"
contains "container default route" "$(ip netns exec trit1 ip route)" "default via 10.231.0.1"

out=$(cni ADD pod2 /var/run/netns/trit2 eth0 "K8S_POD_NAMESPACE=prod;K8S_POD_NAME=db;IP=10.231.0.77")
contains "static IP via CNI_ARGS" "$out" "10.231.0.77/24"
[ $FWOK = 1 ] && contains "zone restored on next attach after firewalld reload" "$(fwzone $BR)" "trusted"
out=$(cni ADD pod3 /var/run/netns/trit3 eth0 "K8S_POD_NAME=x;IP=10.231.0.77")
contains "static IP conflict rejected" "$out" "already in use"
out=$(cni ADD pod4 /var/run/netns/trit3 eth0 "K8S_POD_NAMESPACE=default;K8S_POD_NAME=web")
contains "veth name collision rejected" "$out" "already exists"
out=$(cni ADD pod5 /proc/self/ns/net eth5 "K8S_POD_NAME=evil")
contains "host netns rejected" "$out" "host network namespace"
out=$(cni ADD pod6 /var/run/netns/trit3 eth0 "" '{"cniVersion":"1.0.0","name":"itnet"')
contains "invalid JSON rejected by client" "$out" '"code":6'

FAILNET='{"cniVersion":"1.0.0","name":"itfail","type":"trestle"}'
out=$(cni ADD failpod /var/run/netns/trit3 eth3 "K8S_POD_NAME=nope" "$FAILNET")
contains "failing setup hook rejects ADD (script_on_error=fail)" "$out" "exited with status 7"
contains "failing hook stderr logged" "$(cat $IT/server.log)" "refusing nope"
check "failed ADD rolled back the veth" bash -c "! ip netns exec trit3 ip link show eth3"
check "failed ADD released the lease" bash -c "[ -z \"\$(ls $IT/state/ipam/itfail 2>/dev/null)\" ]"
check "failed ADD removed the new bridge" bash -c "! ip link show tbr$(printf itfail | md5sum | cut -c1-12)"
out=$(cni DEL failpod /var/run/netns/trit3 eth3 "K8S_POD_NAME=nope" "$FAILNET"; echo "rc=$?")
contains "failing teardown hook never blocks DEL" "$out" "rc=0"

if command -v ping >/dev/null; then
	check "container -> bridge ping" ip netns exec trit1 ping -c1 -W2 10.231.0.1
	check "container -> container ping" ip netns exec trit1 ping -c1 -W2 10.231.0.77
fi
out=$(cni CHECK pod1 /var/run/netns/trit1 eth0 "K8S_POD_NAMESPACE=default;K8S_POD_NAME=web"; echo "rc=$?")
contains "CHECK succeeds" "$out" "rc=0"

# a client that connects and stalls must not block other requests
python3 -c "import socket,time,sys; s=socket.socket(socket.AF_UNIX); s.connect(sys.argv[1]); time.sleep(8)" "$IT/trestle.sock" &
STALL=$!
sleep 0.3
start=$(date +%s)
out=$(cni CHECK pod1 /var/run/netns/trit1 eth0 "K8S_POD_NAMESPACE=default;K8S_POD_NAME=web"; echo "rc=$?")
elapsed=$(( $(date +%s) - start ))
contains "request served while another client stalls" "$out" "rc=0"
check "no head-of-line blocking (${elapsed}s)" test "$elapsed" -lt 4
kill $STALL 2>/dev/null; wait $STALL 2>/dev/null

# concurrent ADDs get distinct addresses (state lock)
for i in 1 2 3 4 5 6; do ip netns add tritc$i; done
PIDS=
for i in 1 2 3 4 5 6; do
	cni ADD par$i /var/run/netns/tritc$i eth0 "K8S_POD_NAME=par$i" > "$IT/par$i.out" &
	PIDS="$PIDS $!"
done
wait $PIDS
ips=$(cat "$IT"/par*.out | grep -o '"address":"[0-9.]*' | sort -u | wc -l)
contains "6 parallel ADDs got 6 distinct addresses" "$ips" "6"
for i in 1 2 3 4 5 6; do cni DEL par$i /var/run/netns/tritc$i eth0 "K8S_POD_NAME=par$i" >/dev/null; ip netns del tritc$i; done

contains "/etc/hosts entry" "$(cat "$IT/hosts")" "10.231.0.2	root.default-web.itnet.trestle"
contains "dnsmasq hosts entry" "$(cat "$IT/itnet.hosts")" "10.231.0.77	root.prod-db.itnet.trestle"

cp "$IT/bin/trestle" "$IT/impostor"
out=$(echo "$CNI" | CNI_COMMAND=ADD CNI_CONTAINERID=imp CNI_NETNS=/var/run/netns/trit3 CNI_IFNAME=eth0 CNI_PATH=/x "$IT/impostor")
contains "impostor client binary rejected" "$out" "not the trestle client"

out=$(echo '{"cniVersion":"0.4.0"}' | CNI_COMMAND=VERSION "$IT/bin/trestle")
contains "VERSION answered locally" "$out" '"supportedVersions":["0.3.0","0.3.1","0.4.0","1.0.0"]'

# ---------------------------------------------------------------- Netavark rootless
say "Netavark (rootless users in user namespaces)"
mkjson() { # id name
	cat <<EOF
{"container_id":"$1","container_name":"$2","port_mappings":[],
 "network":{"dns_enabled":true,"driver":"trestle","id":"n1","internal":false,"ipv6_enabled":false,"name":"itnet","network_interface":"$BR","options":null,"ipam_options":{"driver":"none"},"subnets":[]},
 "network_options":{"aliases":["$2-alias"],"interface_name":"eth0"}}
EOF
}
mkjson aaaa1111 webapp > "$IT/a.json"; mkjson bbbb2222 webapp > "$IT/b.json"; chmod 644 "$IT"/*.json
# run the client as <user> inside a fresh user+network namespace; keep the
# namespace alive with a background sleep so teardown can be tested later
rootless() { # user json cmd -> prints output
	su "$1" -s /bin/bash -c "TRESTLE_CONFIG=$IT/trestle.conf unshare -U -r -n bash -c '
		$IT/bin/trestle $3 /proc/self/ns/net < $2; echo rc=\$?; ip -4 -o addr show eth0 2>/dev/null; ip route 2>/dev/null'"
}
out=$(rootless $U1 "$IT/a.json" setup)
contains "user A setup succeeds" "$out" "rc=0"
contains "user A gets status block" "$out" '"interfaces":{"eth0":{"mac_address"'
contains "user A dns server = bridge" "$out" '"dns_server_ips":["10.231.0.1"]'
contains "address inside user namespace" "$out" "10.231.0."
contains "default route inside user namespace" "$out" "default via 10.231.0.1"
out=$(rootless $U2 "$IT/b.json" setup)
contains "user B (via group) setup with same container name" "$out" "rc=0"
out=$(rootless $U3 "$IT/a.json" setup)
contains "user C denied" "$out" "is not permitted to use network 'itnet'"
out=$(rootless $U2 "$IT/a.json" teardown)
contains "user B cannot tear down user A's container" "$out" "belongs to another user"

AFILE=$IT/aardvark/itnet
contains "aardvark config has gateway" "$(head -1 "$AFILE" 2>/dev/null)" "10.231.0.1"
contains "aardvark entry for user A" "$(cat "$AFILE" 2>/dev/null)" "aaaa1111 10.231.0."
contains "aardvark names" "$(cat "$AFILE" 2>/dev/null)" "webapp,webapp-alias,$U1.webapp.itnet.trestle"
check "aardvark-dns started" test -s "$IT/aardvark/aardvark.pid"
for _ in $(seq 30); do [ -s "$IT/hups" ] && break; sleep 0.1; done
check "aardvark-dns got SIGHUP on update" test -s "$IT/hups"
contains "hosts has rootless entry" "$(cat "$IT/hosts")" "$U1.webapp.itnet.trestle"

RE=$(cat $HO/setup-aaaa1111.env 2>/dev/null)
contains "rootless setup hook: user" "$RE" "TRESTLE_USER=$U1"
contains "rootless setup hook: rootless flag" "$RE" "TRESTLE_ROOTLESS=1"
contains "rootless setup hook: aliases" "$RE" "TRESTLE_CONTAINER_ALIASES=webapp-alias"
contains "rootless setup hook: mode" "$RE" "TRESTLE_MODE=netavark"
contains "rootless setup hook enters the user's netns via fd" "$RE" "inet 10.231.0."
out=$(rootless $U1 "$IT/a.json" teardown)
contains "user A teardown" "$out" "rc=0"
TE=$(cat $HO/teardown-aaaa1111.env 2>/dev/null)
contains "teardown hook: event" "$TE" "TRESTLE_EVENT=teardown"
contains "teardown hook: host ifname" "$TE" "TRESTLE_HOST_IFNAME=trv"
contains "teardown hook: ip" "$TE" "TRESTLE_IP=10.231.0."
contains "teardown hook: container name" "$TE" "TRESTLE_CONTAINER_NAME=webapp"
out=$(rootless $U2 "$IT/b.json" teardown)
contains "user B teardown" "$out" "rc=0"
if grep -q aaaa1111 "$AFILE" 2>/dev/null; then bad "aardvark entry removed"; else ok "aardvark entry removed"; fi
if grep -q "$U1" "$IT/hosts"; then bad "hosts entry removed"; else ok "hosts entry removed"; fi

out=$(echo '{"name":"itnet","id":"abc","driver":"trestle","network_interface":"","subnets":[],"ipv6_enabled":false,"internal":false,"dns_enabled":false,"ipam_options":{"driver":"host-local"},"options":{}}' > "$IT/create.json"; chmod 644 "$IT/create.json"; su $U1 -s /bin/sh -c "TRESTLE_CONFIG=$IT/trestle.conf $IT/bin/trestle create < $IT/create.json")
contains "create fills bridge name" "$out" "\"network_interface\":\"$BR\""
contains "netavark create hook: podman network id" "$(cat $HO/create-network.env)" "TRESTLE_PODMAN_NETWORK_ID=abc"
contains "netavark create hook: user" "$(cat $HO/create-network.env)" "TRESTLE_USER=$U1"
contains "create sets ipam none" "$out" '"ipam_options":{"driver":"none"}'
out=$(echo '{"name":"itnet","id":"abc","driver":"trestle","subnets":[{"subnet":"192.168.0.0/24"}]}' | "$IT/bin/trestle" create)
contains "create rejects conflicting subnet" "$out" "conflicts with the trestle subnet"
out=$("$IT/bin/trestle" info)
contains "info api_version" "$out" '"api_version":"1.0.0"'

# ---------------------------------------------------------------- client checks the server
if [ -z "${TRESTLE_IT_WRAPPER:-}" ]; then
say "client verifies the server"
cat > "$IT/fakeserver.py" <<EOF
import socket, os, sys, time
p = sys.argv[1]
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.bind(p); os.chmod(p, 0o777); s.listen(1)
time.sleep(30)
EOF
chmod 644 "$IT/fakeserver.py"
mkdir -p "$IT/fake"; chown $U3 "$IT/fake"
sed "s|^socket = .*|socket = $IT/fake/fake.sock|" "$IT/trestle.conf" > "$IT/fake.conf"; chmod 644 "$IT/fake.conf"
su $U3 -s /bin/sh -c "python3 $IT/fakeserver.py $IT/fake/fake.sock" &
for _ in $(seq 30); do [ -S "$IT/fake/fake.sock" ] && break; sleep 0.1; done
out=$(cni_fake() { echo "$CNI" | TRESTLE_CONFIG=$IT/fake.conf CNI_COMMAND=ADD CNI_CONTAINERID=f CNI_NETNS=/var/run/netns/trit3 CNI_IFNAME=eth0 CNI_PATH=/x "$IT/bin/trestle"; }; cni_fake)
contains "client refuses a socket served by a non-root process" "$out" "not root"
pkill -f "$IT/fakeserver.py"
fi

# ---------------------------------------------------------------- reload
say "[network:*] catch-all"
WNS='{"cniVersion":"1.0.0","name":"wild1","type":"trestle"}'
WBR=tbr$(printf wild1 | md5sum | cut -c1-12)
out=$(cni ADD w1 /var/run/netns/trit3 ew1 "K8S_POD_NAME=w1" "$WNS")
contains "unconfigured network accepted through [network:*]" "$out" '"address":"10.240.0.2/24","gateway":"10.240.0.1"'
check "catch-all network got its own bridge" ip link show "$WBR"
[ $FWOK = 1 ] && contains "[network:*] bridge in its firewalld zone" "$(fwzone $WBR)" "trusted"
contains "bridge has the first pool subnet" "$(ip -4 addr show $WBR)" "10.240.0.1/24"
contains "nftables masquerade for the new subnet" "$(nft list table inet trestleit)" "ip saddr 10.240.0.0/24"
contains "hosts entry for catch-all network" "$(cat $IT/hosts)" "root.w1.wild1.trestle"
out=$(cni ADD w2 /var/run/netns/trit3 ew2 "K8S_POD_NAME=w2" '{"cniVersion":"1.0.0","name":"wild2","type":"trestle"}')
contains "second catch-all network gets the next /24" "$out" '"address":"10.240.1.2/24"'
out=$("$IT/bin/trestled" -t -c "$IT/trestle.conf")
contains "trestled -t lists catch-all networks" "$out" "wild2"
cat > "$IT/w3.json" <<EOF
{"container_id":"cccc3333","container_name":"wapp","port_mappings":[],
 "network":{"driver":"trestle","id":"n3","name":"wild3","subnets":[]},
 "network_options":{"interface_name":"eth0"}}
EOF
chmod 644 "$IT/w3.json"
out=$(rootless $U1 "$IT/w3.json" setup)
contains "rootless user allowed by [network:*] users" "$out" '"ipnet":"10.240.2.2/24"'
out=$(rootless $U3 "$IT/w3.json" setup)
contains "user not in [network:*] users is denied" "$out" "is not permitted to use network 'wild3'"
rootless $U1 "$IT/w3.json" teardown >/dev/null
out=$(cni ADD w4 /var/run/netns/trit3 ew4 "K8S_POD_NAME=w4" '{"cniVersion":"1.0.0","name":"itnet","type":"trestle"}')
contains "explicit section still wins over [network:*]" "$out" '"gateway":"10.231.0.1"'
cni DEL w4 /var/run/netns/trit3 ew4 "K8S_POD_NAME=w4" '{"cniVersion":"1.0.0","name":"itnet","type":"trestle"}' >/dev/null
cni DEL w1 /var/run/netns/trit3 ew1 "K8S_POD_NAME=w1" "$WNS" >/dev/null
cni DEL w2 /var/run/netns/trit3 ew2 "K8S_POD_NAME=w2" '{"cniVersion":"1.0.0","name":"wild2","type":"trestle"}' >/dev/null
check "catch-all bridge removed after last container" bash -c "! ip link show $WBR"
out=$(cni ADD w1 /var/run/netns/trit3 ew1 "K8S_POD_NAME=w1" "$WNS")
contains "network keeps its subnet after the bridge was removed" "$out" '"gateway":"10.240.0.1"'
cni DEL w1 /var/run/netns/trit3 ew1 "K8S_POD_NAME=w1" "$WNS" >/dev/null

say "reload"
# drop the catch-all: unconfigured networks must be refused again
sed -i '/^\[network:\*\]/,$d' "$IT/trestle.conf"
cat >> "$IT/trestle.conf" <<EOF

[network:itnet2]
users = *
bridge = trit-br0
EOF
kill -HUP $SERVER_PID; sleep 1.5
out=$(cni ADD pod9 /var/run/netns/trit3 eth1 "K8S_POD_NAME=late" '{"cniVersion":"1.0.0","name":"itnet2","type":"trestle"}')
contains "network added by SIGHUP reload is usable" "$out" '"name":"eth1"'
contains "network without subnet returns no ips" "$out" '"dns":{}'
out=$(cni ADD pod6 /var/run/netns/trit3 eth0 "" '{"cniVersion":"1.0.0","name":"other","type":"trestle"}')
contains "unconfigured network rejected without [network:*]" "$out" "not permitted by trestle"
cni DEL pod9 /var/run/netns/trit3 eth1 "K8S_POD_NAME=late" '{"cniVersion":"1.0.0","name":"itnet2","type":"trestle"}' >/dev/null
check "trestle-created configured bridge removed when empty" bash -c "! ip link show trit-br0"

# pre-existing bridge is never deleted
ip link add trit-br0 type bridge
out=$(cni ADD pod9 /var/run/netns/trit3 eth1 "K8S_POD_NAME=late" '{"cniVersion":"1.0.0","name":"itnet2","type":"trestle"}')
cni DEL pod9 /var/run/netns/trit3 eth1 "K8S_POD_NAME=late" '{"cniVersion":"1.0.0","name":"itnet2","type":"trestle"}' >/dev/null
check "pre-existing bridge kept" ip link show trit-br0
contains "only bridges trestle creates are passed to nmcli" "$(grep -c 'device set trit-br0 managed no' $IT/nmcli.log)" "1"
ip link del trit-br0

# ---------------------------------------------------------------- teardown
say "CNI DEL"
out=$(cni DEL pod1 /var/run/netns/trit1 eth0 "K8S_POD_NAMESPACE=default;K8S_POD_NAME=web"; echo "rc=$?")
contains "DEL pod1" "$out" "rc=0"
out=$(cni DEL pod2 "" eth0 "K8S_POD_NAMESPACE=prod;K8S_POD_NAME=db"; echo "rc=$?")
contains "DEL without netns" "$out" "rc=0"
out=$(cni DEL pod2 "" eth0 "K8S_POD_NAMESPACE=prod;K8S_POD_NAME=db"; echo "rc=$?")
contains "DEL is idempotent" "$out" "rc=0"
check "veth removed" bash -c "! ip link show $VETH"
check "bridge removed after last container" bash -c "! ip link show $BR"
if [ $FWOK = 1 ]; then
	if "$FWC" --zone=trusted --list-interfaces | grep -qw "$BR"; then bad "removed bridge taken out of firewalld zone"
	else ok "removed bridge taken out of firewalld zone"; fi
fi
if grep -q "trestle managed" "$IT/hosts"; then bad "hosts block removed"; else ok "hosts block removed"; fi
check "no IP leases left" bash -c "[ -z \"\$(ls $IT/state/ipam/itnet)\" ]"

say "shutdown"
kill $SERVER_PID; wait $SERVER_PID 2>/dev/null; SERVER_PID=
[ -n "${TRESTLE_IT_WRAPPER:-}" ] && cp "$IT/server.log" "${TRESTLE_IT_LOG:-/dev/null}"
check "socket removed on exit" bash -c "! test -e $IT/trestle.sock"
check "nftables table removed on exit" bash -c "! nft list table inet trestleit"

if [ $FAIL -ne 0 ]; then
	echo; echo "---- server log (tail) ----"; tail -40 "$IT/server.log"
fi
echo
echo "integration: $PASS passed, $FAIL failed"
[ $FAIL -eq 0 ]
