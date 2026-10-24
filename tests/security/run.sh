#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Hostile-input test for trestled, run as root:
#
#   tests/security/run.sh <build-dir>      (ideally built with ASan/UBSan)
#
# Starts a private trestled whose client_binary is the python interpreter,
# runs attack.py as an allowed user (in its own user+net namespace), as a
# user without permission and as root, then checks the daemon survived, no
# sanitizer reports were written, no interfaces / files were left behind and
# nothing hostile reached /etc/hosts-style or aardvark output.
set -u
BUILD=${1:?build dir}
HERE=$(cd "$(dirname "$0")" && pwd)
D=${TRESTLE_SEC_DIR:-/tmp/trestle-sec}
UA=trestle-sec-a
UC=trestle-sec-c
PY=$(readlink -f "$(command -v python3)")
PASS=0 FAIL=0 SERVER_PID=
ok()  { PASS=$((PASS+1)); echo "  ok   $*"; }
bad() { FAIL=$((FAIL+1)); echo "  FAIL $*"; }
links() { ip -o link show | awk -F': ' '{print $2}' | cut -d@ -f1 | grep -E '^(trv|tbr)' | sort; }

cleanup() {
	[ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null && wait "$SERVER_PID" 2>/dev/null
	[ -f "$D/aardvark/aardvark.pid" ] && kill "$(cat "$D/aardvark/aardvark.pid")" 2>/dev/null
	ip netns del trsec 2>/dev/null
	for l in $(links); do ip link del "$l" 2>/dev/null; done
	nft delete table inet trestlesec 2>/dev/null
	userdel -r $UA 2>/dev/null; userdel -r $UC 2>/dev/null
	rm -rf "$D" /tmp/trestle-pwned
}
trap cleanup EXIT
cleanup
useradd -m $UA; useradd -m $UC
mkdir -p "$D/state" "$D/aardvark" "$D/asan"; chmod 755 "$D"; chmod 1777 "$D/asan"
install -m 0755 "$BUILD/trestled" "$D/"
cp "$HERE/attack.py" "$D/"; chmod 644 "$D/attack.py"
printf '127.0.0.1 localhost\n' > "$D/hosts"
cat > "$D/aardvark-dns" <<'A'
#!/bin/sh
setsid sh -c 'echo $$ > "$1/aardvark.pid"; trap "" HUP; while :; do sleep 1; done' x "$2" >/dev/null 2>&1 &
sleep 0.2
A
chmod 755 "$D/aardvark-dns"
cat > "$D/trestle.conf" <<C
[global]
socket = $D/state/trestle.sock
client_binary = $PY
server_binary = $D/trestled
state_dir = $D/state
hosts_path = $D/hosts
request_timeout = 5
nft_table = trestlesec
aardvark_binary = $D/aardvark-dns
aardvark_dir = $D/aardvark
networkmanager = no
log_level = debug

[network:sec]
users = $UA, root
subnet = 10.77.0.1/24
hosts_file = yes
aardvark_dns = yes
dnsmasq_hosts = $D/dnsmasq-%n.hosts
firewall = yes
masquerade = yes
C
export ASAN_OPTIONS="log_path=$D/asan/asan:detect_leaks=0:abort_on_error=0"
export UBSAN_OPTIONS="log_path=$D/asan/ubsan:print_stacktrace=1"
"$D/trestled" -f -c "$D/trestle.conf" >"$D/server.log" 2>&1 &
SERVER_PID=$!
for _ in $(seq 50); do [ -S "$D/state/trestle.sock" ] && break; sleep 0.1; done
ip netns add trsec
BEFORE_LINKS=$(links)
BEFORE_FILES=$(find / -xdev -newer "$D/trestle.conf" -type f \( -path /proc -o -path /sys -o -path "$D" \) -prune -o -type f -print 2>/dev/null | grep -v "^$D" | sort)

echo "### attacker: allowed user"
su $UA -s /bin/sh -c "$PY $D/attack.py $D/state/trestle.sock user /run/netns/trsec" && ok "allowed-user attack cases" || bad "allowed-user attack cases"
echo "### attacker: user without permission"
out=$(su $UC -s /bin/sh -c "$PY $D/attack.py $D/state/trestle.sock user /run/netns/trsec" 2>&1)
# for this user every accept case must have failed with a permission error
if echo "$out" | grep -q "valid setup .*-> 0 "; then bad "unpermitted user got a setup through"; else ok "unpermitted user never attached"; fi
echo "### attacker: root"
$PY "$D/attack.py" "$D/state/trestle.sock" root /run/netns/trsec && ok "root attack cases" || bad "root attack cases"

echo "### slow clients"
# one user holding many connections, dripping a byte per second
su $UC -s /bin/sh -c "$PY - $D/state/trestle.sock" <<'P' &
import socket, sys, time
socks = []
for i in range(80):
    s = socket.socket(socket.AF_UNIX); s.connect(sys.argv[1]); socks.append(s)
for _ in range(25):
    for s in socks:
        try: s.send(b"T")
        except OSError: pass
    time.sleep(1)
P
DRIP=$!
sleep 3
t0=$(date +%s)
out=$(su $UA -s /bin/sh -c "$PY -c '
import socket,struct,sys
s=socket.socket(socket.AF_UNIX); s.settimeout(30); s.connect(\"$D/state/trestle.sock\")
s.sendall(struct.pack(\"=IHHI\",0x54525354,1,0,2)+b\"{}\"); s.shutdown(1)
d=s.recv(4096); print(\"answered\" if len(d)>=12 else \"closed\")
'" 2>&1)
t1=$(date +%s)
kill $DRIP 2>/dev/null; wait $DRIP 2>/dev/null
echo "  (other client: $out after $((t1-t0))s)"
if [ "$out" = answered ] && [ $((t1-t0)) -le 6 ]; then ok "dripping clients cannot starve other requests"; else bad "dripping clients starve other requests ($out, $((t1-t0))s)"; fi

echo "### side effects"
kill -0 $SERVER_PID 2>/dev/null && ok "daemon still running" || bad "daemon died"
[ -S "$D/state/trestle.sock" ] && ok "socket still there" || bad "socket gone"
[ "$(links)" = "$BEFORE_LINKS" ] && ok "no interfaces left behind" || bad "interfaces left: $(links | tr '\n' ' ')"
[ ! -e /tmp/trestle-pwned ] && ok "no injected command ran" || bad "/tmp/trestle-pwned exists"
grep -q "6.6.6.6\|evil" "$D/hosts" "$D"/dnsmasq-* "$D/aardvark/"* 2>/dev/null && bad "injected name reached DNS output" || ok "no injected names in hosts/dnsmasq/aardvark files"
[ "$(grep -c . "$D/hosts")" -le 3 ] && ok "hosts file clean" || bad "hosts file: $(cat "$D/hosts")"
ls -A "$D/state/attachments/sec" 2>/dev/null | grep -q . && bad "attachment records left: $(ls "$D/state/attachments/sec")" || ok "no attachment records left"
ls -A "$D/state/ipam/sec" 2>/dev/null | grep -v '^\.last$' | grep -q . && bad "leases left" || ok "no leases left"
find "$D/state" -name '*..*' -o -name '.*' ! -name .last ! -name '.' -print | grep -v '\.tmp' | grep -q . && bad "dot files in state: $(find "$D/state" -name '.*' ! -name .last)" || ok "no dot/traversal names in state"
AFTER_FILES=$(find / -xdev -newer "$D/trestle.conf" -type f \( -path /proc -o -path /sys -o -path "$D" \) -prune -o -type f -print 2>/dev/null | grep -v "^$D" | sort)
NEW=$(comm -13 <(echo "$BEFORE_FILES") <(echo "$AFTER_FILES") | grep -v -E '^/(root|home)/|^/var/log|^/tmp/claude|^/tmp/sort|\.pyc$')
[ -z "$NEW" ] && ok "no files written outside the state dir" || bad "new files: $NEW"
if ls "$D/asan/"* >/dev/null 2>&1; then bad "sanitizer reports:"; cat "$D/asan/"* | head -60; else ok "no ASan/UBSan reports"; fi
grep -c "" "$D/server.log" | xargs echo "  (server log lines:)"
grep -P '[\x00-\x08\x0b-\x1f]' "$D/server.log" | head -3 | cat -A | head -3
grep -n "trestle-pwned\|6.6.6.6" "$D/server.log" | head -5
cp "$D/server.log" "${TRESTLE_SEC_LOG:-/tmp/trestle-sec-server.log}"
echo; echo "passed $PASS, failed $FAIL"
[ $FAIL -eq 0 ]
