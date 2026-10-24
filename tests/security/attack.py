#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Hostile-client test for trestled. Talks the wire protocol directly (the
# daemon must be configured with client_binary = this python interpreter so
# requests get past the binary check) and sends malformed frames, bad file
# descriptors, corrupt JSON and injection payloads.
#
#   attack.py SOCKET MODE [ROOT_NETNS_PATH]
#
# MODE "user": runs as an unprivileged user, moves itself into a new user +
#              network namespace (like rootless Podman) and attacks the
#              Netavark and CNI paths.
# MODE "root": runs as root and attacks the path-based (Kubernetes) CNI path.
#
# Every case states what the daemon must do: "reject" (non-zero exit with an
# error message, or the connection closed) or "accept". Prints one line per
# case and exits non-zero if any case behaved unexpectedly. Side effects
# (links, files, hosts entries) are checked by run.sh afterwards.
import json
import os
import socket
import struct
import sys
import time

REQ_MAGIC = 0x54525354
RESP_MAGIC = 0x54525350
SOCK = sys.argv[1]
MODE = sys.argv[2]
ROOT_NS = sys.argv[3] if len(sys.argv) > 3 else None

results = []
failures = 0


def frame(body, flags=0, magic=REQ_MAGIC, version=1, length=None):
    if isinstance(body, str):
        body = body.encode("utf-8", "surrogatepass")
    if length is None:
        length = len(body)
    return struct.pack("=IHHI", magic, version, flags, length) + body


def exchange(raw, fds=(), timeout=15, chunks=None, shut=True):
    """Send raw bytes (first byte carries fds). Returns (exit, text) or
    ("closed", "") / ("timeout", "")."""
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect(SOCK)
    try:
        if fds:
            socket.send_fds(s, [raw[:1]], list(fds))
            raw = raw[1:]
        if chunks:
            for c in chunks:
                s.sendall(c)
                time.sleep(0.05)
        elif raw:
            s.sendall(raw)
        if shut:
            s.shutdown(socket.SHUT_WR)
        data = b""
        while True:
            try:
                b = s.recv(65536)
            except (ConnectionResetError, BrokenPipeError):
                break
            if not b:
                break
            data += b
    except socket.timeout:
        return ("timeout", "")
    except (BrokenPipeError, ConnectionResetError):
        return ("closed", "")
    finally:
        s.close()
    if len(data) < 12:
        return ("closed", data.decode(errors="replace"))
    magic, code, ln = struct.unpack("=IiI", data[:12])
    if magic != RESP_MAGIC:
        return ("badmagic", repr(data[:40]))
    return (code, data[12:12 + ln].decode(errors="replace"))


def case(name, expect, raw=None, fds=(), **kw):
    global failures
    code, text = exchange(raw if raw is not None else b"", fds, **kw)
    if expect == "either":       # a documented lenient case; clean up if it attached
        ok = isinstance(code, int)
        if code == 0:
            undo(raw, fds)
    elif expect == "reject":
        ok = code in ("closed",) or (isinstance(code, int) and code != 0)
        if isinstance(code, int) and code != 0:
            try:
                j = json.loads(text)
                ok = isinstance(j, dict) and ("error" in j or "msg" in j)
            except ValueError:
                ok = False
    else:
        ok = code == 0
    if not ok:
        failures += 1
        if code == 0 and expect == "reject" and raw:
            undo(raw, fds)
    print("  %-4s %-60s -> %s %s" % ("ok" if ok else "FAIL", name, code, text[:140].replace("\n", "\\n")))
    sys.stdout.flush()
    return code, text


def undo(raw, fds):
    """Tear down what an accepted setup / ADD attached."""
    try:
        j = json.loads(raw[12:].decode("utf-8", "replace"))
    except ValueError:
        return
    if j.get("command") == "setup":
        j["command"] = "teardown"
        j["argv"][1] = "teardown"
    elif j.get("command") == "ADD":
        j["command"] = "DEL"
        j["env"]["CNI_COMMAND"] = "DEL"
    else:
        return
    exchange(frame(json.dumps(j), flags=1 if fds else 0), fds[:1])


# ------------------------------------------------------------------ builders
def nv_exec(cid="c" * 64, cname="web", net="sec", ifname="eth0", ips=None, mac=None, aliases=None, extra=None):
    opts = {"interface_name": ifname}
    if ips is not None:
        opts["static_ips"] = ips
    if mac is not None:
        opts["static_mac"] = mac
    if aliases is not None:
        opts["aliases"] = aliases
    o = {"container_id": cid, "container_name": cname, "port_mappings": [],
         "network": {"name": net, "id": "f" * 64, "driver": "trestle", "network_interface": "",
                     "subnets": [], "ipv6_enabled": False, "internal": False, "dns_enabled": True,
                     "options": {}, "ipam_options": {"driver": "none"}},
         "network_options": opts}
    if extra:
        o.update(extra)
    return json.dumps(o)


def wire(command="setup", stdin=None, path="/run/user/1000/netns/x", fd=True, mode="netavark",
         argv=None, env=None, rootless=True, version=1, raw_obj=None):
    if raw_obj is not None:
        return json.dumps(raw_obj)
    if stdin is None:
        stdin = nv_exec()
    if argv is None:
        argv = ["/usr/libexec/netavark/trestle", command] + ([path] if command in ("setup", "teardown") else [])
    return json.dumps({"version": version, "mode": mode, "command": command, "argv": argv,
                       "env": env or {}, "netns_path": path if command in ("setup", "teardown", "ADD", "DEL", "CHECK") else "",
                       "netns_fd": fd, "rootless": rootless, "stdin": stdin})


def cni_conf(net="sec", ver="1.0.0", extra=None):
    c = {"cniVersion": ver, "name": net, "type": "trestle"}
    if extra:
        c.update(extra)
    return json.dumps(c)


def cni_env(cmd="ADD", cid="d" * 64, netns="/run/netns/x", ifname="eth0", args="", path="/opt/cni/bin"):
    e = {"CNI_COMMAND": cmd, "CNI_CONTAINERID": cid, "CNI_NETNS": netns, "CNI_IFNAME": ifname, "CNI_PATH": path}
    if args is not None:
        e["CNI_ARGS"] = args
    return e


def cni_wire(env, conf=None, fd=False, path=None):
    return json.dumps({"version": 1, "mode": "cni", "command": env.get("CNI_COMMAND", ""), "argv": ["trestle"],
                       "env": env, "netns_path": path if path is not None else env.get("CNI_NETNS", ""),
                       "netns_fd": fd, "rootless": False, "stdin": conf if conf is not None else cni_conf()})


# ------------------------------------------------------------------ setup
host_ns = os.open("/proc/self/ns/net", os.O_RDONLY)
mnt_ns = os.open("/proc/self/ns/mnt", os.O_RDONLY)
passwd = os.open("/etc/passwd", os.O_RDONLY)
root_ns = os.open(ROOT_NS, os.O_RDONLY) if ROOT_NS else -1
devnull = os.open("/dev/null", os.O_RDONLY)

if MODE == "root":
    os.unshare(os.CLONE_NEWNET)
if MODE == "user":
    uid, gid = os.getuid(), os.getgid()
    os.unshare(os.CLONE_NEWUSER | os.CLONE_NEWNET)
    with open("/proc/self/setgroups", "w") as f:
        f.write("deny")
    with open("/proc/self/uid_map", "w") as f:
        f.write("0 %d 1" % uid)
    with open("/proc/self/gid_map", "w") as f:
        f.write("0 %d 1" % gid)
my_ns = os.open("/proc/self/ns/net", os.O_RDONLY)
my_userns = os.open("/proc/self/ns/user", os.O_RDONLY)

R = "reject"
A = "accept"

print("### framing")
case("bad magic", R, frame(wire(), magic=0x41414141, flags=1), [my_ns])
case("bad version", R, frame(wire(), version=7, flags=1), [my_ns])
case("zero length body", R, frame(b"", flags=1), [my_ns])
case("length 0xffffffff", R, frame(b"{}", length=0xFFFFFFFF))
case("length 1MiB+1", R, frame(b"{}", length=(1 << 20) + 1))
case("length says 4096, 10 bytes then EOF", R, frame(b"0123456789", length=4096))
case("5-byte header then EOF", R, frame(b"")[:5])
case("empty connection", R, b"")
case("fd flag set, no fd attached", R, frame(wire(), flags=1))
case("fd attached, flag clear", R, frame(wire(fd=False), flags=0), [my_ns])
case("two fds attached", R, frame(wire(), flags=1), [my_ns, my_ns])
case("unknown flag bits", R, frame(wire(), flags=0xFFFF), [my_ns])
# bytes after the declared length are never read: harmless, the request is
# handled normally
case("garbage after body (ignored)", A,
     frame(wire(stdin=nv_exec(cid="3" * 64, cname="gb", ifname="gb0")), flags=1) + b"GARBAGE", [my_ns])
case("  (teardown of it)", A, frame(wire("teardown", stdin=nv_exec(cid="3" * 64, cname="gb", ifname="gb0")), flags=1), [my_ns])

print("### file descriptors")
case("fd is /etc/passwd", R, frame(wire(), flags=1), [passwd])
case("fd is /dev/null", R, frame(wire(), flags=1), [devnull])
case("fd is a mount namespace", R, frame(wire(), flags=1), [mnt_ns])
case("fd is a user namespace", R, frame(wire(), flags=1), [my_userns])
case("fd is the host network namespace", R, frame(wire(), flags=1), [host_ns])
if root_ns >= 0:
    case("fd is a netns owned by another user", R if MODE == "user" else A,
         frame(wire(stdin=nv_exec(cid="e" * 64, cname="rootns")), flags=1), [root_ns])
    if MODE == "root":
        case("  (teardown of the above)", A,
             frame(wire("teardown", stdin=nv_exec(cid="e" * 64, cname="rootns")), flags=1), [root_ns])

print("### corrupt wire JSON")
for name, body in [
    ("not JSON", b"\x00\xff\xfe garbage"),
    ("truncated JSON", wire()[:50].encode()),
    ("top-level array", b"[1,2,3]"),
    ("top-level string", b'"hello"'),
    ("JSON null", b"null"),
    ("two objects", (wire() + wire()).encode()),
    ("deep nesting [x100000", b"[" * 100000),
    ("deep nesting object x30000", b'{"a":' * 30000 + b"1" + b"}" * 30000),
    ("invalid UTF-8", wire().replace("web", "\xff\xfe").encode("latin-1")),
    ("NUL byte inside body", wire().encode()[:40] + b"\x00" + wire().encode()[40:]),
    ("version as string", wire(raw_obj={**json.loads(wire()), "version": "1"}).encode()),
    ("version 2", wire(version=2).encode()),
    ("version 1.9", wire(raw_obj={**json.loads(wire()), "version": 1.9}).encode()),
    ("version 4294967297", wire(raw_obj={**json.loads(wire()), "version": 4294967297}).encode()),
    ("mode unknown", wire(mode="docker").encode()),
    ("mode with NUL", wire(mode="netavark\u0000x").encode()),
    ("missing stdin", json.dumps({k: v for k, v in json.loads(wire()).items() if k != "stdin"}).encode()),
    ("stdin is an object", wire(raw_obj={**json.loads(wire()), "stdin": {"a": 1}}).encode()),
    ("argv is a string", wire(raw_obj={**json.loads(wire()), "argv": "setup"}).encode()),
    ("argv empty", wire(argv=[]).encode()),
    ("argv 1000 entries", wire(argv=["x"] * 1000).encode()),
    ("argv non-string entries", wire(argv=["x", 1, None]).encode()),
    ("argv extra args", wire(argv=["x", "setup", "/p", "extra"]).encode()),
    ("env is an array", wire(raw_obj={**json.loads(wire()), "env": []}).encode()),
    ("netns_fd is a string", wire(raw_obj={**json.loads(wire()), "netns_fd": "true"}).encode()),
    ("command mismatch (argv setup, command teardown)", wire(raw_obj={**json.loads(wire()), "command": "teardown"}).encode()),
    ("netns_path mismatch", wire(raw_obj={**json.loads(wire()), "netns_path": "/elsewhere"}).encode()),
    ("info sent to the daemon", wire("info").encode()),
    ("duplicate keys (last wins: mode)", (wire()[:-1] + ', "mode": "bogus"}').encode()),
    ("huge stdin (900 KB)", wire(stdin=nv_exec(extra={"pad": "A" * 900000})).encode()),
]:
    # a big but in-limit request with unknown fields is valid
    case(name, "either" if name.startswith("huge stdin") else R, frame(body, flags=1), [my_ns])

print("### corrupt Netavark stdin")
LENIENT = {"static ip ipv6": "IPv6 addresses are ignored (not supported yet)",
           "two static ips": "the first usable address is taken"}
for name, stdin in [
    ("stdin empty", ""),
    ("stdin not JSON", "garbage"),
    ("stdin array", "[]"),
    ("stdin trailing data", nv_exec() + "}"),
    ("stdin two objects", nv_exec() + nv_exec()),
    ("stdin deep nesting", '{"a":' * 50000 + "1" + "}" * 50000),
    ("container_id missing", json.dumps({k: v for k, v in json.loads(nv_exec()).items() if k != "container_id"})),
    ("container_id number", nv_exec(cid=12345)),
    ("container_id ..", nv_exec(cid="..")),
    ("container_id .", nv_exec(cid=".")),
    ("container_id ../../etc", nv_exec(cid="../../etc")),
    ("container_id .hidden", nv_exec(cid=".hidden")),
    ("container_id -rf", nv_exec(cid="-rf")),
    ("container_id with NUL", nv_exec(cid="abc\u0000/../../x")),
    ("container_id 129 chars", nv_exec(cid="a" * 129)),
    ("container_id newline", nv_exec(cid="abc\ndef")),
    ("container_name $(id)", nv_exec(cname="$(touch /tmp/trestle-pwned)")),
    ("container_name backticks", nv_exec(cname="`touch /tmp/trestle-pwned`")),
    ("container_name ;rm", nv_exec(cname="a;rm -rf /")),
    ("container_name newline+hosts line", nv_exec(cname="x\n6.6.6.6 evil")),
    ("container_name NUL", nv_exec(cname="web\u0000evil")),
    ("container_name 65 chars", nv_exec(cname="a" * 65)),
    ("container_name 10000 chars", nv_exec(cname="a" * 10000)),
    ("container_name unicode", nv_exec(cname="wéb")),
    ("container_name leading dash", nv_exec(cname="-web")),
    ("network name ../../etc", nv_exec(net="../../etc")),
    ("network name with /", nv_exec(net="a/b")),
    ("network name $(id)", nv_exec(net="$(id)")),
    ("network name NUL", nv_exec(net="sec\u0000x")),
    ("network name newline", nv_exec(net="sec\n[global]")),
    ("network name 65 chars", nv_exec(net="s" * 65)),
    ("network name not permitted", nv_exec(net="nosuchnet")),
    ("network not an object", nv_exec(extra={"network": "sec"})),
    ("network.name number", nv_exec(extra={"network": {"name": 7}})),
    ("ifname ../x", nv_exec(ifname="../x")),
    ("ifname with /", nv_exec(ifname="eth/0")),
    ("ifname 16 chars", nv_exec(ifname="a" * 16)),
    ("ifname with space", nv_exec(ifname="eth 0")),
    ("ifname ..", nv_exec(ifname="..")),
    ("ifname with quote", nv_exec(ifname='e"th')),
    ("ifname NUL", nv_exec(ifname="eth\u00000")),
    ("ifname empty", nv_exec(ifname="")),
    ("static ip gateway", nv_exec(ips=["10.77.0.1"])),
    ("static ip network address", nv_exec(ips=["10.77.0.0"])),
    ("static ip broadcast", nv_exec(ips=["10.77.0.255"])),
    ("static ip outside subnet", nv_exec(ips=["10.78.0.5"])),
    ("static ip garbage", nv_exec(ips=["10.77.0.5; id"])),
    ("static ip 999.1.1.1", nv_exec(ips=["999.1.1.1"])),
    ("static ip with newline", nv_exec(ips=["10.77.0.5\n"])),
    ("static ip with NUL", nv_exec(ips=["10.77.0.5\u0000junk"])),
    ("static ip number", nv_exec(ips=[167772165])),
    ("static ip ipv6", nv_exec(ips=["::1"])),
    ("static ips not an array", nv_exec(ips="10.77.0.5")),
    ("two static ips", nv_exec(ips=["10.77.0.5", "10.77.0.6"])),
    ("static mac multicast", nv_exec(mac="ff:ff:ff:ff:ff:ff")),
    ("static mac garbage", nv_exec(mac="zz:zz:zz:zz:zz:zz")),
    ("static mac signed/space hex", nv_exec(mac="+2:+0:+0:+0:+0:+1")),
    ("static mac space-padded", nv_exec(mac=" 2: 0: 0: 0: 0: 1")),
    ("static mac long", nv_exec(mac="02:00:00:00:00:01:02")),
    ("static mac NUL", nv_exec(mac="02:00:00:00:00:01\u0000x")),
    ("interface_name missing", json.dumps({**json.loads(nv_exec()), "network_options": {}})),
    ("network_options array", json.dumps({**json.loads(nv_exec()), "network_options": []})),
]:
    case(name + (" [%s]" % LENIENT[name] if name in LENIENT else ""), "either" if name in LENIENT else R,
         frame(wire(stdin=stdin), flags=1), [my_ns])

print("### injection through accepted fields (must succeed, but sanitized)")
inj_aliases = ["ok1", "x\n6.6.6.6 evil.inject", "a b", "$(id)", "../x", "a" * 70, 5, None, {"a": 1}, "ok2"]
case("setup with hostile aliases (invalid ones dropped)", A,
     frame(wire(stdin=nv_exec(cid="1" * 64, cname="inj", ifname="inj0", aliases=inj_aliases)), flags=1), [my_ns])
case("teardown of it", A,
     frame(wire("teardown", stdin=nv_exec(cid="1" * 64, cname="inj")), flags=1), [my_ns])
case("netns_path with newline and shell", R,
     frame(wire(path="/x\n$(touch /tmp/trestle-pwned)\n", stdin=nv_exec(cid="2" * 64, cname="p", ifname="pth0")), flags=1),
     [my_ns])
case("  (teardown with that path)", R,
     frame(wire("teardown", path="/x\n$(touch /tmp/trestle-pwned)\n", stdin=nv_exec(cid="2" * 64, cname="p")),
           flags=1), [my_ns])

print("### authorization")
case("rootless=false with the host netns path", R,
     frame(wire(fd=False, rootless=False, path="/proc/1/ns/net"), flags=0))
case("teardown of a container never attached (idempotent)", A,
     frame(wire("teardown", stdin=nv_exec(cid="9" * 64, cname="ghost")), flags=1), [my_ns])

print("### CNI")
cfd = [my_ns]
for name, env, conf in [
    ("CNI_COMMAND unknown", cni_env(cmd="RM"), None),
    ("CNI_COMMAND with NUL", cni_env(cmd="ADD\u0000x"), None),
    ("CNI_CONTAINERID ..", cni_env(cid=".."), None),
    ("CNI_CONTAINERID ../../../etc/x", cni_env(cid="../../../etc/x"), None),
    ("CNI_CONTAINERID empty", cni_env(cid=""), None),
    ("CNI_IFNAME ../x", cni_env(ifname="../x"), None),
    ("CNI_IFNAME 40 chars", cni_env(ifname="e" * 40), None),
    ("CNI_NETNS relative", cni_env(netns="netns/x"), None),
    ("CNI_NETNS with newline", cni_env(netns="/run/netns/x\n"), None),
    ("CNI_ARGS IP outside subnet", cni_env(args="IP=1.2.3.4"), None),
    ("CNI_ARGS IP injection", cni_env(args="IP=10.77.0.9;$(id)"), None),
    ("CNI_ARGS MAC bad", cni_env(args="MAC=zz"), None),
    ("CNI_ARGS 100 KB", cni_env(args="K8S_POD_NAME=" + "a" * 100000), None),
    ("cniVersion 9.9.9", cni_env(), cni_conf(ver="9.9.9")),
    ("cniVersion number", cni_env(), json.dumps({"cniVersion": 1, "name": "sec", "type": "trestle"})),
    ("conf name ../etc", cni_env(), cni_conf(net="../etc")),
    ("conf name NUL", cni_env(), cni_conf(net="sec\u0000x")),
    ("conf not JSON", cni_env(), "{{{{"),
    ("conf trailing data", cni_env(), cni_conf() + "x"),
    ("runtimeConfig.ips bad", cni_env(), cni_conf(extra={"runtimeConfig": {"ips": ["10.77.0.9/33"]}})),
    ("runtimeConfig.ips not array", cni_env(), cni_conf(extra={"runtimeConfig": {"ips": "10.77.0.9/24"}})),
    ("runtimeConfig.mac multicast", cni_env(), cni_conf(extra={"runtimeConfig": {"mac": "01:00:5e:00:00:01"}})),
    ("CNI env missing CNI_IFNAME", {k: v for k, v in cni_env().items() if k != "CNI_IFNAME"}, None),
]:
    case(name, R, frame(cni_wire(env, conf, fd=True), flags=1), cfd)
if MODE == "user":
    case("CNI by a user with only a path (no fd)", R, frame(cni_wire(cni_env(netns="/proc/1/ns/net"))))
else:
    case("CNI root: path is the host netns", R, frame(cni_wire(cni_env(netns="/proc/1/ns/net"))))
    case("CNI root: path is /etc/passwd", R, frame(cni_wire(cni_env(netns="/etc/passwd"))))
    case("CNI root: path does not exist", R, frame(cni_wire(cni_env(netns="/nonexistent/ns"))))
    case("CNI root: path traversal to /proc/self/ns/net", R,
         frame(cni_wire(cni_env(netns="/run/netns/../../proc/self/ns/net"))))

print("### baseline (valid requests still work)")
case("valid setup", A, frame(wire(stdin=nv_exec(cid="b" * 64, cname="base", ifname="base0")), flags=1), [my_ns])
case("valid teardown", A, frame(wire("teardown", stdin=nv_exec(cid="b" * 64, cname="base")), flags=1), [my_ns])

print("### stalls")
t0 = time.time()
code, _ = exchange(frame(wire(), flags=1)[:20], [my_ns], timeout=40, shut=False)
dt = time.time() - t0
print("  %-4s %-60s -> %s after %.1fs" % ("ok" if code in ("closed",) or isinstance(code, int) else "FAIL",
                                          "partial request then silence is dropped", code, dt))
if not (code == "closed" or isinstance(code, int)):
    failures += 1

print("\n%d failures" % failures)
sys.exit(1 if failures else 0)
