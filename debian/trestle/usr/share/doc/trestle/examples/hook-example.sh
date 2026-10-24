#!/bin/sh
# Example trestle hook script.
#
# Install it root-owned and not writable by group/others, e.g.
#   install -o root -g root -m 0755 hook-example.sh /etc/trestle/hooks/lab.sh
# and reference it from the network section:
#   [network:lab]
#   create_script   = /etc/trestle/hooks/lab.sh
#   setup_script    = /etc/trestle/hooks/lab.sh
#   teardown_script = /etc/trestle/hooks/lab.sh
#
# The event is the first argument and $TRESTLE_EVENT. Everything printed is
# written to the trestled journal. A non-zero exit status aborts a create or
# setup only when script_on_error = fail; teardown failures are only logged.

set -eu

case "$1" in
create)
	# a podman network was created, or trestle (re)created the bridge
	logger -t trestle-hook "network $TRESTLE_NETWORK on bridge $TRESTLE_BRIDGE" \
		"(created now: $TRESTLE_BRIDGE_CREATED) by ${TRESTLE_USER:-?}"
	;;
setup)
	echo "$TRESTLE_USER attached $TRESTLE_CONTAINER_NAME ($TRESTLE_CONTAINER_ID)" \
	     "to $TRESTLE_NETWORK: $TRESTLE_HOST_IFNAME <-> $TRESTLE_CONTAINER_IFNAME" \
	     "ip ${TRESTLE_IP_CIDR:-none}"

	# Example: limit the container to 100 Mbit/s towards the host bridge.
	# tc qdisc replace dev "$TRESTLE_HOST_IFNAME" root tbf rate 100mbit burst 32kbit latency 400ms

	# Example: run a command inside the container network namespace. The
	# namespace is passed as file descriptor $TRESTLE_NETNS_FD, which also
	# works for rootless containers whose netns path is not visible here.
	if [ -n "${TRESTLE_NETNS_FD:-}" ]; then
		nsenter --net="/proc/self/fd/$TRESTLE_NETNS_FD" \
			sysctl -q -w net.ipv4.conf."$TRESTLE_CONTAINER_IFNAME".rp_filter=1 || true
	fi
	;;
teardown)
	echo "$TRESTLE_CONTAINER_NAME left $TRESTLE_NETWORK (${TRESTLE_IP:-no ip})"
	;;
esac
