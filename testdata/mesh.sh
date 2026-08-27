#!/bin/sh
# Three-node end-to-end check in network namespaces.
#
# Needs root and wireguard-tools (`wg`). This is the only test that exercises the
# real `ip`/`wg`/`nft` calls — the Go tests fake the command runner and assert on
# argv, which finds argument bugs but not kernel ones.
#
#   sudo sh testdata/mesh.sh
set -e

BIN=${BIN:-./wglan}
NODES="1 2 3"
LAN=192.168.99
MESH=10.90.0

[ -x "$BIN" ] || { echo "build first: go build -o wglan ."; exit 1; }
command -v wg >/dev/null || { echo "wireguard-tools not installed"; exit 1; }

cleanup() {
	for i in $NODES; do
		ip netns pids "wgl$i" 2>/dev/null | xargs -r kill 2>/dev/null || true
		ip netns del "wgl$i" 2>/dev/null || true
	done
	ip link del br-wgl 2>/dev/null || true
	rm -rf "$TMP"
}
trap cleanup EXIT
TMP=$(mktemp -d)

ip link add br-wgl type bridge
ip link set br-wgl up
for i in $NODES; do
	ip netns add "wgl$i"
	ip link add "v$i" type veth peer name "p$i"
	ip link set "v$i" master br-wgl up
	ip link set "p$i" netns "wgl$i"
	ip -n "wgl$i" link set lo up
	ip -n "wgl$i" link set "p$i" up
	ip -n "wgl$i" addr add "$LAN.$i/24" dev "p$i"
	mkdir -p "$TMP/$i"
	: > "$TMP/$i/hosts"
done

SECRET=$($BIN secret)
start() { # start <node> [bootstrap]
	i=$1
	boot=$2
	set -- --state-dir "$TMP/$i" --hosts-file "$TMP/$i/hosts" --secret "$SECRET" \
		--mesh-ip "$MESH.$i/24" --hostname "node$i" --lan-ip "$LAN.$i"
	if [ -n "$boot" ]; then
		set -- "$@" --bootstrap "$boot"
	fi
	# The two steps a systemd unit takes: `join` sets the node up, announces it
	# and returns; `run` is the long-lived control listener.
	ip netns exec "wgl$i" "$BIN" join "$@" >"$TMP/$i/log" 2>&1
	# No --lan-ip or --interface here: join persisted both, and `run` reading
	# them back is exactly what this exercises.
	ip netns exec "wgl$i" "$BIN" run --state-dir "$TMP/$i" \
		--hosts-file "$TMP/$i/hosts" >>"$TMP/$i/log" 2>&1 &
	sleep 1
}

start 1
start 2 "$LAN.1:51821"
start 3 "$LAN.1:51821"
sleep 2

fail=0
for i in $NODES; do
	peers=$(ip netns exec "wgl$i" wg show wglan0 peers | grep -c . || true)
	if [ "$peers" -ne 2 ]; then
		echo "FAIL node$i: wg show lists $peers peers, want 2"
		fail=1
	fi
	for j in $NODES; do
		[ "$i" = "$j" ] && continue
		if ! ip netns exec "wgl$i" ping -c1 -W2 "$MESH.$j" >/dev/null 2>&1; then
			echo "FAIL node$i cannot reach $MESH.$j"
			fail=1
		fi
	done
	for j in $NODES; do
		if ! grep -q "node$j.mesh" "$TMP/$i/hosts"; then
			echo "FAIL node$i hosts block missing node$j.mesh"
			fail=1
		fi
	done
done

# A LEAVE from node3 must remove it everywhere.
ip netns exec wgl3 "$BIN" leave --state-dir "$TMP/3" --hosts-file "$TMP/3/hosts" \
	--secret "$SECRET" --lan-ip "$LAN.3" >>"$TMP/3/log" 2>&1
sleep 1
for i in 1 2; do
	peers=$(ip netns exec "wgl$i" wg show wglan0 peers | grep -c . || true)
	if [ "$peers" -ne 1 ]; then
		echo "FAIL node$i still has $peers peers after node3 left"
		fail=1
	fi
	if grep -q "node3.mesh" "$TMP/$i/hosts"; then
		echo "FAIL node$i hosts block still names node3"
		fail=1
	fi
done

for i in $NODES; do sed "s/^/node$i: /" "$TMP/$i/log"; done
if [ "$fail" -eq 0 ]; then
	echo "PASS: three-node mesh converged, leave propagated"
fi
exit "$fail"
