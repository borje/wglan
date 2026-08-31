# Implementing wglan

Read [SPEC.md](SPEC.md) first — this file is the build order, not the design. Both are at draft 2;
the ten things draft 1 got wrong are indexed in [SPEC §17](SPEC.md).

## Layout

Small enough that packages are a liability, not an asset. Six files, one `main` package, plus one
package for the thing worth isolating.

```
go.mod                  module github.com/atvirokodosprendimai/wglan — no requires
main.go                 flag parsing, subcommand dispatch, bring-up, serve
join.go                 JOIN/LEAVE/PROBE client + handlers, fan-out, rate limiter
state.go                peers.json load/save (atomic), peer lookups
system.go               wg/ip/hosts side effects — every exec.Command lives here
status.go               wg show parsing, stale determination
main_test.go            hosts block, argv, merge rules, three-node convergence, hardening
envelope/envelope.go    seal/open, HKDF, freshness, seen-set, field validation
envelope/envelope_test.go
firewall_test.go        guards the embedded ruleset; `nft -c -f` it when run as root
nftables/wglan.conf     the firewall skeleton, embedded and printed by `wglan firewall`
systemd_test.go         guards the shipped unit; `systemd-analyze verify` when installed
systemd/wglan.service   the shipped unit; operator copies it to /etc/systemd/system/
testdata/mesh.sh        three netns end-to-end; needs root and wireguard-tools
```

The mutex lives on the `Node` struct in `join.go` rather than on the state file loader: it has to
cover validate → apply → persist → reply as one sequence (SPEC §14), which spans `state.go` and
`system.go` both.

`envelope` is a separate package for one reason: **nothing outside it may construct a payload
struct.** `Open` is the only exported way to get one, so "validation is welded to the open"
(SPEC §4.5) is enforced by the compiler rather than by discipline.

`system.go` is separate for the same kind of reason: one file to grep to answer "what does this
binary do to my host", and one seam to fake in tests. A `CommandRunner func(name string, args
...string) ([]byte, error)` field on the daemon struct is enough — no interface with one
implementation.

## Build order

Each milestone ends in something runnable, and the acceptance check is the thing you actually run.

### 1 · Envelope

`wglan secret`, HKDF derivation, `Seal`, `Open`, field validation, both frame caps, the ±600s
window, the nonce seen-set. No networking.

*Accept:* `go test ./envelope -race` covering — round-trip; wrong key fails; flipped ciphertext
byte fails; flipped nonce byte fails; timestamp −601s fails; timestamp +601s fails (both
directions, this is the one people skip); `protocol` mismatch fails; oversized frame rejected
without allocating the body; a replayed nonce fails and the set evicts; a full 256-peer
`JOIN_REPLY` fits the reply cap and does *not* fit the inbound one; every field-validation rule
from SPEC §4.3, each with one valid and one hostile input (`hostname` containing a newline,
`mesh_ip` of `10.90.0.1 10.90.0.2`, `pubkey` of 43 chars, `endpoint` without a port,
`control_port` of 0 and 65536, and each of those inside a `peers[]` entry).

### 2 · Interface + state

`ip`/`wg` bring-up, keygen, `peers.json` atomic write, reload-on-restart. Still no protocol. The
firewall is not part of bring-up: `wglan firewall` prints a ruleset and the operator installs it
(SPEC §12.5).

*Accept:* on one host, `wglan join --mesh-ip 10.90.0.1/24 --secret ...` with no `--bootstrap`
brings up `wglan0` holding the address **and returns**; `wg show wglan0` lists it with no peers;
`wglan run` then serves and can be killed and restarted — it comes back from `peers.json` without
touching the network. Second run must be silent about
everything already correct. Separately, on that default-interface node: `wglan firewall | diff -
nftables/wglan.conf` is empty, and `sudo nft -c -f <(wglan firewall)` passes. Before the join
`wglan firewall` must error, not print (SPEC §12.5).

### 3 · Two-node join

TCP listener, `JOIN` handler, `JOIN_REPLY`, the peer-add `wg set`, the hosts block.

*Accept:* two VMs. Node2 joins node1; `ping 10.90.0.1` from node2 and `ping 10.90.0.2` from node1
**both** work — one direction passing and the other hanging is the signature of a missing conntrack
rule, which is why the shipped ruleset leads with one; `curl
http://node1.mesh` resolves, once config management has allowed 80 in the `mesh` chain. Then reboot
node2 — the tunnel returns with no join and no network round trip.

### 4 · Fan-out

Union the received list, `JOIN` every learned peer, unify the duplicate/subnet rejections and
their log lines.

*Accept:* three nodes, all joined via node1. Every node's `wg show` lists **both** others — this
is the milestone that either works or silently half-works, so check all three, not just the
joiner. Then: a fourth node with a colliding `--mesh-ip` is rejected on every peer with a log line
naming both pubkeys, and the mesh is unchanged. And the case draft 1 allowed: an
**already-known** pubkey sending a `JOIN` that claims an existing peer's address is rejected too
(SPEC §3.4). `TestMergeRules` and `TestCollidingJoinRejectedByPeer` cover both; `testdata/mesh.sh`
covers the happy path against a real kernel.

### 5 · Hardening + status

Rate limiter, connection semaphore, deadlines, uniform rejection, `status` with the stale marker
(SPEC §8: handshake age past 180s, transfer counters printed beside it).

*Accept:* `go test -race` on the handler with 100 concurrent connections, half of them garbage;
`peers.json` is valid afterwards, no two pubkeys hold one address, and no goroutine leaks.
Hand-check: `nc` the control port with 5KB of `/dev/urandom` — connection closes, one log line, no
reply body. Stop a peer's WireGuard and confirm `status` marks it stale within ~3 minutes.

### 6 · leave / forget / sync

*Accept:* `wglan leave` on node3 removes it from node1 and node2 — `peers.json`, `wg show`, and
`/etc/hosts` on both. A `LEAVE` injected from a **different** mesh address naming node3's pubkey
is dropped, and so is one that arrives on the LAN address rather than `wglan0` (SPEC §6.1 — this is
the test that matters; write it before the feature: `TestLeaveBinding`,
`TestLeaveOffTunnelRejected`). `sync` after deliberately racing two joins repairs the missing edge.

### 7 · probe

`PROBE` / `PROBE_REPLY`, in-tunnel and source-bound like `LEAVE`. Not a repurposed `sync`: a
`JOIN_REPLY` carries no liveness data (SPEC §7).

*Accept:* `wglan probe node7` prints `reachable from 0/N peers` when every peer agrees, and a
partial count when only the caller's link is broken. A `PROBE` arriving off-tunnel is dropped.

## Test strategy

- **Table-driven, `t.Parallel()`, `-race` always.** The daemon accepts concurrent connections by
  construction.
- **Fake the command runner, not the network.** Real loopback TCP in tests is cheap and finds real
  framing bugs; real `ip link add` needs root and finds nothing. So: exercise the protocol over
  `net.Pipe`/loopback, assert on the *recorded argv* of every `wg`/`ip`/`nft` call.
- **Assert on argv, not on a rendered string.** `[]string{"wg","set","wglan0","peer",...}` — if a
  test compares a joined string, the injection guarantee in SPEC §12.3 is untested.
- **The hosts-block writer gets its own test with a hostile `/etc/hosts`**: no markers, markers
  present with content, markers with unrelated entries above and below, a duplicated END marker.
  Everything outside the markers must survive byte-for-byte.
- **`testdata/mesh.sh`** runs the three-node sequence plus a `leave` in network namespaces. It
  needs root and `wireguard-tools`, and it is the only test that exercises the real `ip`/`wg`/`nft`
  calls — faking the runner finds argument bugs, not kernel ones. Two VMs by hand remains an
  acceptable substitute at this scale.
- The tunnel-binding tests use `127.0.0.<n>` for both the mesh and the "LAN" address, so SPEC §6.1
  is exercised over real loopback TCP without root: a node listening on its own mesh address sees
  in-tunnel connections, and one listening elsewhere does not.

## Deliberately not in v1

Listed so they are not re-litigated mid-build, with the trigger that would justify each:

| Deferred | Add when |
|---|---|
| Structured logging / metrics | A human reading log lines stops being enough. Not at tens of nodes. |
| Persisted transfer-counter snapshot for staleness | A peer is ever seen reading stale while healthy (SPEC §8). |
| Per-node signatures over `peers[]` entries | Second-hand endpoint poisoning by a member matters. That is the certificate architecture of SPEC §12.4, not a field. |
| Challenge–response instead of the timestamp | Clock skew proves to be a real field problem, **or** revocation is added (SPEC §16 — they arrive together). |
| IPv6, ACLs, subnet routing, DNS | A requirement appears. None exists. |
| Automatic eviction | Only as soft state plus quorum. Read SPEC §8 in full first; it is a reversal of the design, not an addition to it. |
