# wglan — specification

**Version:** protocol `wglan-v1` · spec draft 2 · status: implemented
**Changes from draft 1:** §17.
**Scope:** a single Go binary that builds a full-mesh WireGuard network across a LAN with no
internet access, no discovery service, and no background reconciliation.

---

## 1. What it is

One shared secret plus one bootstrap address gets a node into a full mesh. Every node's mesh
address is assigned by the operator. Control messages are AES-256-GCM sealed; opening one *is*
the proof of membership. After a join completes, nothing runs on a timer.

Target scale: tens of nodes, ~1 join/day churn, Linux only, IPv4 only.

**Dependencies: none.** `crypto/hkdf`, `crypto/aes`, `crypto/cipher`, `net`, `os/exec` are all
stdlib as of Go 1.24. The binary shells out to `wg`, `ip`, and `nft`, exactly as `wg-quick` does.

## 2. Non-goals

Each of these is cut for a reason, and the reason is what stops it being re-added by accident.

| Cut | Why |
|---|---|
| DHT / rendezvous / any internet-facing discovery | The requirement is LAN-only. This deletes the entire class of "offline mode is broken because bootstrap failed". |
| LAN multicast / broadcast discovery | At ~1 join/day, a hand-supplied bootstrap IP is less machinery than a multicast group plus beacon loop, and it works across VLANs and routed subnets where multicast does not. |
| Derived or negotiated addressing | See §3. Addresses are operator-assigned; there is nothing to agree on. |
| Reconcile loop, peer expiry, automatic eviction | WireGuard's own endpoint roaming plus `PersistentKeepalive` handles drift. Liveness is *detected* but never acted on automatically and never propagated (§8). |
| Revocation | Membership is "knows the secret", permanently. Removing a node is a secret rotation, which is a flag day, not a command (§12.4). |
| Embedded DNS | `/etc/hosts` block management. No resolver integration to get wrong across systemd-resolved / NetworkManager / plain resolv.conf. |
| netlink library | Shell out to `wg`/`ip`. Every side effect is a command an operator can re-run by hand. |
| ACLs, IPv6, macOS/Windows, mobile, GUI | Not requirements. |

## 3. Identity, addressing, naming

### 3.1 Addressing is static and complete

The mesh subnet is **operator-chosen** (`10.90.0.0/24` in all examples here) and recorded wherever
the host inventory already lives. Each node is configured with its full address and mask:

```
wglan join --secret wglan://v1/... --mesh-ip 10.90.0.3/24 --bootstrap 192.168.1.21:51821
```

`--mesh-ip` is mandatory. There is no assignment protocol, no next-free-slot search, no
negotiation, and no tie-break rule.

The rationale, because it is load-bearing: an assigned-at-join address is a value independent
nodes must *agree* on, which is a consensus problem. Two nodes bootstrapping concurrently through
different members both see the same slot free, both commit, and with no reconcile loop and
`peers.json` authoritative on restart, the duplicate is permanent. A pre-commit re-check does not
fix it — no lock is held across the round trip, so it is TOCTOU. A statically assigned address is
a value each node is *told*. The class of bug disappears.

A secret-derived subnet is separately unnecessary: `JOIN` carries the sender's address, and
per-peer `AllowedIPs` is always a `/32`. WireGuard has no concept of a mesh subnet. Deriving one
only lets nodes compute addresses they were not told — and an HKDF-picked `10.x.y.0/24` lands
inside space that is heavily occupied on any real corporate or cloud network, where a human
picking a subnet would have checked.

### 3.2 The mask must cover every peer

The mask creates the connected route onto `wglan0` via `ip addr add`. A `JOIN` advertising an
address outside the receiving node's own configured subnet is **rejected with an error naming
both**, so an inventory typo fails loudly at join time instead of surfacing later as unexplained
unreachability.

### 3.3 Duplicates are detected, never resolved

A `JOIN` claiming an address, or a hostname, already held by a **different** pubkey is rejected
and logged, naming both pubkeys and the value. A duplicate static address is an inventory bug;
the response to a config bug is a loud failure, not silent renumbering. One map lookup, no round
trips, no tie-break rule that every node must implement identically.

**This check has no exceptions**, including for a pubkey the receiver already knows. See §3.4 for
why that sentence has to be written down.

This is the accepted cost of static addressing: derivation makes duplicates impossible, static
assignment makes them a human error that this check has to catch.

### 3.4 The peer map is keyed on pubkey

A `JOIN` from an already-known pubkey **updates** that peer's address and hostname in place
rather than tripping the duplicate check *against its own current values*. The check against every
**other** pubkey still runs (§3.3).

That distinction is load-bearing and draft 1 got it wrong. If a known pubkey were exempt from the
duplicate check outright, any member could seal a `JOIN` carrying its own pubkey and another peer's
`mesh_ip`; every receiver would move `AllowedIPs 10.90.0.7/32` onto the attacker's key, and node7's
traffic would arrive at the attacker decryptable. That is not address squatting, it is
interception, and with no reconcile loop it is permanent. The narrow exemption keeps both
properties below while leaving the theft rejected and logged.

Two things depend on the exemption:

- **Renumbering is one variable change plus a restart.** The node re-`JOIN`s every peer with its
  new address and every peer updates in place. No scheme deriving the address from the node's key
  can do this without regenerating the keypair.
- **A reinstalled node** (new keypair, same hostname) is `forget` on the old pubkey plus a normal
  join — not hand-edited JSON on every host.

The accepted cost: renumbering *into* an address still held by a lingering dead peer needs a
`forget` first. §8 already lists that as a reason a dead peer wants a human decision.

### 3.5 Naming

Hostname defaults to the OS hostname, overridable with `--hostname`, validated against
`^[a-z0-9-]{1,63}$`. Written into a marked block in `/etc/hosts`, rewritten whenever the peer
list changes:

```
# BEGIN wglan
10.90.0.1 node1.mesh
10.90.0.2 node2.mesh
# END wglan
```

Gives working FQDNs (`curl https://node2.mesh`) with no new listening service. Only the region
between the markers is ever touched; the rest of the file is preserved byte-for-byte.

## 4. Control protocol

Control plane: **TCP**, default port **51821**, one framed message per connection.
Data plane: WireGuard UDP, default port **51820**. Separate ports, separate concerns.

### 4.1 Key derivation

```
envelope_key = HKDF-SHA256(secret, info="wglan-envelope-v1", salt=nil) → 32 bytes
```

Derived once at startup. The info string is domain-separated from any other tool's, so a secret
reused across tools never produces cross-openable messages.

Secret format: `wglan://v1/<base64url of 32 random bytes>`, generated by `wglan secret`.

### 4.2 Outer frame

The only bytes an unauthenticated party can influence:

```
[uint32 big-endian length]     cap 4096 inbound, 262144 on a reply we asked for (see below)
{
  "nonce":      base64,        // 12 random bytes, fresh per message
  "ciphertext": base64         // AES-256-GCM; the tag covers the entire payload
}
```

**Two caps, not one.** A single 4096-byte cap cannot hold the peer list it is supposed to carry: a
`peers[]` entry is 130–190 bytes of JSON and the ciphertext is base64'd on the way out, so the
frame fills at roughly **20 peers** — well under the "tens of nodes" this targets, and the failure
lands exactly in the fan-out path. So:

- **Inbound, 4096 bytes.** The listener never reads more. A `JOIN`, `LEAVE`, `PROBE` or
  `PROBE_REPLY` is nowhere near it, and this is the only number an unauthenticated party can spend.
- **On a reply, 262144 bytes.** Read only on a connection this node dialled itself, so a stranger
  can never make a node buffer it. 256 peers is ~50KB of payload, ~66KB base64; the rest is
  headroom.

Larger than the applicable cap is dropped on the length prefix, without reading or allocating the
body.

### 4.3 Sealed payload

Every field is inside the ciphertext, so all of it is confidential *and* tamper-evident.

| Field | Type | Rule |
|---|---|---|
| `protocol` | string | `"wglan-v1"`. Checked first; fails closed on version skew before any other field is read. |
| `type` | string | `JOIN`, `JOIN_REPLY`, or `LEAVE`. |
| `timestamp` | int64 | Unix seconds. Freshness bound, §4.4. Inside the seal, so unforgeable. |
| `pubkey` | string | Sender's WireGuard public key: exactly 44 base64 chars decoding to 32 bytes. |
| `hostname` | string | `^[a-z0-9-]{1,63}$`. |
| `mesh_ip` | string | Sender's mesh address, no mask (the mask is local-only state). Must parse via `netip.ParseAddr`, be IPv4 unicast, and fall inside the receiver's configured subnet. |
| `lan_endpoint` | string | Sender's `ip:port` for the WireGuard data plane. Must parse via `net.SplitHostPort` + address parse — not a regex. |
| `control_port` | int | 1–65535. Sender's TCP control port. |
| `peers` | array | `JOIN_REPLY` only. `{pubkey, hostname, mesh_ip, lan_endpoint, control_port}` per known member. **Capped at 256 entries, each validated by the identical rules above.** |
| `target` | string | `PROBE` only. Pubkey of the peer being asked about. |
| `known`, `handshake_age` | bool, int64 | `PROBE_REPLY` only. Whether the responder knows the target, and seconds since its last handshake (`-1` = never). |

`control_port` is on the wire because without it fan-out, `sync`, `leave` and `probe` can only
guess 51821 — `--control-port` (§9) would be a flag that silently does not work.

`peers[]` entries get the same per-field validation as the sender's own fields, and one bad entry
rejects the whole message. They are what reaches `wg set` and `/etc/hosts`; a rule that applies only
to the top level is a rule with a hole in it.

A `LEAVE` carries `protocol`, `type`, `timestamp`, `pubkey` only. Any other field present is a
rejection rather than something carried around unread.

`peers` is why confidentiality is required rather than nice-to-have: one captured reply is the
complete network map, not one node's details.

### 4.4 Freshness

A payload whose `timestamp` is more than **600 seconds** old, **or more than 600 seconds in the
future**, is rejected. Both directions deliberately — rejecting only "too old" leaves a
future-dated capture replayable indefinitely once its time arrives.

**A nonce seen-set, after all.** Draft 1 deferred it: a `JOIN` asserts "peer X is at address Y",
so applying it twice equals applying it once — with the stated trigger "add a seen-set only if
`JOIN` ever gains a non-idempotent side effect".

That trigger has already fired, in §3.4. Update-in-place makes `JOIN` a last-writer-wins mutation,
not an insert: replay a capture from just before a node renumbered and every receiver reverts it;
replay one from just before a `forget` and the peer comes back. Both need a capture from inside the
same 600-second window as an operator action, which is narrow — and cheaper to close than to
document. The set is keyed on the nonce and evicted lazily on insert, bounded by the freshness
window above, so it introduces no timer.

### 4.5 Validation is welded to the open

One function opens the envelope, checks `protocol`, checks freshness, unmarshals, and validates
every field. **There is no code path that returns an unvalidated struct.** A rule that callers
must remember is a rule that gets forgotten.

## 5. Join

`JOIN` is one message shape and it covers first join, fan-out greeting, `sync`, and `probe`.

1. **First node.** No `--bootstrap`. Empty peer list, takes its configured address, starts
   listening.
2. **Every subsequent node** connects to the bootstrap target over TCP and sends a sealed `JOIN`.
   The recipient:
   - opens the envelope — failure is the single uniform rejection (§12.2);
   - validates every field (§4.3), checks address and hostname against what it knows (§3.3);
   - **adds the sender as a WireGuard peer immediately** — no separate hello step, the `JOIN`
     already carries the address;
   - replies with `JOIN_REPLY` = its own info plus its full known peer list.
3. **The joiner unions every peer list it receives** into its own state, then sends the same
   `JOIN` directly to **every peer it has learned about** — not just the bootstrap target — so
   every existing member independently adds it. Fan-out replies are unioned too; it costs nothing
   and picks up members the bootstrap target had not yet heard about.
4. **Any existing node can serve as a bootstrap target.** No single point of failure for joining,
   with no redundancy logic.

### 5.1 Convergence, and where it does not hold

For joins that do not overlap in time, convergence is exact by induction: every prior joiner
contacted every member that existed at its own join, so any node's list is complete for the mesh
as of that node's join. A new joiner therefore receives a complete list and, after greeting
everyone on it, every member is complete again. No gossip round, no eventual consistency — fully
resolved by the time the last reply comes back.

**Two nodes joining concurrently through *different* bootstrap targets can each finish without
learning about the other.** Neither appears in any list the other receives, the edge between them
is simply missing, and with no reconcile loop nothing notices. Unioning all fan-out replies
narrows the window but cannot close it.

This is a property of a purely reactive runtime, not a bug to fix with more protocol. The answer
is `sync` (§7), run once after a batch of joins. Operational rule: **add nodes one at a time, or
run `sync` afterwards.**

## 6. Leave

Three things get confused as one feature. They carry different amounts of certainty, so they get
different answers:

| Situation | Who knows | Mechanism |
|---|---|---|
| A node is being decommissioned on purpose | The departing node, with certainty | `LEAVE` — one message, fans out, done |
| An operator is cleaning up after a node already gone | The operator | `forget <pubkey>`, per node |
| A node silently loses connectivity | **Nobody, reliably** | Detected locally, shown in `status`, corroborated with `probe`, acted on by a human |

`wglan leave` seals a `LEAVE` and sends it to every peer in `peers.json`, reusing the joiner's
fan-out. Each recipient removes the peer from `peers.json`, the `/etc/hosts` block, and the
interface. This fixes a real asymmetry: joining was one command that propagated mesh-wide, while
leaving was `forget` on all N−1 others.

**`LEAVE` is not sent from a shutdown hook.** A node stopping to reboot has not left the mesh, and
making every restart announce a departure turns the common case into the rare case's message.

**After the fan-out completes, `wglan leave` deletes its own mesh interface.** Not the firewall —
wglan never touches nftables (§12), so there is nothing of its own to remove there. The interface
is deleted unconditionally, whether or not every peer was reachable: an unreachable peer already
falls to row three of the table above (detected, not acted on), and that outcome doesn't change
because a *different* peer left cleanly. Deletion happens strictly after the fan-out, never
interleaved with it — `LEAVE` is bound to the tunnel (§6.1), so tearing the interface down mid-loop
would break every send after the first, silencing exactly the peers still waiting to hear.

### 6.1 Required constraint

**A `LEAVE` is honoured only when it arrives inside the tunnel, from the mesh address owned by the
pubkey it names.** A sealed message proves the sender holds the secret — *not* that the sender is
the pubkey named inside it. Without this binding, any member could evict any other member, and in
a design with no reconcile loop the eviction is permanent. Requiring `LEAVE` to arrive over
`wglan0` from the departing peer's own mesh IP makes WireGuard's cryptokey routing prove the
sender's identity before any wglan code runs.

`LEAVE` is a cooperative convenience, not a security control. A hostile or crashed node simply
never sends one — which is why row three of the table above is not solved by it.

## 7. Repair — operator-triggered, no background logic

The absence of a reconcile loop must not mean the absence of any way to fix state. All three of
these are manual, run to completion, and add no timers.

- **`wglan sync <peer-ip:port>`** — sends the ordinary `JOIN`, unions the returned list, applies
  the difference (`wg set` per new peer, rewrite the hosts block). Because `JOIN` is already
  symmetric, `sync` is the join path with "already known is not an error" — not a new protocol.
  This is the fix for a missing edge after concurrent joins, and for a node whose `peers.json` was
  lost or is stale. It runs **outside** the tunnel, for the reason in §13.
- **`wglan forget <pubkey>`** — removes that peer from `peers.json`, the hosts block, and the
  interface. Run per node. Bounded local state cleanup, **not revocation**: a node that still
  holds the secret can rejoin.
- **`wglan probe <pubkey|hostname>`** — asks every known member for *their* view of one suspect
  peer and prints the tally: `node7: reachable from 0/11 peers`. This is the diagnosis step before
  `forget`, and it exists because one node's opinion about reachability is not evidence (§8).

  It is **not** "a `sync` that reports instead of applying", as draft 1 had it: a `JOIN_REPLY`
  carries no liveness data, so there is nothing for a repurposed `sync` to report. `PROBE` carries
  a `target` pubkey and `PROBE_REPLY` answers with `known` plus `handshake_age`. Both travel inside
  the tunnel and are bound to the sender's mesh address exactly as `LEAVE` is (§6.1), because a
  probe only ever addresses peers already in `peers.json`.

## 8. Liveness — detected locally, never propagated

WireGuard already tracks what is needed: **stale means a handshake older than 180 seconds**
(`REJECT_AFTER_TIME`).

Draft 1 asked for two signals — handshake age **and** transfer counters that had not grown "since
the last check" — on the grounds that a peer with nothing to say looks idle while being perfectly
healthy. That is true in general and false here, twice over. First, §11 sets
`persistent-keepalive 25` on every peer in both directions, so a reachable peer is never silent and
its handshake cannot age past the rejection threshold. Second, `status` is one-shot and nothing runs
on a timer (§1), so there is no "last check" to compare against; two runs a second apart would mark
a healthy mesh stale. The counters are printed next to the handshake age instead, so a human still
sees both numbers and can disagree.

Add a persisted counter snapshot only if a peer is ever seen reading stale while healthy.

Detection never triggers automatic eviction and is never broadcast. Recording why, so it does not
get re-litigated:

1. **"The node is dead" and "I cannot reach the node" are indistinguishable to one observer.**
   Not an implementation gap — it is the property that makes distributed failure detection hard,
   and the reason real systems use quorums or leases rather than one node's opinion.
2. **The dangerous case is partial connectivity, not total.** A fully isolated node cannot
   broadcast anything, so it is self-limiting. But a VLAN misconfiguration or an asymmetric
   firewall rule leaves a node able to reach most peers and not others. It then announces "node7
   is gone" while ten other nodes are talking to node7 happily.
3. **In this design that mistake is permanent.** No reconcile loop to undo it, no re-add path, and
   the eviction is persisted to `peers.json`, so it survives restarts. A two-node routing fault
   becomes a mesh-wide eviction of a healthy node.
4. **The costs of *not* evicting are inventory costs, not runtime costs.** A lingering dead peer
   rots `status` output, leaves a stale `node7.mesh` entry that fails slowly (connect timeout
   rather than NXDOMAIN), and holds its address against reuse via the duplicate check. All
   human-visible, none breaking. Inventory is operator-owned here by design, so these want a human
   decision — exactly what automatic eviction removes. (Runtime cost is near zero but not zero:
   with `PersistentKeepalive=25` a dead peer draws periodic unanswered handshake initiations,
   ~148 bytes every few seconds during each attempt window.)

If automatic eviction is ever genuinely wanted, the minimum safe shape is: **soft state only**
(mark unreachable, never remove from WireGuard or `peers.json`, so a false positive costs a wrong
label rather than a broken mesh) **plus majority agreement** before even the soft mark propagates.
That is a periodic detector, a gossip round, and a quorum rule — the reconcile loop this design
deleted plus a consensus mechanism it never had. A deliberate reversal of the purely-reactive
property, not a feature added at the edges.

## 9. CLI surface

```
wglan secret                                  print a fresh wglan://v1/... secret
wglan join    --secret S --mesh-ip A/M [--bootstrap IP:PORT] [--hostname H]
              [--interface wglan0] [--listen-port 51820] [--control-port 51821]
wglan run                                     serve the control listener from persisted state
wglan status                                  per-peer view, with stale marking
wglan sync    IP:PORT                         pull + apply peer-list difference
wglan forget  PUBKEY                          local removal of one peer
wglan leave                                   announce departure to every peer, then remove the interface
wglan probe   PUBKEY|HOSTNAME                 mesh-wide reachability tally
wglan firewall                                print the nftables skeleton for this node
```

Also on every subcommand: `--state-dir` (default `/var/lib/wglan`), `--hosts-file` (default
`/etc/hosts`), and `--lan-ip` to override the detected LAN address on a multi-homed host. The first two exist so
the whole binary is testable without root.

`join` is idempotent, and precisely: it loads existing state, brings the interface and firewall
skeleton up to match, and then fans out a `JOIN` **only** if `--bootstrap` was given or `--mesh-ip`
differs from the persisted value. With neither, it is bring-up and nothing else — a restart makes
no network round trip.

`join` then **returns**; it does not serve. The control listener belongs to `run` alone, which is
the process a service manager supervises. Draft 2 had `join` end in the serve loop, which made the
one-command first run pretty and everything after it awkward: the command never returned, and it
could not be re-run against a node whose daemon already held the control port — which is exactly
when a repair is wanted. Bringing a node up is therefore two steps, `join` then `run`, and `sync`
is `join --bootstrap` under the name an operator will look for.

The secret is taken from `--secret`, else `$WGLAN_SECRET`, else `<state-dir>/secret`, where `join`
persists it. Without that last step `run` could not serve the listener after a reboot without an
operator present, which contradicts the reboot-resilience this design claims.

### 9.1 `status` output

```
node3.mesh   10.90.0.3/24                             self
node4.mesh   10.90.0.4    192.168.1.24:51820   handshake 18s   rx 4.2M tx 3.9M
node7.mesh   10.90.0.7    192.168.1.27:51820   stale 4d1h      rx 812.0K tx 1.1M
```

Reads `peers.json`, then `wg show <if> latest-handshakes` and `wg show <if> transfer`. The stale
marker is the whole liveness feature: it reports, a human decides. It never removes a peer and is
never sent to another node. Transfer totals are shown, not gated on (§8).

### 9.2 Logging

- One line per `JOIN` handled, sent or received: direction, truncated pubkey, and outcome —
  accepted (first sight), **changed**, or rejected with the reason.
- **A change is logged differently from a first-sight add, and names old and new values.** This is
  the load-bearing mitigation for the one threat sealing does not cover (§13, last row): static
  addressing means a receiver has nothing to verify `mesh_ip` against, so the address cannot be
  made unforgeable — but silent persistent poisoning becomes a visible event. The same line covers
  the legitimate case: renumbering a node should be conspicuous in every peer's log.
- **Never swallow a rejection silently.** The *wire* response stays uniform (§12.2); the *local*
  log must discriminate, or a field failure is unfalsifiable. Reasons, each naming both parties:
  envelope failed to open · timestamp outside window · unsupported protocol · malformed field ·
  address outside our subnet · address held by another pubkey · hostname held by another pubkey.
- No structured logging, no metrics endpoint. A line per event is enough at this scale.

## 10. State on disk

`/var/lib/wglan/peers.json` — this node's identity plus one entry per peer:

```json
{
  "self":  {"pubkey": "...", "hostname": "node3", "mesh_ip": "10.90.0.3/24",
            "listen_port": 51820, "control_port": 51821},
  "peers": [{"pubkey": "...", "hostname": "node1", "mesh_ip": "10.90.0.1",
             "lan_endpoint": "192.168.1.21:51820"}]
}
```

Private key: `/var/lib/wglan/private.key`, mode `0600`, directory `0700`. Shared secret:
`/var/lib/wglan/secret`, same modes, written by `join` so `run` needs no operator after a reboot
(§9). The keypair is X25519, generated with `crypto/ecdh` — no `wg genkey` subprocess and no stdin
to plumb through the command runner.

**On restart:** if the file exists, reload it straight into WireGuard and skip bootstrapping
entirely — no network round trip. Fall back to `--bootstrap` only when there is no local state, or
when one is passed explicitly.

**`--mesh-ip` wins over the persisted value for this node's own address**, and the file is
rewritten to match. That precedence is what makes renumbering work: change the variable, restart,
and the node re-announces itself to every peer.

Writes are atomic: write `peers.json.tmp` in the same directory, `fsync`, `rename`.

## 11. System side effects — the exact commands

Everything wglan does to the host, in `exec.Command` argv-array form. Never a shell string.

**Interface bring-up** (idempotent; skip each step whose state already matches):
```
ip link add dev wglan0 type wireguard
wg set wglan0 listen-port 51820 private-key /var/lib/wglan/private.key
ip addr add 10.90.0.3/24 dev wglan0
ip link set up dev wglan0
```

**Per peer, on add or update** — one invocation, no full-config rewrite, no interface restart:
```
wg set wglan0 peer <PUBKEY> endpoint <IP:PORT> allowed-ips <MESH_IP>/32 persistent-keepalive 25
```

**Per peer, on removal:**
```
wg set wglan0 peer <PUBKEY> remove
```

**Firewall: none.** wglan does not edit nftables. `wglan firewall` prints a ruleset for the
operator to install; see §12.5.

**Reads for `status`:**
```
wg show wglan0 latest-handshakes
wg show wglan0 transfer
```

## 12. Security

### 12.1 One mechanism, not two

Authentication and confidentiality are the same primitive. Every control message is sealed, and a
successful open *is* the proof of membership — there is no token. A stranger on the LAN can
neither be added as a peer nor learn anything about the mesh, including the peer list that an
authenticate-only design would leak in cleartext during every join.

### 12.2 Pre-auth hardening

The listener is reachable by anyone on the LAN up to the point the envelope fails to open.

- Read **one** length-prefixed message per connection, 4KB hard cap inbound, before doing anything
  else. Never parse an unbounded stream. The larger reply cap in §4.2 applies only to a connection
  this node dialled itself, so it is not reachable by a stranger.
- 3-second read/write deadline on the connection.
- **Rate-limit per source IP *before* attempting the decrypt** — without this, a stranger makes
  the node burn AES cycles on garbage for free.
- **Open the envelope before reading any field.** A GCM failure is a single uniform outcome, so
  wrong key, wrong protocol, stale timestamp, and malformed bytes are indistinguishable on the
  wire *by construction* rather than by careful ordering of hand-written checks. A failed open
  closes the connection with no reply. No parser is reachable before the open succeeds, so there
  is no parser oracle.
- Cap concurrent inbound connections (semaphore of 8) and drop beyond that. Not rate-limiting
  legitimate traffic — churn is ~1/day — a floor against a trivial LAN-local DoS. The per-IP
  limiter caps rate; the semaphore caps simultaneity. Different defenses.
- **None of this defends against a member.** Anyone holding the secret is inside every gate here
  by definition.

### 12.3 Input validation

Every network-supplied field is validated **as a precondition of processing the message**, not at
the point of use. This matters specifically because the daemon shells out to `wg`/`ip` and writes
`/etc/hosts`, both unforgiving of unexpected input. Rules are in §4.3. Plus: argv-array `exec`
exclusively, so even a value that somehow passed validation cannot be reinterpreted by a shell.

### 12.4 Removing a node is a flag day

Membership is "knows the secret", permanently. Anyone who ever held it — a stolen laptop, an
ex-contractor's VM, a decommissioned host with an unwiped disk — can rejoin at will, and their
sealed `JOIN` is by construction indistinguishable from a legitimate one. Neither `forget` nor
`leave` changes that; both are state cleanup.

Every node's envelope key derives from the secret, so a node on the old secret and a node on the
new one cannot exchange *any* control message. There is no grace period and no dual-secret mode:
**rotation is not a rolling operation.** The mesh is partitioned for the duration and every kept
node must be touched inside that window. At a few dozen nodes with manual joins, that is a planned
maintenance window.

If revocation ever becomes a requirement, the answer is **short-lived certificates, not a
revocation list** — identity in a signed cert with a lifetime, so revocation is "let it lapse"
(this is Nebula's model). That is a different identity architecture, not a feature to bolt onto a
shared secret, which is exactly why deferring it here is defensible and why a half-measure would
be worse than the honest gap.

### 12.5 Host firewall — one file, one owner

Once a node joins, WireGuard exposes whatever that host already has listening on `0.0.0.0` — not
just what it was meant to expose. `sshd`'s all-interfaces bind is why SSH just works over the mesh
with no code involved; a monitoring agent or a stray debug listener is exposed identically, with no
deliberateness at all.

**wglan ships the ruleset and never applies it.** `wglan firewall` prints `nftables/wglan.conf` with
its two `define` lines set from `--interface` and `--control-port`:

```
wglan firewall > /etc/nftables.d/wglan.conf
nft -c -f /etc/nftables.d/wglan.conf     # check before committing to it
nft -f    /etc/nftables.d/wglan.conf
```

The file is a `table inet wglan` with a base chain at `policy accept`, two rules scoping the
fail-closed drop to `iifname $WGLAN_IFACE`, and a regular `mesh` chain holding the allow-list:
conntrack first, then the control port, then ICMP echo, then whatever this node serves. It reloads
idempotently (`table` / `delete table` / `table`) and rebuilds atomically.

An earlier draft had the daemon create this at startup, create-if-missing. That was wrong in four
separate ways, and the pattern in the mistakes is what settles the question:

- A base chain at `policy drop`, which is not a scoped default-deny but a total one — first startup
  cut the host off entirely.
- No conntrack rule, so every connection the host *initiated* over the mesh hung, `ping <peer>`
  included.
- `iif` rather than `iifname`, matching an interface index that decays to nothing when the interface
  is recreated — failing open, with no path to repair since the check was on the table's existence.
- Eight sequential `nft add` calls, so a failure partway left a table with no drop rule in it, and
  every later start concluded the skeleton was already there.

Each was a bug in *managing host state that belongs to someone else*, not in the ruleset. Emitting
the file removes the class:

- **It survives.** A runtime-applied table is destroyed by `systemctl restart nftables` with nothing
  noticing, and by a reboot; a file in the nftables config is reloaded by both.
- **One owner.** The per-node allow rules go in the same `mesh` chain in the same file, so a reload
  rebuilds the whole thing rather than leaving wglan's half in place and the operator's gone. The
  split-ownership footgun disappears instead of being managed.
- **Reviewable.** It is nftables, diffable, and `nft -c -f` checks it. Three of the four bugs above
  lived inside a Go format string where nothing could see them.
- **Nothing to reconcile.** No create-if-missing, no drift detection, no half-built state, no
  question about what an upgrade does to an existing node.

What it costs, stated plainly: **it is not on by default.** A node that joins before the file is
installed exposes every port it already has bound. That is the trade — a default-deny the daemon
could not apply correctly, against a correct one somebody has to install.

**Scope by interface name, not by IP — and not by index.** `iifname "wglan0"` needs neither the
address nor the interface to exist yet, so the file can be loaded before wglan ever runs, and it
stays correct across a renumber.

**The input hook is not the whole story.** The chain gates host processes. A container port published
with `-p` is DNAT'd in `prerouting` and *forwarded*, never delivered to `input`, so it bypasses this
file entirely — verified. Gate those in Docker's `DOCKER-USER` forward chain, or give the container
host networking and allow the port here. No ruleset hooked at `input` can cover that case, so the
file says so in a comment rather than implying a guarantee it does not have.

## 13. Threat model

| Threat | Mitigation | Residual |
|---|---|---|
| Stranger on the LAN joins the mesh | Cannot produce an openable envelope without the secret. Sealing *is* the membership proof. | None. |
| Passive eavesdropper learns the topology — and via `peers`, the entire mesh from one capture | Whole payload inside the AEAD. | None. |
| Tampering with a captured message. The serious case: rewriting `mesh_ip` repoints a peer's `AllowedIPs` and hosts entry, and nothing ever repairs it | GCM tag covers the entire payload; any edit fails the open. | None from a non-member. |
| Verbatim replay inside the freshness window | Nonce seen-set, bounded by the freshness window (§4.4). `JOIN` is *not* idempotent — §3.4 makes it last-writer-wins — so replaying a pre-renumber or pre-`forget` capture would otherwise undo the change. | None. |
| Replay of an old or future-dated capture | Freshness check, ±600s, inside the seal. | Bounded to a 10-minute window. |
| Pre-auth resource exhaustion | 4KB framed read inbound · 3s deadlines · connection semaphore · **per-IP rate limit before the decrypt attempt**. | A LAN-local flood can still deny joins while it runs. Joins are rare and manual; accepted. |
| Parser oracle | A failed open is the only rejection reachable pre-auth, and it is uniform. Structurally stronger than ordered hand-written checks: GCM failure carries no field-level detail to leak. | None. |
| Injection via a wire field into `wg`/`ip`/`/etc/hosts` | Strict per-field validation as a precondition, plus argv-array `exec` exclusively. | None. |
| A member reaches a service this host never meant to expose | Not mitigated by the daemon. `wglan firewall` emits a default-deny ruleset for `wglan0`, but installing it is the operator's act (§12.5). | **Accepted, and worth being honest about:** a node that joins before the file is installed exposes every port already bound on it. Container ports published with `-p` bypass the file even when it is installed, being forwarded rather than delivered to `input`. |
| **A member forges a `LEAVE` to evict a healthy node** | Honoured only inside the tunnel, from the departing peer's own mesh address, so cryptokey routing binds the message to its sender before any code runs. A `LEAVE` naming someone else is dropped. Two checks, not one: the connection must have been accepted on *our* mesh address (so it arrived on `wglan0`, not the LAN), and its source must be the mesh address recorded for the pubkey named. | None from this path. Same binding on `PROBE`. |
| **A member moves an existing peer's address onto its own pubkey** — the interception case, not the squatting one | The duplicate check has no exemption for known pubkeys (§3.3, §3.4): a `JOIN` whose `mesh_ip` or `hostname` is held by a different pubkey is rejected and logged, naming both. | None from this path. The cost is that renumbering into an address a dead peer still holds needs a `forget` first. |
| **A member forges an unclaimed address for itself** | Not mitigated. Any holder of the secret can seal a `JOIN` claiming any *free* in-subnet address for its own pubkey. | **Accepted, consistent with the model**: membership is total and permanent by design. Deterministic addressing would allow verifying `mesh_ip == derive(pubkey, secret)`; static addressing forecloses that permanently. The substitute is loud change-logging (§9.2), which cannot prevent the forgery but makes it impossible to miss. |
| **A member lies about a third party's `lan_endpoint`**, e.g. pointing 256 peers' keepalives at one victim | Partly. For a `JOIN` arriving directly, the endpoint host is taken from the connection's observed source address and only the claimed port is kept — a node cannot lie about where it is. Entries learned second-hand through `peers[]` have nothing to compare against and stay as claimed. | A member can still poison second-hand entries. Closing it needs per-node signatures, which is the certificate architecture of §12.4, not a field. |

**`sync` does not get the free safety, but `leave` and `probe` do.** Draft 1 hoped `sync` could
travel inside the tunnel and inherit WireGuard's authentication for nothing. It cannot: the case
`sync` exists to repair is a *missing* edge after concurrent joins, so by definition there is no
tunnel to that peer yet. `sync` is the `JOIN` path, outside the tunnel, with the envelope as its
only authentication.

`leave` and `probe` only ever address peers already in `peers.json`, so those two do travel inside
the tunnel — cryptokey routing authenticates the sender before any wglan code executes, and the
envelope is belt-and-braces. They also bind their own source address explicitly when dialling, so a
multi-homed host cannot have the kernel pick a source the receiver will reject.

## 14. Concurrency

All mutations to the peer map and the two files it drives (`peers.json`, the `/etc/hosts` block)
happen under **one mutex covering the full validate → apply → persist → snapshot sequence** for a
single `JOIN`. Sealing and writing the reply happen outside the lock, from that snapshot: the
snapshot is immutable by then, and the write is network I/O under a deadline that no other handler
should have to queue behind. The reason is ordinary and local: two concurrent handlers must not interleave a map
update with a file rewrite and leave either file reflecting a state that never existed.

Note what this lock is *not* doing. In an auto-assignment design it would be load-bearing for
correctness — and could not deliver, because serializing on one node says nothing about a joiner
bootstrapping through a different one. With static addresses it has no distributed obligation at
all: an address is decided before either node starts, so concurrent joins cannot conflict over one
no matter how they interleave.

The daemon is a network-facing server accepting concurrent connections by construction, so
`go test -race` is non-optional.

## 15. Reaching a service on another node

Operational note, not part of the daemon. A container on `node2` bound to `node2`'s **mesh IP
specifically** (`docker run -p 10.90.0.2:443:443 ...`, never `0.0.0.0`) is reachable from `node1`
as `https://node2.mesh` over the tunnel and only over the tunnel — the LAN and public interfaces
never see the DNAT rule.

That bind, the firewall allow rules, and the TLS SAN all want the address known *before* the node
joins, which an operator-assigned static address gives directly and a join-order-dependent
assignment could not. TLS certs need `node2.mesh` in the SAN; self-signed, or one local CA in
every node's trust store, is sufficient for a private mesh.

## 16. Open questions

- **Clock skew on an air-gapped LAN.** The 600-second window requires every clock to be within 10
  minutes of every other's — trivially true with NTP, and *not* guaranteed on exactly the network
  this targets: no internet, freshly imaged VMs, a dead RTC battery. The failure is a join refused
  with the deliberately-uniform rejection, indistinguishable on the wire from a wrong secret.
  Three ways out, increasing cost:
  1. Ship the 600s window, require a working clock, and rely on the *local* log line — which does
     distinguish "timestamp outside window" from "failed to open" — to make diagnosis a
     five-second job. **Current default.**
  2. Widen to an hour. Cheap; weakens the replay bound for no structural gain, since replay is
     already harmless while `JOIN` stays idempotent.
  3. Replace the timestamp with challenge–response: the bootstrap node sends a sealed random
     nonce, the joiner seals it back. Removes the clock dependence and gives true single-use
     replay protection — at the cost of a second round trip and per-connection listener state.
     Reach for this only if (1) proves to be a real field problem.

  Note that the seen-set (§4.4) shares this clock dependence rather than adding a new one: it is
  bounded *by* the freshness window, so a node with a badly wrong clock fails at the timestamp check
  before the nonce is ever consulted.
- **~~`sync` inside the tunnel.~~ Resolved: no.** The case `sync` exists to repair is a missing edge
  after concurrent joins, and a missing edge means no tunnel. `sync` runs outside the tunnel with
  the envelope as its only authentication; `leave` and `probe` keep the binding (§13).
- Adding revocation later would change the replay calculus: a revoked member's captured `JOIN`
  would still open and still be honoured inside the freshness window. **Revocation and
  challenge–response arrive together or not at all.**

## 17. Changes from draft 1

Draft 1 was reviewed before implementation and ten things did not survive contact. Each is recorded
where it belongs above; this is the index, so nothing looks like an undocumented divergence.

| # | Draft 1 | Draft 2 | Where |
|---|---|---|---|
| 1 | `nft` skeleton was one base chain with `policy drop`, created by the daemon | Base chain `policy accept`, drop scoped to `iifname`, allow-list in a regular chain the drop jumps into — and shipped as a file the operator installs rather than applied at startup. Draft 1's version cut the host off entirely | §12.5 |
| 2 | One 4096-byte frame cap, `peers` capped at 256 | Two caps: 4096 inbound, 262144 on a reply we asked for. 4096 held ~20 peers | §4.2 |
| 3 | A known pubkey was exempt from the duplicate checks | Exempt only against its own current values; collision with any *other* pubkey is still rejected. The exemption was an interception primitive | §3.3, §3.4, §13 |
| 4 | `--control-port` existed but was on neither the wire nor the peer record | `control_port` is a payload field and a peer field | §4.3, §10 |
| 5 | Nothing ever allowed tcp/51821 on `wglan0`, so in-tunnel `LEAVE` could not arrive | The shipped ruleset allows the control port and ICMP echo | §12.5 |
| 6 | No nonce cache, because "`JOIN` is idempotent" | Seen-set, because §3.4 made `JOIN` last-writer-wins — draft 1's own stated trigger | §4.4, §13 |
| 7 | Stale required transfer counters "since the last check", which nothing stored | Stale is handshake age past 180s; keepalives make it sufficient. Counters are printed | §8, §9.1 |
| 8 | `peers[]` validation was implied; `lan_endpoint` was taken on trust | `peers[]` validated identically, one bad entry rejects the message; a direct `JOIN`'s endpoint host comes from the observed source address | §4.3, §13 |
| 9 | `sync` was to travel inside the tunnel "for free"; `probe` was "a `sync` that reports" | `sync` runs outside the tunnel; `probe` is its own message pair carrying liveness | §7, §13, §16 |
| 10 | The secret had nowhere to live, so `run` could not start after a reboot | `<state-dir>/secret`, written by `join` | §9, §10 |

**Since draft 2.** Three further firewall defects surfaced during implementation — no conntrack rule
(every outbound connection hung), `iif` instead of `iifname` (failed open on interface re-create),
and non-atomic creation (a partial skeleton was unrepairable). All three were bugs in *applying* the
ruleset rather than in the ruleset itself. wglan no longer edits nftables at all: it emits
`nftables/wglan.conf` for the operator to install (§12.5). The `--no-firewall` flag that briefly
existed to opt out of the daemon's editing is gone with it.
