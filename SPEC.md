# wglan — specification

**Version:** protocol `wglan-v1` · spec draft 1 · status: ready to implement
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

This is the accepted cost of static addressing: derivation makes duplicates impossible, static
assignment makes them a human error that this check has to catch.

### 3.4 The peer map is keyed on pubkey

A `JOIN` from an already-known pubkey **updates** that peer's address and hostname in place
rather than tripping the duplicate checks. Two things depend on this:

- **Renumbering is one variable change plus a restart.** The node re-`JOIN`s every peer with its
  new address and every peer updates in place. No scheme deriving the address from the node's key
  can do this without regenerating the keypair.
- **A reinstalled node** (new keypair, same hostname) is `forget` on the old pubkey plus a normal
  join — not hand-edited JSON on every host.

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
[uint32 big-endian length]     hard cap 4096 — larger is dropped without reading the body
{
  "nonce":      base64,        // 12 random bytes, fresh per message
  "ciphertext": base64         // AES-256-GCM; the tag covers the entire payload
}
```

### 4.3 Sealed payload

Every field is inside the ciphertext, so all of it is confidential *and* tamper-evident.

| Field | Type | Rule |
|---|---|---|
| `protocol` | string | `"wglan-v1"`. Checked first; fails closed on version skew before any other field is read. |
| `type` | string | `JOIN`, `JOIN_REPLY`, or `LEAVE`. |
| `timestamp` | int64 | Unix seconds. Freshness bound, §4.4. Inside the seal, so unforgeable. |
| `pubkey` | string | Sender's WireGuard public key: exactly 44 base64 chars decoding to 32 bytes. |
| `hostname` | string | `^[a-z0-9-]{1,63}$`. |
| `mesh_ip` | string | Sender's mesh address, no mask (the mask is local-only state). Must parse via `net.ParseAddr` and fall inside the receiver's configured subnet. |
| `lan_endpoint` | string | Sender's `ip:port` for the WireGuard data plane. Must parse via `net.SplitHostPort` + address parse — not a regex. |
| `peers` | array | `JOIN_REPLY` only. `{pubkey, hostname, mesh_ip, lan_endpoint}` per known member. **Capped at 256 entries.** |

A `LEAVE` carries `protocol`, `type`, `timestamp`, `pubkey` only. No other field is read.

`peers` is why confidentiality is required rather than nice-to-have: one captured reply is the
complete network map, not one node's details.

### 4.4 Freshness

A payload whose `timestamp` is more than **600 seconds** old, **or more than 600 seconds in the
future**, is rejected. Both directions deliberately — rejecting only "too old" leaves a
future-dated capture replayable indefinitely once its time arrives.

**No nonce cache.** A `JOIN` asserts "peer X is at address Y"; applying it twice equals applying
it once. Add a seen-set only if `JOIN` ever gains a non-idempotent side effect.

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
  lost or is stale.
- **`wglan forget <pubkey>`** — removes that peer from `peers.json`, the hosts block, and the
  interface. Run per node. Bounded local state cleanup, **not revocation**: a node that still
  holds the secret can rejoin.
- **`wglan probe <pubkey|hostname>`** — asks every known member for *their* view of one suspect
  peer and prints the tally: `node7: unreachable from 11/11 peers (stale 4d)`. A `probe` is a
  `sync` that reports instead of applying. This is the diagnosis step before `forget`, and it
  exists because one node's opinion about reachability is not evidence (§8).
  *Build this last, and only if diagnosing suspected-dead peers becomes a recurring chore* — the
  stale marker in `status` answers the common case alone.

## 8. Liveness — detected locally, never propagated

WireGuard already tracks what is needed. **Two signals, not one:** a handshake older than the
threshold **and** transfer counters that have not grown since the last check. Handshake age alone
misleads, because a peer with nothing to say looks idle while being perfectly healthy.

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
wglan leave                                   announce departure to every peer
wglan probe   PUBKEY|HOSTNAME                 mesh-wide reachability tally
```

`join` is idempotent: with existing state it behaves as `run` plus a `sync` against `--bootstrap`
if one is given.

### 9.1 `status` output

```
node4.mesh   10.90.0.4   192.168.1.24:51820   handshake 18s
node7.mesh   10.90.0.7   192.168.1.27:51820   stale (4d, no transfer)
```

Reads `peers.json`, then `wg show <if> latest-handshakes` and `wg show <if> transfer`. The stale
marker is the whole liveness feature: it reports, a human decides. It never removes a peer and is
never sent to another node.

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

Private key: `/var/lib/wglan/private.key`, mode `0600`, directory `0700`.

**On restart:** if the file exists, reload it straight into WireGuard and skip bootstrapping
entirely. Fall back to `--bootstrap` only when there is no local state.

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

**Firewall skeleton, at startup, create-if-missing only** (§12.5):
```
nft add table inet wglan
nft add chain inet wglan wglan0_in '{ type filter hook input priority 0; policy drop; }'
```

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

- Read **one** length-prefixed message per connection, 4KB hard cap, before doing anything else.
  Never parse an unbounded stream.
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

### 12.5 Host firewall — split ownership

Once a node joins, WireGuard exposes whatever that host already has listening on `0.0.0.0` — not
just what it was meant to expose. `sshd`'s all-interfaces bind is why SSH just works over the
mesh with no code involved; a monitoring agent or a stray debug listener is exposed identically,
with no deliberateness at all.

Two concerns, two owners:

- **wglan** ensures, at startup, that one thing exists: `table inet wglan` with chain `wglan0_in`,
  `policy drop`, scoped `iif "wglan0"` — **created only if missing, with no rules beyond the
  policy.** It never inspects ports, services, or peers, and never modifies the chain if it
  already exists.
- **Config management inserts the allow rules into that same chain**, e.g.
  `iif "wglan0" tcp dport 22 accept`. Not a separate table: two independently-owned tables both
  hooked at `input` need their relative priorities primed correctly for an ACCEPT in one to take
  effect before a DROP in the other, which is a real footgun and easy to get silently wrong. One
  chain, top-to-bottom, first match wins, is much harder to break.
- **Scope by interface, not by IP.** `iif "wglan0"` needs neither the address nor the interface to
  exist yet, so there is no ordering dependency between skeleton creation, rule insertion, and the
  join. It is exactly as precise as scoping by mesh subnet, since nothing but WireGuard-decrypted
  peer traffic can ever arrive on `wglan0`. (With static addressing the mesh IP *is* known ahead
  of time and could be used — interface scoping is still preferred because it survives a
  renumber.)
- **The allow-list is per-node** — every node allows 22, the HTTPS node also allows 443 — and
  belongs in host vars next to `mesh_ip`, not in the daemon.

No drift detection beyond the fail-closed skeleton. Which ports get allowed is operator
discipline; only the guarantee that *nothing* is allowed until something explicitly says otherwise
is built in.

## 13. Threat model

| Threat | Mitigation | Residual |
|---|---|---|
| Stranger on the LAN joins the mesh | Cannot produce an openable envelope without the secret. Sealing *is* the membership proof. | None. |
| Passive eavesdropper learns the topology — and via `peers`, the entire mesh from one capture | Whole payload inside the AEAD. | None. |
| Tampering with a captured message. The serious case: rewriting `mesh_ip` repoints a peer's `AllowedIPs` and hosts entry, and nothing ever repairs it | GCM tag covers the entire payload; any edit fails the open. | None from a non-member. |
| Verbatim replay inside the freshness window | Not prevented, and does not need to be: `JOIN` is idempotent. No nonce cache, deliberately. | Only if `JOIN` gains a non-idempotent side effect. Add a seen-set then, not before. |
| Replay of an old or future-dated capture | Freshness check, ±600s, inside the seal. | Bounded to a 10-minute window. |
| Pre-auth resource exhaustion | 4KB framed read · 3s deadlines · connection semaphore · **per-IP rate limit before the decrypt attempt**. | A LAN-local flood can still deny joins while it runs. Joins are rare and manual; accepted. |
| Parser oracle | A failed open is the only rejection reachable pre-auth, and it is uniform. Structurally stronger than ordered hand-written checks: GCM failure carries no field-level detail to leak. | None. |
| Injection via a wire field into `wg`/`ip`/`/etc/hosts` | Strict per-field validation as a precondition, plus argv-array `exec` exclusively. | None. |
| **A member forges a `LEAVE` to evict a healthy node** | Honoured only inside the tunnel, from the departing peer's own mesh address, so cryptokey routing binds the message to its sender before any code runs. A `LEAVE` naming someone else is dropped. | None from this path. |
| **A member forges another member's address** | Not mitigated. Any holder of the secret can seal a `JOIN` claiming any in-subnet address for its own pubkey. | **Accepted, consistent with the model**: membership is total and permanent by design. Deterministic addressing would allow verifying `mesh_ip == derive(pubkey, secret)`; static addressing forecloses that permanently. The substitute is loud change-logging (§9.2), which cannot prevent the forgery but makes it impossible to miss. |

**Why `sync` is safer than `JOIN`, for free.** `JOIN` must run outside the tunnel — at bootstrap
there is no tunnel yet. `sync` runs between established members, so it can bind the mesh address
and travel inside the tunnel: cryptokey routing has already authenticated the sender before any
wglan code executes, and the envelope is belt-and-braces.

## 14. Concurrency

All mutations to the peer map and the two files it drives (`peers.json`, the `/etc/hosts` block)
happen under **one mutex covering the full validate → apply → persist → reply sequence** for a
single `JOIN`. The reason is ordinary and local: two concurrent handlers must not interleave a map
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
- **`sync` inside the tunnel.** §13 notes `sync` can inherit WireGuard's authentication for free.
  Confirm during implementation that nothing in the repair path must run before a tunnel exists —
  if it does, `sync` needs the same outside-the-tunnel treatment as `JOIN` and the extra safety
  evaporates.
- Adding revocation later would change the replay calculus: a revoked member's captured `JOIN`
  would still open and still be honoured inside the freshness window. **Revocation and
  challenge–response arrive together or not at all.**
