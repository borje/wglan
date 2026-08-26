# wglan

A minimal WireGuard mesh for a LAN with no internet access.

One shared secret and one bootstrap address gets a node into a full mesh. Addresses are assigned
by the operator. Control messages are sealed with AES-256-GCM, and opening one *is* the proof of
membership — there is no token, no certificate authority, and no discovery service. Once a join
completes, **nothing runs on a timer.**

> The name is deliberately boring: **WireGuard, on the LAN.** It sorts next to `wg` and
> `wg-quick`, and a colleague who finds `wglan0` in `ip a` needs no context to guess what it is.

```
wglan secret                                                   # on any host
wglan firewall > /etc/nftables.d/wglan.conf && nft -f $_       # once per host
wglan join --secret wglan://v1/... --mesh-ip 10.90.0.1/24      # first node
wglan join --secret wglan://v1/... --mesh-ip 10.90.0.2/24 \
           --bootstrap 192.168.1.21:51821                       # every node after
curl https://node1.mesh                                         # from node2
```

The second command is the entire mesh. The third is the only one you repeat.

## What you get

- **Full mesh from one bootstrap IP.** A joiner unions the peer list it is handed, then greets
  every member directly. Convergence is exact for non-overlapping joins — no gossip round, no
  eventual consistency.
- **No background logic.** No reconcile loop, no peer expiry, no timers. Endpoint drift is
  WireGuard's own roaming behaviour. State repair is three explicit commands.
- **Static addressing.** Every node's address is in your inventory, known before it joins — which
  is what a firewall rule, a container bind, and a TLS SAN all need.
- **Symmetric join and leave.** `wglan leave` propagates mesh-wide the same way a join does.
- **Human-readable names.** A managed `/etc/hosts` block, not a DNS server.
- **Zero dependencies.** `crypto/hkdf`, `crypto/ecdh` and AES-GCM are stdlib as of Go 1.24; the
  binary shells out to `wg`, `ip`, and `nft` exactly as `wg-quick` does.
- **A firewall ruleset you install, not one it applies.** `wglan firewall` prints a default-deny
  `nftables` table for the mesh interface, ready for `/etc/nftables.d/`. wglan never edits your
  firewall — so it survives an `nftables` restart, and there is no half-owned table to reconcile.

## What you don't

No DHT, no rendezvous server, no multicast. No revocation — membership is "knows the secret",
permanently, and removing a node is a secret rotation, which is a flag day rather than a command.
No automatic eviction of unreachable peers: liveness is detected and reported, never acted on
automatically and never propagated. No IPv6, no ACLs, no DNS, Linux only.

Each of those has a reason recorded next to it, because the reason is what stops it being
re-added by accident. See [SPEC.md §2](SPEC.md) and §8.

## Documentation

| Document | For |
|---|---|
| **[SPEC.md](SPEC.md)** | The normative spec. Wire format, CLI surface, exact `wg`/`ip`/`nft` invocations, threat model, open questions. Implement from this. |
| **[IMPLEMENTATION.md](IMPLEMENTATION.md)** | File layout, six milestones with the acceptance check for each, test strategy, and the deferral list with its triggers. |
| **[docs/field-guide.html](docs/field-guide.html)** | The argument, with sequence diagrams — join, restart, data plane, false-eviction cascade, bootc readiness ordering. For evaluating the design rather than building it. |
| **[docs/feature-matrix.html](docs/feature-matrix.html)** | wglan against the tools people shop for "WireGuard mesh," plus an internal shipped/deferred inventory. For positioning, not for building it. |
| **[nftables/wglan.conf](nftables/wglan.conf)** | The shipped firewall skeleton, commented. `wglan firewall` prints this with your `--interface` and `--control-port` filled in. |
| **[SPEC.md §17](SPEC.md)** | The ten things spec draft 1 got wrong, and what replaced each. Read this before assuming the code diverges from the spec. |

## Status

Implemented, spec at draft 2. `go build ./...` produces the binary; `go test ./... -race` is the
gate. `testdata/mesh.sh` runs three nodes plus a `leave` in network namespaces — root and
`wireguard-tools` required.

Draft 1 was reviewed before any code was written and ten defects came out of it, three of them
serious: the `nftables` skeleton took the whole host offline rather than defaulting `wglan0` to
deny, a 4KB frame cap could not carry the peer list past ~20 nodes, and an exemption in the
duplicate-address check let any member move another peer's address onto its own key. All ten are
fixed in the spec and the code, and indexed in [SPEC.md §17](SPEC.md).

Extracted from a design review of [wgmesh](https://github.com/atvirokodosprendimai/wgmesh), whose
sealed-envelope pattern this reuses and whose DHT, gossip, RPC, reconcile loop, derived addressing,
and collision resolution it does not.
