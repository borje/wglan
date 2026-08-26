# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`wglan` is a minimal WireGuard full-mesh daemon/CLI for a LAN with no internet access: one shared
secret plus one bootstrap address joins a node into a full mesh. No DHT, no gossip, no reconcile
loop, no revocation — read the README's "What you get" / "What you don't" before proposing a
feature; most tempting additions (background reconciliation, automatic eviction, DNS, IPv6, ACLs)
are deliberately deferred and listed with their trigger condition in
[IMPLEMENTATION.md](IMPLEMENTATION.md) ("Deliberately not in v1"). Don't re-add them without the
trigger having actually occurred.

**[SPEC.md](SPEC.md) is the normative spec — implement from it, not from the README.** It has the
wire format, exact CLI surface, exact `wg`/`ip`/`nft` invocations, threat model, and open
questions. §17 lists what draft 1 got wrong and why, so read that before assuming the code
diverges from the spec by mistake. [IMPLEMENTATION.md](IMPLEMENTATION.md) is the build order: file
layout, six milestones each with its acceptance check, and test strategy — read it before adding a
file or a package.

## Commands

```
go build ./...              # build everything
go vet ./...
go test ./... -race         # the gate; race is not optional (concurrent handler by construction)
go test ./envelope -race    # envelope package alone
go test -run TestName ./... -race   # a single test
sudo testdata/mesh.sh        # three-node end-to-end in network namespaces; needs root + wireguard-tools
```

`firewall_test.go` guards the embedded `nftables/wglan.conf` ruleset; run as root to also exercise
`nft -c -f` against it.

`wglan firewall | diff - nftables/wglan.conf` must be empty — the CLI prints the same file it
embeds, with only `--interface`/`--control-port` substituted (see `renderFirewall` in main.go).

## Architecture

One `main` package, deliberately not split further — six files, plus one package (`envelope`) for
the one thing worth isolating. Do not add new packages or split main.go without a reason as strong
as the ones below (see IMPLEMENTATION.md "Layout" for the full rationale):

- **`envelope/`** — seal/open, HKDF key derivation, freshness window, nonce seen-set, all field
  validation. Payload structs can only be constructed via `Open`, so "validation is welded to the
  open" (SPEC §4.5) is a compiler-enforced invariant, not a discipline one. Never construct an
  `envelope.Peer`/payload outside this package.
- **`main.go`** — flag parsing, subcommand dispatch, interface bring-up, serve loop. Embeds
  `nftables/wglan.conf` via `go:embed` and rewrites two named-constant lines for `wglan firewall`.
- **`join.go`** — the `Node` struct (one mutex, one state file, one subnet), JOIN/LEAVE/PROBE
  client + handlers, fan-out on join, rate limiter. The mutex covers the whole
  validate → apply → persist → reply sequence for one message (SPEC §14) — it has to span
  `state.go` and `system.go`, which is why it lives on `Node` rather than on the state loader.
- **`state.go`** — `peers.json` load/save (atomic write), peer lookups. `Self.MeshIP` carries the
  subnet mask; the mask is local-only and never goes on the wire.
- **`system.go`** — every `exec.Command` call in the binary lives here (wg/ip/hosts side effects),
  behind a `CommandRunner func(name string, args ...string) ([]byte, error)` field — one seam to
  fake in tests, one file to grep to answer "what does this binary do to my host". Don't call
  `exec.Command` from anywhere else.
- **`status.go`** — `wg show` parsing and stale-peer determination (handshake age past 180s).

No background logic anywhere: nothing runs on a timer once a join completes. Liveness is detected
on demand (`status`, `probe`) and never acted on automatically or propagated (SPEC §8) — don't add
a reconcile loop or auto-eviction; that's `IMPLEMENTATION.md`'s explicit deferral list.

## Testing conventions (see IMPLEMENTATION.md "Test strategy")

- Table-driven, `t.Parallel()`, always `-race`.
- **Fake the `CommandRunner`, not the network.** Protocol tests run over real loopback
  TCP/`net.Pipe` (cheap, finds real framing bugs); `wg`/`ip`/`nft` calls are faked and asserted on
  recorded argv — real `ip link add` needs root and finds nothing a fake can't.
- **Assert on argv (`[]string{...}`), never on a joined/rendered string** — a string comparison
  would leave the command-injection guarantee (SPEC §12.3) untested.
- Tunnel-binding tests (LEAVE/PROBE must be rejected off-tunnel, SPEC §6.1) use `127.0.0.<n>` for
  both mesh and "LAN" addresses so the binding check is exercised over real loopback without root.
- The hosts-block writer test uses a hostile `/etc/hosts` (no markers, markers with unrelated
  content around them, duplicated END marker) — everything outside the markers must survive
  byte-for-byte.

## Conventions worth knowing before editing

- Zero third-party dependencies (`go.mod` has no `require`s) — the binary uses only stdlib crypto
  (`crypto/hkdf`, `crypto/ecdh`, AES-GCM, all present since Go 1.24) plus shelling out to `wg`,
  `ip`, `nft` the same way `wg-quick` does. Don't add a dependency.
- Rejections (duplicate address, colliding pubkey, off-tunnel LEAVE/PROBE, oversized frame) are
  handled uniformly and logged with both parties named — check SPEC §3.4 and §12.3 before changing
  a rejection path, since draft 1's bugs here were the serious ones (see README "Status").
- `wglan firewall` never edits nftables; it only prints a ruleset for the operator to install. Do
  not add code that calls `nft` to mutate rules directly — see SPEC §12.5.

## Development process

New features are built TDD: red, green, refactor. Write the failing test first (per the acceptance
check for that milestone in IMPLEMENTATION.md), watch it fail, make it pass with the minimum code,
then refactor with the test still green. Bug fixes follow the same shape: a failing regression test
before the fix.
