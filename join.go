package main

import (
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"slices"
	"sync"
	"time"

	"github.com/atvirokodosprendimai/wglan/envelope"
)

const (
	dialTimeout = 3 * time.Second
	ioDeadline  = 3 * time.Second
	maxInflight = 8
	rateBurst   = 5
	rateWindow  = 10 * time.Second
)

// Node is one wglan instance. The mutex covers the full
// validate -> apply -> persist -> reply sequence for a single message, so two
// handlers can never interleave a map update with a file rewrite (SPEC §14).
type Node struct {
	mu     sync.Mutex
	dir    string
	st     State
	subnet netip.Prefix
	lanIP  string
	key    envelope.Key
	ver    *envelope.Verifier
	sys    *Sys
}

func (n *Node) self() envelope.Peer { return n.st.Self.AsPeer(n.lanIP) }

func short(pubkey string) string {
	if len(pubkey) > 8 {
		return pubkey[:8]
	}
	return pubkey
}

// ---------------------------------------------------------------- apply

type outcome int

const (
	unchanged outcome = iota
	added
	changed
)

// mergeLocked applies one peer to the map. Callers hold n.mu.
func (n *Node) mergeLocked(p envelope.Peer) (outcome, error) {
	if p.Pubkey == n.st.Self.Pubkey {
		return unchanged, nil
	}
	addr, err := netip.ParseAddr(p.MeshIP)
	if err != nil {
		return unchanged, fmt.Errorf("malformed field: mesh_ip %q from %s", p.MeshIP, short(p.Pubkey))
	}
	if !n.subnet.Contains(addr) {
		return unchanged, fmt.Errorf("address outside our subnet: %s claims %s, we are %s",
			short(p.Pubkey), p.MeshIP, n.subnet)
	}
	if selfAddr, _ := netip.ParsePrefix(n.st.Self.MeshIP); selfAddr.Addr().String() == p.MeshIP {
		return unchanged, fmt.Errorf("address held by us: %s claims %s", short(p.Pubkey), p.MeshIP)
	}
	if n.st.Self.Hostname == p.Hostname {
		return unchanged, fmt.Errorf("hostname held by us: %s claims %q", short(p.Pubkey), p.Hostname)
	}

	// A known pubkey updates in place, so renumbering is one variable change plus
	// a restart (SPEC §3.4) — but the collision check against every *other*
	// pubkey still runs. Without that, any member could move an existing peer's
	// /32 onto its own key and intercept that peer's traffic.
	if h, ok := n.st.holder(func(q envelope.Peer) bool {
		return q.MeshIP == p.MeshIP && q.Pubkey != p.Pubkey
	}); ok {
		return unchanged, fmt.Errorf("address held by another pubkey: %s claims %s, held by %s",
			short(p.Pubkey), p.MeshIP, short(h.Pubkey))
	}
	if h, ok := n.st.holder(func(q envelope.Peer) bool {
		return q.Hostname == p.Hostname && q.Pubkey != p.Pubkey
	}); ok {
		return unchanged, fmt.Errorf("hostname held by another pubkey: %s claims %q, held by %s",
			short(p.Pubkey), p.Hostname, short(h.Pubkey))
	}

	// WireGuard first, state second — in both branches. The reverse order left a
	// peer in the map when `wg set` failed, and that phantom was then advertised
	// in the reply, persisted, and reloaded on every restart: exactly the
	// state/WireGuard divergence SPEC §14 exists to rule out.
	i := n.st.byPubkey(p.Pubkey)
	if i < 0 {
		if err := n.sys.SetPeer(p); err != nil {
			return unchanged, err
		}
		n.st.Peers = append(n.st.Peers, p)
		log.Printf("peer %s added: %s %s.mesh via %s", short(p.Pubkey), p.MeshIP, p.Hostname, p.LANEndpoint)
		return added, nil
	}
	old := n.st.Peers[i]
	if old == p {
		return unchanged, nil
	}
	if err := n.sys.SetPeer(p); err != nil {
		return unchanged, err
	}
	// A change is logged differently from a first-sight add, naming old and new.
	// This is the whole mitigation for a member forging another member's address
	// (SPEC §13, last row): it cannot prevent the forgery, but silent persistent
	// poisoning becomes a visible event.
	log.Printf("peer %s CHANGED: %s %s.mesh via %s -> %s %s.mesh via %s",
		short(p.Pubkey), old.MeshIP, old.Hostname, old.LANEndpoint, p.MeshIP, p.Hostname, p.LANEndpoint)
	n.st.Peers[i] = p
	return changed, nil
}

func (n *Node) persistLocked() error {
	if err := saveState(n.dir, n.st); err != nil {
		return err
	}
	return n.sys.WriteHosts(append(slices.Clone(n.st.Peers), n.self()))
}

// apply merges a set of peers, persists once, and returns the resulting peer
// list. Merge, persist and snapshot happen in one critical section, so the reply
// a handler sends can never describe a state that never existed (SPEC §14).
// Sealing and writing that reply happen outside the lock: they are network I/O
// under a deadline, and the snapshot is already immutable by then.
//
// Rejections are logged, never silently swallowed, and never returned to the
// sender (SPEC §9.2, §12.2).
func (n *Node) apply(peers []envelope.Peer) (int, int, []envelope.Peer) {
	n.mu.Lock()
	defer n.mu.Unlock()
	var nAdded, nChanged int
	for _, p := range peers {
		switch res, err := n.mergeLocked(p); {
		case err != nil:
			log.Printf("rejected peer %s: %v", short(p.Pubkey), err)
		case res == added:
			nAdded++
		case res == changed:
			nChanged++
		}
	}
	if nAdded+nChanged > 0 {
		if err := n.persistLocked(); err != nil {
			log.Printf("persist failed: %v", err)
		}
	}
	return nAdded, nChanged, slices.Clone(n.st.Peers)
}

func (n *Node) forget(pubkey string) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	i := n.st.byPubkey(pubkey)
	if i < 0 {
		return fmt.Errorf("no peer with pubkey %s", pubkey)
	}
	p := n.st.Peers[i]
	n.st.Peers = slices.Delete(n.st.Peers, i, i+1)
	if err := n.sys.RemovePeer(pubkey); err != nil {
		return err
	}
	if err := n.persistLocked(); err != nil {
		return err
	}
	log.Printf("peer %s removed: %s %s.mesh", short(pubkey), p.MeshIP, p.Hostname)
	return nil
}

// ---------------------------------------------------------------- client

// exchange dials addr, sends one sealed message, and optionally reads one reply.
//
// tunnel binds the source address to our own mesh address. LEAVE and PROBE are
// only honoured when they arrive from the sender's mesh IP (SPEC §6.1), and on a
// multi-homed host the kernel would otherwise be free to pick another one.
func (n *Node) exchange(addr string, p envelope.Payload, wantReply, tunnel bool) (envelope.Payload, error) {
	var zero envelope.Payload
	frame, err := envelope.Seal(n.key, p)
	if err != nil {
		return zero, err
	}
	d := net.Dialer{Timeout: dialTimeout}
	if tunnel {
		pfx, err := netip.ParsePrefix(n.st.Self.MeshIP)
		if err != nil {
			return zero, err
		}
		d.LocalAddr = &net.TCPAddr{IP: pfx.Addr().AsSlice()}
	}
	conn, err := d.Dial("tcp", addr)
	if err != nil {
		return zero, err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(ioDeadline)); err != nil {
		return zero, err
	}
	if _, err := conn.Write(frame); err != nil {
		return zero, err
	}
	if !wantReply {
		return zero, nil
	}
	body, err := envelope.ReadFrame(conn, envelope.MaxFrameReply)
	if err != nil {
		return zero, err
	}
	o, err := n.ver.Open(body, time.Now())
	if err != nil {
		return zero, err
	}
	return o.P(), nil
}

// joinTo sends a JOIN to one target and applies the reply. This is the whole of
// `sync` too: the join path with "already known is not an error".
//
// It runs outside the tunnel. SPEC §16 hoped `sync` could inherit WireGuard's
// authentication by travelling inside it, but the case `sync` exists to repair is
// a *missing* edge — there is no tunnel to that peer yet, by definition.
func (n *Node) joinTo(addr string) error {
	reply, err := n.exchange(addr, envelope.Payload{Type: envelope.TypeJoin, Peer: n.self()}, true, false)
	if err != nil {
		return err
	}
	if reply.Type != envelope.TypeJoinReply {
		return fmt.Errorf("%s answered %s, want JOIN_REPLY", addr, reply.Type)
	}
	a, c, _ := n.apply(append(slices.Clone(reply.Peers), reply.Peer))
	log.Printf("join -> %s: accepted, %d added, %d changed", addr, a, c)
	return nil
}

// cmdSync is the repair path of SPEC §7 and the answer to the missing edge in
// §5.1: one JOIN to a reachable member, then the same fan-out a join does. The
// fan-out is the half that matters — a peer that joined before us has a frozen
// list and learns about us from nobody else.
func (n *Node) cmdSync(addr string) error {
	if err := n.joinTo(addr); err != nil {
		return err
	}
	n.fanout(addr)
	return nil
}

// fanout greets every peer we now know about, so each one adds us independently.
func (n *Node) fanout(skip string) {
	n.mu.Lock()
	targets := slices.Clone(n.st.Peers)
	n.mu.Unlock()
	for _, p := range targets {
		addr := p.ControlAddr()
		if addr == "" || addr == skip {
			continue
		}
		if err := n.joinTo(addr); err != nil {
			log.Printf("join -> %s (%s): %v", addr, short(p.Pubkey), err)
		}
	}
}

// announceLeave fans a LEAVE out to every peer, inside the tunnel — the only
// place a receiver can bind the message to its sender (SPEC §6.1).
func (n *Node) announceLeave() {
	n.mu.Lock()
	targets := slices.Clone(n.st.Peers)
	me := n.st.Self.Pubkey
	n.mu.Unlock()
	msg := envelope.Payload{Type: envelope.TypeLeave, Peer: envelope.Peer{Pubkey: me}}
	for _, p := range targets {
		if _, err := n.exchange(p.MeshControlAddr(), msg, false, true); err != nil {
			log.Printf("leave -> %s (%s): %v", p.MeshControlAddr(), short(p.Pubkey), err)
			continue
		}
		log.Printf("leave -> %s (%s): sent", p.MeshControlAddr(), short(p.Pubkey))
	}
}

// cmdLeave is the whole of `wglan leave`: announce, tear the interface down,
// clear our hosts block, and remove peers.json. The removal is what makes the
// leave symmetric on this side: peers.json is the systemd unit's
// ConditionPathExists, so leaving it behind resurrected the departed node —
// interface, peer list, hosts block and all — on the next boot, half-rejoined
// to a mesh that had just forgotten it. The secret and keypair stay, so a
// rejoin is one command.
//
// Every step runs, and the errors are reported together at the end. Returning
// on the first one stopped short of the removal — and the announce has already
// gone out by then, so every peer has forgotten this node while it still has
// the state that brings it back. A host that rebooted without `wglan run`
// enabled is exactly that case: the announce works, `ip link delete` does not,
// and each retry of `wglan leave` failed identically with no recovery short of
// rm by hand.
func (n *Node) cmdLeave() error {
	n.announceLeave()
	errs := []error{n.sys.RemoveLink(), n.sys.WriteHosts(nil)}
	if err := os.Remove(statePath(n.dir)); err != nil && !os.IsNotExist(err) {
		errs = append(errs, err)
	}
	if err := errors.Join(errs...); err != nil {
		return fmt.Errorf("left the mesh, but the teardown was incomplete: %w", err)
	}
	log.Printf("left the mesh: %s removed; stop any running `wglan run` yourself", statePath(n.dir))
	return nil
}

// ---------------------------------------------------------------- server

type limiter struct {
	mu   sync.Mutex
	hits map[string][]time.Time
}

func newLimiter() *limiter { return &limiter{hits: map[string][]time.Time{}} }

// allow rate-limits per source IP. Checked before the decrypt is attempted, so a
// stranger cannot make the node burn AES cycles on garbage for free.
func (l *limiter) allow(ip string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for k, ts := range l.hits {
		kept := slices.DeleteFunc(slices.Clone(ts), func(t time.Time) bool { return now.Sub(t) > rateWindow })
		if len(kept) == 0 {
			delete(l.hits, k)
		} else {
			l.hits[k] = kept
		}
	}
	if len(l.hits[ip]) >= rateBurst {
		return false
	}
	l.hits[ip] = append(l.hits[ip], now)
	return true
}

// Serve accepts control connections until the listener is closed.
func (n *Node) Serve(ln net.Listener) error {
	sem := make(chan struct{}, maxInflight)
	lim := newLimiter()
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		ip := hostOf(conn.RemoteAddr())
		if !lim.allow(ip, time.Now()) {
			log.Printf("rejected %s: rate limit", ip)
			conn.Close()
			continue
		}
		select {
		case sem <- struct{}{}:
		default:
			log.Printf("rejected %s: %d connections already in flight", ip, maxInflight)
			conn.Close()
			continue
		}
		go func() {
			defer func() { conn.Close(); <-sem }()
			n.handle(conn)
		}()
	}
}

func hostOf(a net.Addr) string {
	host, _, err := net.SplitHostPort(a.String())
	if err != nil {
		return a.String()
	}
	return host
}

// handle processes one message. Every rejection closes the connection with no
// reply: uniform on the wire, discriminating in the log.
func (n *Node) handle(conn net.Conn) {
	from := hostOf(conn.RemoteAddr())
	if err := conn.SetDeadline(time.Now().Add(ioDeadline)); err != nil {
		return
	}
	body, err := envelope.ReadFrame(conn, envelope.MaxFrameIn)
	if err != nil {
		log.Printf("rejected %s: %v", from, err)
		return
	}
	o, err := n.ver.Open(body, time.Now())
	if err != nil {
		log.Printf("rejected %s: %v", from, err)
		return
	}
	p := o.P()

	switch p.Type {
	case envelope.TypeJoin:
		n.handleJoin(conn, p, from)
	case envelope.TypeLeave:
		n.handleLeave(conn, p, from)
	case envelope.TypeProbe:
		n.handleProbe(conn, p, from)
	default:
		log.Printf("rejected %s (%s): %s arrives only as a reply", from, short(p.Pubkey), p.Type)
	}
}

func (n *Node) handleJoin(conn net.Conn, p envelope.Payload, from string) {
	sender := p.Peer
	// Bind the endpoint to observed reality where there is anything to observe:
	// off-tunnel, the source address of the connection is the endpoint, and only
	// the claimed port is kept. Second-hand entries in peers[] stay claimed.
	if !n.inTunnel(conn) {
		// The observed source must be IPv4 — the only address family anything in
		// this mesh accepts. serve() listens IPv4-only, but this handler must not
		// depend on that: a JOIN observed at a v6 source would store a "[v6]:port"
		// endpoint, and every receiver of a later JOIN_REPLY carrying it rejects
		// the whole message ("one bad entry rejects the message").
		src, err := netip.ParseAddr(from)
		if err != nil || !src.Unmap().Is4() {
			log.Printf("rejected JOIN from %s (%s): source is not an IPv4 LAN address", from, short(sender.Pubkey))
			return
		}
		from = src.Unmap().String()
		if _, port, err := net.SplitHostPort(sender.LANEndpoint); err == nil {
			if fixed := net.JoinHostPort(from, port); fixed != sender.LANEndpoint {
				log.Printf("peer %s claimed endpoint %s, observed %s — using observed",
					short(sender.Pubkey), sender.LANEndpoint, fixed)
				sender.LANEndpoint = fixed
			}
		}
	}
	log.Printf("join <- %s (%s): %s %s.mesh", from, short(sender.Pubkey), sender.MeshIP, sender.Hostname)
	_, _, known := n.apply(append(slices.Clone(p.Peers), sender))

	reply := envelope.Payload{Type: envelope.TypeJoinReply, Peer: n.self(), Peers: known}
	if len(reply.Peers) > envelope.MaxPeers {
		reply.Peers = reply.Peers[:envelope.MaxPeers]
		log.Printf("join <- %s: peer list truncated to %d", from, envelope.MaxPeers)
	}
	frame, err := envelope.Seal(n.key, reply)
	if err != nil {
		log.Printf("join <- %s: cannot seal reply: %v", from, err)
		return
	}
	if _, err := conn.Write(frame); err != nil {
		log.Printf("join <- %s: reply failed: %v", from, err)
	}
}

// inTunnel reports whether the connection arrived on the mesh interface, by
// checking that it was accepted on *our own mesh address* rather than a LAN one.
// This is what stops a LAN-side spoofed source address from passing the check
// below it.
func (n *Node) inTunnel(conn net.Conn) bool {
	self, err := netip.ParsePrefix(n.st.Self.MeshIP)
	if err != nil {
		return false
	}
	local, err := netip.ParseAddr(hostOf(conn.LocalAddr()))
	return err == nil && local == self.Addr()
}

// handleLeave honours a LEAVE only from inside the tunnel, from the mesh address
// owned by the pubkey it names. A sealed message proves the sender holds the
// secret — not that it is the pubkey named inside (SPEC §6.1).
func (n *Node) handleLeave(conn net.Conn, p envelope.Payload, from string) {
	if !n.inTunnel(conn) {
		log.Printf("rejected LEAVE from %s (%s): did not arrive on %s", from, short(p.Pubkey), n.sys.Iface)
		return
	}
	n.mu.Lock()
	i := n.st.byPubkey(p.Pubkey)
	var owner string
	if i >= 0 {
		owner = n.st.Peers[i].MeshIP
	}
	n.mu.Unlock()
	if i < 0 {
		log.Printf("rejected LEAVE from %s: unknown pubkey %s", from, short(p.Pubkey))
		return
	}
	if owner != from {
		log.Printf("rejected LEAVE from %s naming %s: that pubkey owns %s", from, short(p.Pubkey), owner)
		return
	}
	log.Printf("leave <- %s (%s): departing", from, short(p.Pubkey))
	if err := n.forget(p.Pubkey); err != nil {
		log.Printf("leave <- %s: %v", from, err)
	}
}

func (n *Node) handleProbe(conn net.Conn, p envelope.Payload, from string) {
	if !n.inTunnel(conn) {
		log.Printf("rejected PROBE from %s (%s): did not arrive on %s", from, short(p.Pubkey), n.sys.Iface)
		return
	}
	n.mu.Lock()
	i := n.st.byPubkey(p.Pubkey)
	ok := i >= 0 && n.st.Peers[i].MeshIP == from
	known := n.st.byPubkey(p.Target) >= 0
	n.mu.Unlock()
	if !ok {
		log.Printf("rejected PROBE from %s (%s): sender is not that pubkey's mesh address", from, short(p.Pubkey))
		return
	}
	age := int64(-1)
	if known {
		v, err := n.handshakeAges()
		if err != nil {
			log.Printf("probe <- %s: cannot read handshakes: %v", from, err)
		} else if a, seen := v[p.Target]; seen {
			age = a
		}
	}
	log.Printf("probe <- %s (%s): target %s known=%v age=%ds", from, short(p.Pubkey), short(p.Target), known, age)
	reply := envelope.Payload{
		Type:         envelope.TypeProbeReply,
		Peer:         envelope.Peer{Pubkey: n.st.Self.Pubkey},
		Known:        known,
		HandshakeAge: age,
	}
	frame, err := envelope.Seal(n.key, reply)
	if err != nil {
		log.Printf("probe <- %s: cannot seal reply: %v", from, err)
		return
	}
	if _, err := conn.Write(frame); err != nil {
		log.Printf("probe <- %s: reply failed: %v", from, err)
	}
}

// probeAll probes every known peer in turn, printing one tally line each.
func (n *Node) probeAll() {
	n.mu.Lock()
	targets := slices.Clone(n.st.Peers)
	n.mu.Unlock()
	for _, p := range targets {
		n.probeMesh(p)
	}
}

// probeMesh asks every peer for its view of one target and prints the tally.
func (n *Node) probeMesh(target envelope.Peer) {
	n.mu.Lock()
	targets := slices.Clone(n.st.Peers)
	me := n.st.Self.Pubkey
	n.mu.Unlock()

	reachable, asked := 0, 0
	// Our own vote needs `wg show`, which needs CAP_NET_ADMIN. Unprivileged, we
	// still poll every peer — but say so, rather than quietly shrinking the
	// denominator.
	if ages, err := n.handshakeAges(); err != nil {
		log.Printf("probe: cannot read our own handshakes, reporting peers only: %v", err)
	} else {
		asked++
		if a, ok := ages[target.Pubkey]; ok && a >= 0 && a < staleAfterSeconds {
			reachable++
		}
	}
	msg := envelope.Payload{Type: envelope.TypeProbe, Peer: envelope.Peer{Pubkey: me}, Target: target.Pubkey}
	for _, p := range targets {
		if p.Pubkey == target.Pubkey {
			continue
		}
		reply, err := n.exchange(p.MeshControlAddr(), msg, true, true)
		if err != nil {
			log.Printf("probe -> %s (%s): %v", p.MeshControlAddr(), short(p.Pubkey), err)
			continue
		}
		if reply.Type != envelope.TypeProbeReply {
			log.Printf("probe -> %s: answered %s", p.MeshControlAddr(), reply.Type)
			continue
		}
		asked++
		if reply.Known && reply.HandshakeAge >= 0 && reply.HandshakeAge < staleAfterSeconds {
			reachable++
		}
	}
	if asked == 0 {
		fmt.Printf("%s: no peer could be asked\n", target.Hostname)
		return
	}
	fmt.Printf("%s (%s): reachable from %d/%d peers\n", target.Hostname, target.MeshIP, reachable, asked)
	if reachable == 0 {
		fmt.Printf("  every peer agrees it is gone — `wglan forget %s` on each node\n", target.Pubkey)
	} else if reachable < asked {
		fmt.Printf("  partial: %d peers still reach it. Your link is the suspect, not %s\n", reachable, target.Hostname)
	}
}

// resolve finds a peer by pubkey or hostname.
func (n *Node) resolve(s string) (envelope.Peer, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if p, ok := n.st.holder(func(q envelope.Peer) bool { return q.Pubkey == s || q.Hostname == s }); ok {
		return p, nil
	}
	return envelope.Peer{}, errors.New("no such peer: " + s)
}
