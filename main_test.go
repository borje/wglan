package main

import (
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/atvirokodosprendimai/wglan/envelope"
)

// ---------------------------------------------------------------- fakes

// fakeSys records argv arrays. Assertions are on the recorded slices, never on a
// joined string — if a test compared a rendered command line, the injection
// guarantee in SPEC §12.3 would be untested.
type fakeSys struct {
	mu    sync.Mutex
	calls [][]string
	out   map[string]string // argv-prefix -> stdout
	fail  map[string]bool   // argv-prefix -> error
}

func newFake() *fakeSys {
	return &fakeSys{out: map[string]string{}, fail: map[string]bool{}}
}

func (f *fakeSys) runner(name string, args ...string) ([]byte, error) {
	argv := append([]string{name}, args...)
	f.mu.Lock()
	f.calls = append(f.calls, argv)
	f.mu.Unlock()
	key := strings.Join(argv, " ")
	f.mu.Lock()
	defer f.mu.Unlock()
	for k := range f.fail {
		if strings.HasPrefix(key, k) {
			return nil, fmt.Errorf("fake: %s failed", k)
		}
	}
	for k, v := range f.out {
		if strings.HasPrefix(key, k) {
			return []byte(v), nil
		}
	}
	return nil, nil
}

func (f *fakeSys) argv() [][]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.calls)
}

func (f *fakeSys) find(prefix ...string) [][]string {
	var got [][]string
	for _, c := range f.argv() {
		if len(c) >= len(prefix) && slices.Equal(c[:len(prefix)], prefix) {
			got = append(got, c)
		}
	}
	return got
}

// testNode builds a node whose mesh address and "LAN" address are both
// 127.0.0.<n>, so the tunnel-binding checks in SPEC §6.1 can be exercised over
// real loopback TCP.
func testNode(t *testing.T, key envelope.Key, n int) (*Node, *fakeSys) {
	t.Helper()
	dir := t.TempDir()
	pub, err := GenKey(keyPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	f := newFake()
	ip := fmt.Sprintf("127.0.0.%d", n)
	node := &Node{
		dir: dir,
		st: State{Self: Self{
			Pubkey:      pub,
			Hostname:    fmt.Sprintf("node%d", n),
			MeshIP:      ip + "/8",
			ListenPort:  51820 + n,
			ControlPort: 0, // filled in by listen()
		}},
		lanIP: ip,
		key:   key,
		ver:   envelope.NewVerifier(key),
		sys:   &Sys{Run: f.runner, Iface: "wglan0", HostsPath: filepath.Join(dir, "hosts")},
	}
	pfx, err := node.st.Self.Prefix()
	if err != nil {
		t.Fatal(err)
	}
	node.subnet = pfx.Masked()
	return node, f
}

// listen starts the control listener on the node's own mesh address, so accepted
// connections look like they arrived through the tunnel.
func listen(t *testing.T, n *Node) net.Listener {
	t.Helper()
	pfx, _ := n.st.Self.Prefix()
	ln, err := net.Listen("tcp", pfx.Addr().String()+":0")
	if err != nil {
		t.Fatal(err)
	}
	n.st.Self.ControlPort = ln.Addr().(*net.TCPAddr).Port
	go n.Serve(ln)
	t.Cleanup(func() { ln.Close() })
	return ln
}

func mustKey(t *testing.T) envelope.Key {
	t.Helper()
	s, err := envelope.NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	k, err := envelope.DeriveKey(s)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// ---------------------------------------------------------------- hosts block

func TestHostsBlock(t *testing.T) {
	t.Parallel()
	entries := []envelope.Peer{
		{Hostname: "node2", MeshIP: "10.90.0.2"},
		{Hostname: "node1", MeshIP: "10.90.0.1"},
	}
	block := "# BEGIN wglan\n10.90.0.1 node1.mesh\n10.90.0.2 node2.mesh\n# END wglan\n"

	cases := []struct {
		name, old, want string
	}{
		{"empty file", "", block},
		{"no markers", "127.0.0.1 localhost\n", "127.0.0.1 localhost\n" + block},
		{"no trailing newline", "127.0.0.1 localhost", "127.0.0.1 localhost\n" + block},
		{
			"markers with content",
			"127.0.0.1 localhost\n# BEGIN wglan\n10.90.0.9 old.mesh\n# END wglan\n::1 ip6-localhost\n",
			"127.0.0.1 localhost\n" + block + "::1 ip6-localhost\n",
		},
		{
			"entries above and below",
			"a\nb\n# BEGIN wglan\nstale\n# END wglan\nc\nd\n",
			"a\nb\n" + block + "c\nd\n",
		},
		{
			"duplicated END marker",
			"# BEGIN wglan\nstale\n# END wglan\n# END wglan\nkeep me\n",
			block + "# END wglan\nkeep me\n",
		},
		{
			"stray END before BEGIN",
			"# END wglan\nkeep\n# BEGIN wglan\nstale\n# END wglan\n",
			"# END wglan\nkeep\n" + block,
		},
		{
			"BEGIN with no END",
			"keep\n# BEGIN wglan\n",
			"keep\n" + block,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := hostsBlock(tc.old, entries)
			if got != tc.want {
				t.Errorf("got:\n%q\nwant:\n%q", got, tc.want)
			}
		})
	}
}

func TestHostsBlockPreservesEverythingOutside(t *testing.T) {
	t.Parallel()
	old := "127.0.0.1\tlocalhost localhost.localdomain\n\n# a comment\n192.168.1.5 nas\n"
	got := hostsBlock(old, []envelope.Peer{{Hostname: "n1", MeshIP: "10.90.0.1"}})
	if !strings.HasPrefix(got, old) {
		t.Fatalf("original content did not survive byte-for-byte:\n%q", got)
	}
	// Rewriting again with the same entries must be a no-op.
	if again := hostsBlock(got, []envelope.Peer{{Hostname: "n1", MeshIP: "10.90.0.1"}}); again != got {
		t.Fatalf("not idempotent:\n%q\n%q", got, again)
	}
}

func TestWriteHostsAtomicAndIdempotent(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "hosts")
	if err := os.WriteFile(path, []byte("127.0.0.1 localhost\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	s := &Sys{Run: newFake().runner, Iface: "wglan0", HostsPath: path}
	peers := []envelope.Peer{{Hostname: "node1", MeshIP: "10.90.0.1"}}
	if err := s.WriteHosts(peers); err != nil {
		t.Fatal(err)
	}
	before, _ := os.Stat(path)
	time.Sleep(10 * time.Millisecond)
	if err := s.WriteHosts(peers); err != nil {
		t.Fatal(err)
	}
	after, _ := os.Stat(path)
	if !before.ModTime().Equal(after.ModTime()) {
		t.Error("second identical write touched the file")
	}
	if got := after.Mode().Perm(); got != 0o644 {
		t.Errorf("mode %v, want 0644", got)
	}
	// No .tmp litter left behind.
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		if strings.Contains(e.Name(), ".tmp") {
			t.Errorf("temp file left behind: %s", e.Name())
		}
	}
}

// ---------------------------------------------------------------- argv

func TestEnsureLinkArgv(t *testing.T) {
	t.Parallel()
	f := newFake()
	f.fail["ip link show"] = true // interface missing
	s := &Sys{Run: f.runner, Iface: "wglan0", HostsPath: "/dev/null"}
	if err := s.EnsureLink("/var/lib/wglan/private.key", "10.90.0.3/24", 51820); err != nil {
		t.Fatal(err)
	}
	want := [][]string{
		{"ip", "link", "add", "dev", "wglan0", "type", "wireguard"},
		{"wg", "set", "wglan0", "listen-port", "51820", "private-key", "/var/lib/wglan/private.key"},
		{"ip", "addr", "add", "10.90.0.3/24", "dev", "wglan0"},
		{"ip", "link", "set", "up", "dev", "wglan0"},
	}
	for _, w := range want {
		if got := f.find(w...); len(got) != 1 {
			t.Errorf("expected exactly one %v, got %d", w, len(got))
		}
	}
}

func TestEnsureLinkRenumbers(t *testing.T) {
	t.Parallel()
	f := newFake()
	f.out["ip -o -4 addr show"] = "5: wglan0    inet 10.90.0.3/24 scope global wglan0\\       valid_lft forever\n"
	s := &Sys{Run: f.runner, Iface: "wglan0", HostsPath: "/dev/null"}
	if err := s.EnsureLink("k", "10.90.0.9/24", 51820); err != nil {
		t.Fatal(err)
	}
	if got := f.find("ip", "addr", "del", "10.90.0.3/24", "dev", "wglan0"); len(got) != 1 {
		t.Error("stale address was not removed on renumber")
	}
	if got := f.find("ip", "addr", "add", "10.90.0.9/24", "dev", "wglan0"); len(got) != 1 {
		t.Error("new address was not added")
	}
	if got := f.find("ip", "link", "add"); len(got) != 0 {
		t.Error("recreated an interface that already existed")
	}
}

func TestEnsureLinkSilentWhenCorrect(t *testing.T) {
	t.Parallel()
	f := newFake()
	f.out["ip -o -4 addr show"] = "5: wglan0    inet 10.90.0.3/24 scope global wglan0\n"
	s := &Sys{Run: f.runner, Iface: "wglan0", HostsPath: "/dev/null"}
	if err := s.EnsureLink("k", "10.90.0.3/24", 51820); err != nil {
		t.Fatal(err)
	}
	for _, c := range f.argv() {
		if slices.Contains(c, "add") || slices.Contains(c, "del") {
			t.Errorf("mutated a correct interface: %v", c)
		}
	}
}

// The skeleton must default-deny the mesh interface without taking the host
// offline, and it must be impossible to leave half-built.
func TestSetPeerArgv(t *testing.T) {
	t.Parallel()
	f := newFake()
	s := &Sys{Run: f.runner, Iface: "wglan0", HostsPath: "/dev/null"}
	p := envelope.Peer{
		Pubkey:      "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dc=",
		Hostname:    "node2",
		MeshIP:      "10.90.0.2",
		LANEndpoint: "192.168.1.22:51820",
		ControlPort: 51821,
	}
	if err := s.SetPeer(p); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"wg", "set", "wglan0", "peer", p.Pubkey,
		"endpoint", "192.168.1.22:51820",
		"allowed-ips", "10.90.0.2/32",
		"persistent-keepalive", "25",
	}
	got := f.argv()
	if len(got) != 1 || !slices.Equal(got[0], want) {
		t.Fatalf("argv\n got %q\nwant %q", got, want)
	}
	if err := s.RemovePeer(p.Pubkey); err != nil {
		t.Fatal(err)
	}
	if got := f.find("wg", "set", "wglan0", "peer", p.Pubkey, "remove"); len(got) != 1 {
		t.Fatal("remove argv wrong")
	}
}

// `wglan leave` deletes the interface after its fan-out, and never touches
// nftables — wglan doesn't manage it any more (SPEC §6, §12).
func TestRemoveLinkArgv(t *testing.T) {
	t.Parallel()
	f := newFake()
	s := &Sys{Run: f.runner, Iface: "wglan0", HostsPath: "/dev/null"}
	if err := s.RemoveLink(); err != nil {
		t.Fatal(err)
	}
	got := f.argv()
	if len(got) != 1 || !slices.Equal(got[0], []string{"ip", "link", "delete", "dev", "wglan0"}) {
		t.Fatalf("argv\n got %q\nwant [[ip link delete dev wglan0]]", got)
	}
	for _, c := range got {
		if c[0] == "nft" {
			t.Errorf("leave touched nftables: %v", c)
		}
	}
}

// ---------------------------------------------------------------- merge rules

func TestMergeRules(t *testing.T) {
	t.Parallel()
	key := mustKey(t)
	n, _ := testNode(t, key, 1)
	n.subnet = netip.MustParsePrefix("10.90.0.0/24")
	n.st.Self.MeshIP = "10.90.0.1/24"
	n.st.Self.Hostname = "node1"

	victim := envelope.Peer{Pubkey: pubN(t, 2), Hostname: "node2", MeshIP: "10.90.0.2", LANEndpoint: "192.168.1.2:51820", ControlPort: 51821}
	attacker := envelope.Peer{Pubkey: pubN(t, 3), Hostname: "node3", MeshIP: "10.90.0.3", LANEndpoint: "192.168.1.3:51820", ControlPort: 51821}

	if _, _, _ = n.apply([]envelope.Peer{victim, attacker}); len(n.st.Peers) != 2 {
		t.Fatalf("setup: %d peers", len(n.st.Peers))
	}

	// The one that matters: an already-known pubkey may not move another peer's
	// /32 onto itself. SPEC §3.4 as written exempted known pubkeys from the
	// duplicate checks, which made this a traffic-interception primitive.
	steal := attacker
	steal.MeshIP = victim.MeshIP
	if a, c, _ := n.apply([]envelope.Peer{steal}); a+c != 0 {
		t.Error("a known pubkey stole another peer's mesh address")
	}
	if i := n.st.byPubkey(victim.Pubkey); n.st.Peers[i].MeshIP != "10.90.0.2" {
		t.Error("victim's address changed")
	}
	if i := n.st.byPubkey(attacker.Pubkey); n.st.Peers[i].MeshIP != "10.90.0.3" {
		t.Error("attacker's address changed")
	}

	// Hostname theft is rejected the same way.
	steal = attacker
	steal.Hostname = victim.Hostname
	if a, c, _ := n.apply([]envelope.Peer{steal}); a+c != 0 {
		t.Error("a known pubkey stole another peer's hostname")
	}

	// But renumbering into a free address still works in place — one variable
	// change plus a restart, with no new pubkey.
	renum := attacker
	renum.MeshIP = "10.90.0.30"
	if a, c, _ := n.apply([]envelope.Peer{renum}); a != 0 || c != 1 {
		t.Errorf("renumber: added=%d changed=%d, want 0/1", a, c)
	}
	if i := n.st.byPubkey(attacker.Pubkey); n.st.Peers[i].MeshIP != "10.90.0.30" {
		t.Error("renumber did not apply")
	}
	if got := len(n.st.Peers); got != 2 {
		t.Errorf("renumber created a second entry: %d peers", got)
	}

	// Out-of-subnet, our own address, and our own hostname are all rejected.
	for _, bad := range []envelope.Peer{
		{Pubkey: pubN(t, 4), Hostname: "node4", MeshIP: "10.91.0.4", LANEndpoint: "192.168.1.4:51820", ControlPort: 51821},
		{Pubkey: pubN(t, 5), Hostname: "node5", MeshIP: "10.90.0.1", LANEndpoint: "192.168.1.5:51820", ControlPort: 51821},
		{Pubkey: pubN(t, 6), Hostname: "node1", MeshIP: "10.90.0.6", LANEndpoint: "192.168.1.6:51820", ControlPort: 51821},
	} {
		if a, c, _ := n.apply([]envelope.Peer{bad}); a+c != 0 {
			t.Errorf("accepted %s / %s", bad.MeshIP, bad.Hostname)
		}
	}
	if got := len(n.st.Peers); got != 2 {
		t.Fatalf("%d peers after rejections, want 2", got)
	}

	// Re-applying the identical peer is not an error and not a change: that is
	// what makes `sync` the join path with "already known is not an error".
	if a, c, _ := n.apply([]envelope.Peer{victim}); a+c != 0 {
		t.Errorf("re-apply reported added=%d changed=%d", a, c)
	}
}

// ---------------------------------------------------------------- protocol

func TestThreeNodeConvergence(t *testing.T) {
	key := mustKey(t)
	n1, _ := testNode(t, key, 1)
	n2, _ := testNode(t, key, 2)
	n3, f3 := testNode(t, key, 3)
	_ = f3
	listen(t, n1)
	listen(t, n2)
	listen(t, n3)

	boot1 := n1.self().ControlAddr()
	if err := n2.joinTo(boot1); err != nil {
		t.Fatal(err)
	}
	n2.fanout(boot1)

	// Everyone joins through node1 — the case that either works or silently
	// half-works, so all three are checked, not just the joiner.
	if err := n3.joinTo(boot1); err != nil {
		t.Fatal(err)
	}
	n3.fanout(boot1)

	for _, tc := range []struct {
		name string
		n    *Node
		want []string
	}{
		{"node1", n1, []string{"node2", "node3"}},
		{"node2", n2, []string{"node1", "node3"}},
		{"node3", n3, []string{"node1", "node2"}},
	} {
		var got []string
		tc.n.mu.Lock()
		for _, p := range tc.n.st.Peers {
			got = append(got, p.Hostname)
		}
		tc.n.mu.Unlock()
		slices.Sort(got)
		if !slices.Equal(got, tc.want) {
			t.Errorf("%s knows %v, want %v", tc.name, got, tc.want)
		}
	}

	// The hosts block on node1 lists all three, self included.
	b, err := os.ReadFile(n1.sys.HostsPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"node1.mesh", "node2.mesh", "node3.mesh"} {
		if !strings.Contains(string(b), want) {
			t.Errorf("hosts block missing %s:\n%s", want, b)
		}
	}
	// And peers.json survived as valid JSON.
	if st, ok, err := loadState(n1.dir); err != nil || !ok || len(st.Peers) != 2 {
		t.Errorf("peers.json: ok=%v err=%v peers=%d", ok, err, len(st.Peers))
	}
}

// A colliding --mesh-ip is rejected on every peer and the mesh is unchanged.
func TestCollidingJoinRejectedByPeer(t *testing.T) {
	key := mustKey(t)
	n1, _ := testNode(t, key, 1)
	n2, _ := testNode(t, key, 2)
	listen(t, n1)
	listen(t, n2)
	if err := n2.joinTo(n1.self().ControlAddr()); err != nil {
		t.Fatal(err)
	}

	// node4 claims node2's address.
	n4, _ := testNode(t, key, 4)
	n4.st.Self.MeshIP = "127.0.0.2/8"
	pfx, _ := n4.st.Self.Prefix()
	n4.subnet = pfx.Masked()
	n4.lanIP = "127.0.0.4"
	listen(t, n4)

	// The JOIN is delivered and answered, but the peer entry must not move.
	_ = n4.joinTo(n1.self().ControlAddr())
	n1.mu.Lock()
	i := n1.st.byPubkey(n2.st.Self.Pubkey)
	still := i >= 0 && n1.st.Peers[i].MeshIP == "127.0.0.2"
	stolen := n1.st.byPubkey(n4.st.Self.Pubkey) >= 0
	n1.mu.Unlock()
	if !still {
		t.Error("node2's entry was overwritten by a colliding join")
	}
	if stolen {
		t.Error("the colliding joiner was added anyway")
	}
}

// SPEC §6.1: a LEAVE is honoured only inside the tunnel, from the mesh address
// owned by the pubkey it names. Written before the feature, per IMPLEMENTATION.md.
func TestLeaveBinding(t *testing.T) {
	key := mustKey(t)
	n1, f1 := testNode(t, key, 1)
	n2, _ := testNode(t, key, 2)
	n3, _ := testNode(t, key, 3)
	listen(t, n1)
	listen(t, n2)
	listen(t, n3)
	if err := n2.joinTo(n1.self().ControlAddr()); err != nil {
		t.Fatal(err)
	}
	if err := n3.joinTo(n1.self().ControlAddr()); err != nil {
		t.Fatal(err)
	}

	leave := envelope.Payload{Type: envelope.TypeLeave, Peer: envelope.Peer{Pubkey: n3.st.Self.Pubkey}}

	// node2 forges a LEAVE naming node3. It holds the secret, so the envelope
	// opens — the binding is what must stop it.
	if _, err := n2.exchange(n1.self().ControlAddr(), leave, false, true); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	n1.mu.Lock()
	present := n1.st.byPubkey(n3.st.Self.Pubkey) >= 0
	n1.mu.Unlock()
	if !present {
		t.Fatal("a member evicted another member by forging a LEAVE")
	}

	// node3's own LEAVE, from its own mesh address, is honoured.
	if _, err := n3.exchange(n1.self().ControlAddr(), leave, false, true); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool {
		n1.mu.Lock()
		defer n1.mu.Unlock()
		return n1.st.byPubkey(n3.st.Self.Pubkey) < 0
	})
	if len(f1.find("wg", "set", "wglan0", "peer", n3.st.Self.Pubkey, "remove")) == 0 {
		t.Error("peer was not removed from the interface")
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("condition never became true")
}

// A message arriving on a LAN address rather than the mesh interface is not
// in-tunnel, whatever source address it claims.
func TestLeaveOffTunnelRejected(t *testing.T) {
	key := mustKey(t)
	n1, f1 := testNode(t, key, 1)
	n2, _ := testNode(t, key, 2)
	_ = f1
	// n1 listens on 127.0.0.9 while its mesh address is 127.0.0.1: the connection
	// is accepted on an address that is not ours in the mesh, so inTunnel is false.
	ln, err := net.Listen("tcp", "127.0.0.9:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	n1.st.Self.ControlPort = ln.Addr().(*net.TCPAddr).Port
	go n1.Serve(ln)

	n2.st.Self.ControlPort = 51821
	n1.apply([]envelope.Peer{n2.self()}) //nolint
	addr := fmt.Sprintf("127.0.0.9:%d", n1.st.Self.ControlPort)
	leave := envelope.Payload{Type: envelope.TypeLeave, Peer: envelope.Peer{Pubkey: n2.st.Self.Pubkey}}
	if _, err := n2.exchange(addr, leave, false, true); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	n1.mu.Lock()
	defer n1.mu.Unlock()
	if n1.st.byPubkey(n2.st.Self.Pubkey) < 0 {
		t.Fatal("LEAVE honoured off-tunnel")
	}
}

// An off-tunnel JOIN's endpoint comes from the observed source address, not the
// claimed one.
func TestJoinEndpointFromObservedSource(t *testing.T) {
	key := mustKey(t)
	n1, _ := testNode(t, key, 1)
	ln, err := net.Listen("tcp", "127.0.0.9:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	n1.st.Self.ControlPort = ln.Addr().(*net.TCPAddr).Port
	go n1.Serve(ln)

	n2, _ := testNode(t, key, 2)
	n2.st.Self.ControlPort = 51821
	n2.lanIP = "203.0.113.7" // a lie: node2 is not there
	addr := fmt.Sprintf("127.0.0.9:%d", n1.st.Self.ControlPort)
	if err := n2.joinTo(addr); err != nil {
		t.Fatal(err)
	}
	n1.mu.Lock()
	defer n1.mu.Unlock()
	i := n1.st.byPubkey(n2.st.Self.Pubkey)
	if i < 0 {
		t.Fatal("join was not applied")
	}
	// The host is whatever the kernel used as the source of the connection; the
	// claimed 203.0.113.7 must not survive. Only the port is taken on trust.
	want := fmt.Sprintf("127.0.0.1:%d", n2.st.Self.ListenPort)
	if got := n1.st.Peers[i].LANEndpoint; got != want {
		t.Fatalf("endpoint %q, want %q — claimed value was trusted over the observed source", got, want)
	}
}

// ---------------------------------------------------------------- hardening

func TestConcurrentGarbageAndJoins(t *testing.T) {
	key := mustKey(t)
	n1, _ := testNode(t, key, 1)
	listen(t, n1)
	addr := n1.self().ControlAddr()

	// The per-IP rate limiter would reject most of these, so exercise the handler
	// directly over a pipe for the garbage half and use real conns for joins.
	var wg sync.WaitGroup
	for i := range 50 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			a, b := net.Pipe()
			go func() {
				defer a.Close()
				junk := make([]byte, 64)
				for j := range junk {
					junk[j] = byte(i + j)
				}
				a.Write(junk)
			}()
			n1.handle(b)
			b.Close()
		}(i)
	}
	for i := range 50 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			joiner := envelope.Peer{
				Pubkey:      pubN(t, i+10),
				Hostname:    fmt.Sprintf("gen%d", i),
				MeshIP:      fmt.Sprintf("127.1.0.%d", i+1),
				LANEndpoint: fmt.Sprintf("127.1.0.%d:51820", i+1),
				ControlPort: 51821,
			}
			frame, err := envelope.Seal(key, envelope.Payload{Type: envelope.TypeJoin, Peer: joiner})
			if err != nil {
				return
			}
			conn, err := net.Dial("tcp", addr)
			if err != nil {
				return
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(3 * time.Second))
			conn.Write(frame)
			envelope.ReadFrame(conn, envelope.MaxFrameReply)
		}(i)
	}
	wg.Wait()

	// Whatever got through, peers.json must be valid and internally consistent.
	st, ok, err := loadState(n1.dir)
	if err != nil || !ok {
		t.Fatalf("peers.json unreadable after the storm: ok=%v err=%v", ok, err)
	}
	seenIP := map[string]string{}
	for _, p := range st.Peers {
		if prev, dup := seenIP[p.MeshIP]; dup && prev != p.Pubkey {
			t.Errorf("two pubkeys hold %s", p.MeshIP)
		}
		seenIP[p.MeshIP] = p.Pubkey
	}
}

func TestRateLimiter(t *testing.T) {
	t.Parallel()
	l := newLimiter()
	now := time.Now()
	for i := range rateBurst {
		if !l.allow("10.0.0.1", now) {
			t.Fatalf("rejected request %d inside the burst", i)
		}
	}
	if l.allow("10.0.0.1", now) {
		t.Error("burst was not enforced")
	}
	if !l.allow("10.0.0.2", now) {
		t.Error("a different source IP was punished for the first one")
	}
	if !l.allow("10.0.0.1", now.Add(rateWindow+time.Second)) {
		t.Error("window never expires")
	}
	if len(l.hits) > 2 {
		t.Errorf("limiter map holds %d entries; eviction is not happening", len(l.hits))
	}
}

func TestOversizedInboundFrameIsDropped(t *testing.T) {
	key := mustKey(t)
	n1, _ := testNode(t, key, 1)
	listen(t, n1)
	conn, err := net.Dial("tcp", n1.self().ControlAddr())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	// 5KB of noise, length prefix included: over the 4KB inbound cap.
	junk := make([]byte, 5<<10)
	for i := range junk {
		junk[i] = byte(i)
	}
	if _, err := conn.Write(junk); err != nil {
		t.Fatal(err)
	}
	// The connection must close with no reply body.
	buf := make([]byte, 1)
	if _, err := conn.Read(buf); err == nil {
		t.Fatal("server sent a reply to an oversized frame")
	}
}

// ---------------------------------------------------------------- helpers

func pubN(t *testing.T, i int) string {
	t.Helper()
	pub, err := GenKey(filepath.Join(t.TempDir(), fmt.Sprintf("k%d", i)))
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

// knows reports whether n has a peer entry for other.
func knows(n *Node, other *Node) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.st.byPubkey(other.st.Self.Pubkey) >= 0
}

// SPEC §5.1: a node that joined earlier has a frozen peer list and never hears
// about a later joiner — nothing pushes, nothing reconciles. `sync` is named as
// the repair, so it has to greet everyone it learns about, not just the target;
// otherwise the missing edge stays missing in the direction that matters.
func TestSyncFansOutToCloseAMissingEdge(t *testing.T) {
	key := mustKey(t)
	n1, _ := testNode(t, key, 1) // the bootstrap both used
	n4, _ := testNode(t, key, 4) // joined first; its list is frozen
	n2, _ := testNode(t, key, 2) // joined later; node4 never heard of it
	listen(t, n1)
	listen(t, n2)
	listen(t, n4)

	boot := n1.self().ControlAddr()
	if err := n4.joinTo(boot); err != nil { // no fan-out: node4 greets only node1
		t.Fatal(err)
	}
	if err := n2.joinTo(boot); err != nil { // no fan-out: node2 greets only node1
		t.Fatal(err)
	}
	if knows(n4, n2) {
		t.Fatal("precondition: node4 must not know node2 yet")
	}

	if err := n2.cmdSync(boot); err != nil {
		t.Fatal(err)
	}

	if !knows(n2, n4) {
		t.Error("node2 did not learn node4 from the sync reply")
	}
	if !knows(n4, n2) {
		t.Error("node4 still does not know node2 — sync did not fan out")
	}
}

// `join` sets up and announces, then returns. It must not end in serve(): the
// control listener belongs to `run`, which is what systemd supervises, and a
// join that never returns cannot be used to repair a node whose daemon is up.
func TestJoinReturnsInsteadOfServing(t *testing.T) {
	key := mustKey(t)
	n1, _ := testNode(t, key, 1)
	n2, _ := testNode(t, key, 2)
	listen(t, n1)
	listen(t, n2) // n2's port is taken, so a serving cmdJoin blocks or collides

	done := make(chan error, 1)
	go func() {
		done <- n2.cmdJoin(opts{dir: n2.dir, bootstrap: n1.self().ControlAddr()}, true)
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("cmdJoin returned an error, want a clean return after announcing: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cmdJoin did not return — it is still serving")
	}
	if !knows(n1, n2) {
		t.Error("cmdJoin returned but never announced us to the bootstrap")
	}
}

// SPEC §7: `wglan probe` with no argument tallies every known peer, not just
// one named suspect. Written before the feature, per IMPLEMENTATION.md.
func TestProbeAllTargetsEveryPeer(t *testing.T) {
	key := mustKey(t)
	n1, _ := testNode(t, key, 1)
	n2, _ := testNode(t, key, 2)
	n3, _ := testNode(t, key, 3)
	listen(t, n1)
	listen(t, n2)
	listen(t, n3)

	boot1 := n1.self().ControlAddr()
	if err := n2.joinTo(boot1); err != nil {
		t.Fatal(err)
	}
	n2.fanout(boot1)
	if err := n3.joinTo(boot1); err != nil {
		t.Fatal(err)
	}
	n3.fanout(boot1)

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = w
	n1.probeAll()
	w.Close()
	os.Stdout = old
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}

	for _, want := range []string{"node2", "node3"} {
		if !strings.Contains(string(out), want) {
			t.Errorf("probeAll output missing a tally for %s:\n%s", want, out)
		}
	}
	if n := strings.Count(string(out), "reachable from"); n != 2 {
		t.Errorf("want 2 tally lines (one per peer), got %d:\n%s", n, out)
	}
}
