package envelope

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

const goodPub = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dc=" // 44 chars, 32 bytes

func testKey(t *testing.T) Key {
	t.Helper()
	s, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	k, err := DeriveKey(s)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func join() Payload {
	return Payload{
		Type: TypeJoin,
		Peer: Peer{
			Pubkey:      goodPub,
			Hostname:    "node3",
			MeshIP:      "10.90.0.3",
			LANEndpoint: "192.168.1.23:51820",
			ControlPort: 51821,
		},
	}
}

func body(t *testing.T, frame []byte) []byte {
	t.Helper()
	got, err := ReadFrame(bytes.NewReader(frame), MaxFrameReply)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func TestSecretRoundTrip(t *testing.T) {
	t.Parallel()
	s, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(s, secretPrefix) {
		t.Fatalf("secret %q lacks prefix", s)
	}
	a, err := DeriveKey(s)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := DeriveKey(s)
	if a != b {
		t.Fatal("derivation is not deterministic")
	}
	// Domain separation: the derived key must not be the secret itself.
	raw, _ := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(s, secretPrefix))
	if bytes.Equal(a[:], raw) {
		t.Fatal("key equals raw secret; HKDF not applied")
	}
}

func TestBadSecrets(t *testing.T) {
	t.Parallel()
	for _, s := range []string{
		"", "hunter2", "wglan://v2/aaaa", secretPrefix + "!!!!",
		secretPrefix + base64.RawURLEncoding.EncodeToString(make([]byte, 31)),
		secretPrefix + base64.RawURLEncoding.EncodeToString(make([]byte, 33)),
	} {
		if _, err := DeriveKey(s); err == nil {
			t.Errorf("DeriveKey(%q) accepted", s)
		}
	}
}

func TestRoundTrip(t *testing.T) {
	t.Parallel()
	k := testKey(t)
	frame, err := Seal(k, join())
	if err != nil {
		t.Fatal(err)
	}
	o, err := NewVerifier(k).Open(body(t, frame), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if got := o.P(); got.Hostname != "node3" || got.MeshIP != "10.90.0.3" || got.ControlPort != 51821 {
		t.Fatalf("payload came back wrong: %+v", got)
	}
	if o.P().Protocol != Protocol {
		t.Fatalf("protocol %q", o.P().Protocol)
	}
}

func TestOpenFailsUniformly(t *testing.T) {
	t.Parallel()
	k := testKey(t)
	frame, err := Seal(k, join())
	if err != nil {
		t.Fatal(err)
	}
	orig := body(t, frame)

	flip := func(field string) []byte {
		var e outer
		if err := json.Unmarshal(orig, &e); err != nil {
			t.Fatal(err)
		}
		switch field {
		case "ciphertext":
			e.Ciphertext[3] ^= 0x01
		case "nonce":
			e.Nonce[3] ^= 0x01
		case "tag":
			e.Ciphertext[len(e.Ciphertext)-1] ^= 0x01
		}
		b, _ := json.Marshal(e)
		return b
	}

	cases := map[string][]byte{
		"flipped ciphertext byte": flip("ciphertext"),
		"flipped nonce byte":      flip("nonce"),
		"flipped tag byte":        flip("tag"),
		"truncated":               orig[:len(orig)-10],
		"not json":                []byte("{"),
		"short nonce":             []byte(`{"nonce":"AAAA","ciphertext":"AAAA"}`),
	}
	for name, b := range cases {
		if _, err := NewVerifier(k).Open(b, time.Now()); !errors.Is(err, ErrOpen) {
			t.Errorf("%s: got %v, want ErrOpen", name, err)
		}
	}

	// Wrong key is the same uniform outcome.
	other := testKey(t)
	if _, err := NewVerifier(other).Open(orig, time.Now()); !errors.Is(err, ErrOpen) {
		t.Errorf("wrong key: got %v, want ErrOpen", err)
	}
}

func TestFreshnessBothDirections(t *testing.T) {
	t.Parallel()
	k := testKey(t)
	now := time.Now()
	for _, tc := range []struct {
		skew time.Duration
		ok   bool
	}{
		{0, true},
		{-599 * time.Second, true},
		{599 * time.Second, true},
		{-601 * time.Second, false},
		{601 * time.Second, false}, // the direction people skip
		{-72 * time.Hour, false},
		{72 * time.Hour, false},
	} {
		p := join()
		p.Timestamp = now.Add(tc.skew).Unix()
		frame, err := Seal(k, p)
		if err != nil {
			t.Fatal(err)
		}
		_, err = NewVerifier(k).Open(body(t, frame), now)
		if tc.ok && err != nil {
			t.Errorf("skew %v: %v", tc.skew, err)
		}
		if !tc.ok && !errors.Is(err, ErrStale) {
			t.Errorf("skew %v: got %v, want ErrStale", tc.skew, err)
		}
	}
}

func TestProtocolMismatchFailsClosed(t *testing.T) {
	t.Parallel()
	k := testKey(t)
	// Seal forces the current protocol, so build the ciphertext by hand.
	p := join()
	p.Protocol = "wglan-v2"
	p.Timestamp = time.Now().Unix()
	plain, _ := json.Marshal(p)
	g, _ := aead(k)
	nonce := make([]byte, nonceLen)
	env, _ := json.Marshal(outer{Nonce: nonce, Ciphertext: g.Seal(nil, nonce, plain, nil)})
	if _, err := NewVerifier(k).Open(env, time.Now()); !errors.Is(err, ErrProtocol) {
		t.Fatalf("got %v, want ErrProtocol", err)
	}
}

func TestReplayRejected(t *testing.T) {
	t.Parallel()
	k := testKey(t)
	v := NewVerifier(k)
	frame, err := Seal(k, join())
	if err != nil {
		t.Fatal(err)
	}
	b := body(t, frame)
	if _, err := v.Open(b, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Open(b, time.Now()); !errors.Is(err, ErrReplay) {
		t.Fatalf("second open: got %v, want ErrReplay", err)
	}
	// The set is bounded by the freshness window; once a message could no longer
	// be accepted anyway, its nonce is evicted rather than kept forever.
	v.fresh([]byte("999999999999"), time.Now().Add(2*Freshness).Unix())
	if len(v.seen) != 1 {
		t.Fatalf("seen-set holds %d entries after eviction, want 1", len(v.seen))
	}
}

func TestOversizedFrameRejectedWithoutBody(t *testing.T) {
	t.Parallel()
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], MaxFrameIn+1)
	// Only the 4-byte header is available: if ReadFrame tried to read the body it
	// would block or error on EOF instead of rejecting on the length alone.
	if _, err := ReadFrame(bytes.NewReader(hdr[:]), MaxFrameIn); !errors.Is(err, ErrFrame) {
		t.Fatalf("got %v, want ErrFrame", err)
	}
	binary.BigEndian.PutUint32(hdr[:], 0)
	if _, err := ReadFrame(bytes.NewReader(hdr[:]), MaxFrameIn); !errors.Is(err, ErrFrame) {
		t.Fatalf("zero length: got %v, want ErrFrame", err)
	}
}

// A full peer list must fit the reply cap — SPEC's 4KB frame could not hold 20.
func TestFullPeerListFits(t *testing.T) {
	t.Parallel()
	k := testKey(t)
	p := join()
	p.Type = TypeJoinReply
	for i := range MaxPeers {
		p.Peers = append(p.Peers, Peer{
			Pubkey:      goodPub,
			Hostname:    fmt.Sprintf("node-with-a-longish-name-%d", i),
			MeshIP:      fmt.Sprintf("10.90.%d.%d", i/256, i%256),
			LANEndpoint: fmt.Sprintf("192.168.%d.%d:51820", i/256, i%256),
			ControlPort: 51821,
		})
	}
	frame, err := Seal(k, p)
	if err != nil {
		t.Fatal(err)
	}
	if len(frame) > MaxFrameReply {
		t.Fatalf("frame is %d bytes, cap %d", len(frame), MaxFrameReply)
	}
	if len(frame) <= MaxFrameIn {
		t.Fatalf("frame is %d bytes — test is not exercising the reply cap", len(frame))
	}
	o, err := NewVerifier(k).Open(body(t, frame), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(o.P().Peers) != MaxPeers {
		t.Fatalf("got %d peers", len(o.P().Peers))
	}
}

// A pubkey must be the canonical encoding of its 32 bytes. Lenient base64
// ignores the unused trailing bits, so distinct 44-char strings decode to the
// same WireGuard key — and everything downstream compares pubkeys as strings
// (dedup, the collision checks, the CHANGED log), while `wg set` canonicalises
// to bytes. A non-canonical variant would slip a known key past every
// string-keyed check as a "new" peer.
func TestPubkeyMustBeCanonicalBase64(t *testing.T) {
	t.Parallel()
	// goodPub ends "…8Dc=": 'c' (011100) has its two low bits unused, so 'd'
	// (011101) decodes to the identical 32 bytes under lenient decoding.
	variant := strings.TrimSuffix(goodPub, "c=") + "d="
	a, _ := base64.StdEncoding.DecodeString(goodPub)
	b, err := base64.StdEncoding.DecodeString(variant)
	if err != nil || !bytes.Equal(a, b) {
		t.Fatal("premise broken: the variant no longer decodes to the same key")
	}
	if err := ValidPubkey(goodPub); err != nil {
		t.Errorf("canonical pubkey rejected: %v", err)
	}
	if err := ValidPubkey(variant); err == nil {
		t.Error("non-canonical encoding of the same key accepted")
	}
}

func TestFieldValidation(t *testing.T) {
	t.Parallel()
	mut := func(f func(*Payload)) Payload {
		p := join()
		f(&p)
		return p
	}
	cases := []struct {
		name string
		p    Payload
		ok   bool
	}{
		{"valid join", join(), true},
		{"valid leave", Payload{Type: TypeLeave, Peer: Peer{Pubkey: goodPub}}, true},
		{"valid probe", Payload{Type: TypeProbe, Peer: Peer{Pubkey: goodPub}, Target: goodPub}, true},
		{"valid probe reply", Payload{Type: TypeProbeReply, Peer: Peer{Pubkey: goodPub}, HandshakeAge: -1}, true},

		{"unknown type", mut(func(p *Payload) { p.Type = "EVICT" }), false},
		{"empty type", mut(func(p *Payload) { p.Type = "" }), false},

		{"pubkey 43 chars", mut(func(p *Payload) { p.Pubkey = goodPub[:43] }), false},
		{"pubkey not base64", mut(func(p *Payload) { p.Pubkey = strings.Repeat("!", 44) }), false},
		{"pubkey empty", mut(func(p *Payload) { p.Pubkey = "" }), false},

		{"hostname with newline", mut(func(p *Payload) { p.Hostname = "node3\n10.90.0.9 evil" }), false},
		{"hostname with space", mut(func(p *Payload) { p.Hostname = "node 3" }), false},
		{"hostname uppercase", mut(func(p *Payload) { p.Hostname = "Node3" }), false},
		{"hostname with slash", mut(func(p *Payload) { p.Hostname = "../../etc/passwd" }), false},
		{"hostname empty", mut(func(p *Payload) { p.Hostname = "" }), false},
		{"hostname 64 chars", mut(func(p *Payload) { p.Hostname = strings.Repeat("a", 64) }), false},
		{"hostname 63 chars", mut(func(p *Payload) { p.Hostname = strings.Repeat("a", 63) }), true},

		{"two mesh ips", mut(func(p *Payload) { p.MeshIP = "10.90.0.1 10.90.0.2" }), false},
		{"mesh ip with mask", mut(func(p *Payload) { p.MeshIP = "10.90.0.3/24" }), false},
		{"mesh ip v6", mut(func(p *Payload) { p.MeshIP = "fd00::1" }), false},
		{"mesh ip unspecified", mut(func(p *Payload) { p.MeshIP = "0.0.0.0" }), false},
		{"mesh ip multicast", mut(func(p *Payload) { p.MeshIP = "224.0.0.1" }), false},
		{"mesh ip link-local", mut(func(p *Payload) { p.MeshIP = "169.254.7.7" }), false},
		{"mesh ip broadcast", mut(func(p *Payload) { p.MeshIP = "255.255.255.255" }), false},

		// A second-hand peers[] endpoint goes straight to `wg set ... endpoint`
		// with nothing to observe it against, so addresses that can never be a
		// LAN endpoint are refused here. Loopback stays valid: the subnet check
		// covers mesh_ip, and the root-free test strategy runs whole meshes on
		// 127.0.0.0/8 (see CLAUDE.md); a loopback *endpoint* remains inside the
		// accepted second-hand-poisoning residual of SPEC §13.
		{"endpoint link-local host", mut(func(p *Payload) { p.LANEndpoint = "169.254.7.7:51820" }), false},
		{"endpoint broadcast host", mut(func(p *Payload) { p.LANEndpoint = "255.255.255.255:51820" }), false},

		{"endpoint no port", mut(func(p *Payload) { p.LANEndpoint = "192.168.1.23" }), false},
		{"endpoint hostname", mut(func(p *Payload) { p.LANEndpoint = "node3.example:51820" }), false},
		{"endpoint port 0", mut(func(p *Payload) { p.LANEndpoint = "192.168.1.23:0" }), false},
		{"endpoint port 65536", mut(func(p *Payload) { p.LANEndpoint = "192.168.1.23:65536" }), false},
		{"endpoint shell metachars", mut(func(p *Payload) { p.LANEndpoint = "192.168.1.23:51820; rm -rf /" }), false},

		{"control port 0", mut(func(p *Payload) { p.ControlPort = 0 }), false},
		{"control port 65536", mut(func(p *Payload) { p.ControlPort = 65536 }), false},
		{"control port 65535", mut(func(p *Payload) { p.ControlPort = 65535 }), true},

		{"peers on a JOIN", mut(func(p *Payload) { p.Peers = []Peer{join().Peer} }), false},
		{"target on a JOIN", mut(func(p *Payload) { p.Target = goodPub }), false},
		{"probe without target", Payload{Type: TypeProbe, Peer: Peer{Pubkey: goodPub}}, false},
		{"leave with extra fields", Payload{Type: TypeLeave, Peer: Peer{Pubkey: goodPub, MeshIP: "10.90.0.3"}}, false},

		{"257 peers", mut(func(p *Payload) {
			p.Type = TypeJoinReply
			for range MaxPeers + 1 {
				p.Peers = append(p.Peers, join().Peer)
			}
		}), false},
		{"hostile peers entry", mut(func(p *Payload) {
			p.Type = TypeJoinReply
			bad := join().Peer
			bad.Hostname = "n\n10.90.0.9 evil"
			p.Peers = []Peer{join().Peer, bad}
		}), false},
		{"peers entry bad endpoint", mut(func(p *Payload) {
			p.Type = TypeJoinReply
			bad := join().Peer
			bad.LANEndpoint = "not-an-endpoint"
			p.Peers = []Peer{bad}
		}), false},
	}

	k := testKey(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			// Seal validates, so a hostile payload never reaches the wire...
			_, sealErr := Seal(k, tc.p)
			if tc.ok != (sealErr == nil) {
				t.Fatalf("Seal: ok=%v err=%v", tc.ok, sealErr)
			}
			if !tc.ok {
				// ...and a hostile payload sealed by a malicious peer is still
				// rejected on open, which is the path that actually matters.
				p := tc.p
				p.Protocol = Protocol
				p.Timestamp = time.Now().Unix()
				plain, _ := json.Marshal(p)
				g, _ := aead(k)
				nonce := make([]byte, nonceLen)
				env, _ := json.Marshal(outer{Nonce: nonce, Ciphertext: g.Seal(nil, nonce, plain, nil)})
				if _, err := NewVerifier(k).Open(env, time.Now()); err == nil {
					t.Fatal("Open accepted a hostile payload")
				}
			}
		})
	}
}

func TestControlAddr(t *testing.T) {
	t.Parallel()
	p := join().Peer
	if got := p.ControlAddr(); got != "192.168.1.23:51821" {
		t.Fatalf("ControlAddr = %q", got)
	}
	if got := p.MeshControlAddr(); got != "10.90.0.3:51821" {
		t.Fatalf("MeshControlAddr = %q", got)
	}
}
