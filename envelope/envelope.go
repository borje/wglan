// Package envelope is the whole security boundary of wglan.
//
// Every control message is one AES-256-GCM envelope whose key is derived from the
// shared secret, so a successful open *is* the proof of membership (SPEC §12.1).
//
// Nothing outside this package can produce a validated message: [Open] is the only
// way to obtain an [Opened], and its single field is unexported. That is SPEC §4.5
// ("validation is welded to the open") enforced by the compiler rather than by
// discipline.
package envelope

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// Protocol is checked before any other field, so version skew fails closed.
	Protocol = "wglan-v1"

	// MaxFrameIn bounds anything an unauthenticated party can make us buffer.
	// A JOIN, LEAVE, PROBE or PROBE_REPLY never approaches it (SPEC §4.2).
	MaxFrameIn = 4 << 10
	// MaxFrameReply bounds a reply read on a connection we dialled ourselves.
	// 256 peers is ~50KB of payload, ~66KB base64 — this leaves headroom without
	// unbounding anything, and no stranger can ever send this much.
	MaxFrameReply = 256 << 10

	// MaxPeers caps the peer list in a JOIN_REPLY.
	MaxPeers = 256

	// Freshness is the ±window a timestamp must fall inside. Both directions:
	// rejecting only "too old" leaves a future-dated capture replayable once its
	// time arrives (SPEC §4.4).
	Freshness = 600 * time.Second

	secretPrefix = "wglan://v1/"
	hkdfInfo     = "wglan-envelope-v1"
	nonceLen     = 12
)

// Message types.
type Type string

const (
	TypeJoin       Type = "JOIN"
	TypeJoinReply  Type = "JOIN_REPLY"
	TypeLeave      Type = "LEAVE"
	TypeProbe      Type = "PROBE"
	TypeProbeReply Type = "PROBE_REPLY"
)

// Rejection reasons. The wire response stays uniform (SPEC §12.2); these exist so
// the *local* log can discriminate, or a field failure is unfalsifiable (SPEC §9.2).
var (
	ErrFrame    = errors.New("frame")
	ErrOpen     = errors.New("envelope failed to open")
	ErrProtocol = errors.New("unsupported protocol")
	ErrStale    = errors.New("timestamp outside window")
	ErrReplay   = errors.New("nonce already seen")
	ErrField    = errors.New("malformed field")
)

// Key is the envelope key, derived once at startup.
type Key [32]byte

// NewSecret returns a fresh secret in wglan://v1/<base64url> form.
func NewSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return secretPrefix + base64.RawURLEncoding.EncodeToString(b), nil
}

// DeriveKey parses a secret and derives the envelope key from its raw 32 bytes.
// The info string is domain-separated, so a secret reused across tools never
// produces cross-openable messages (SPEC §4.1).
func DeriveKey(secret string) (Key, error) {
	var k Key
	raw, ok := strings.CutPrefix(strings.TrimSpace(secret), secretPrefix)
	if !ok {
		return k, fmt.Errorf("secret must start with %s", secretPrefix)
	}
	b, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return k, fmt.Errorf("secret is not base64url: %w", err)
	}
	if len(b) != 32 {
		return k, fmt.Errorf("secret decodes to %d bytes, want 32", len(b))
	}
	out, err := hkdf.Key(sha256.New, b, nil, hkdfInfo, 32)
	if err != nil {
		return k, err
	}
	copy(k[:], out)
	return k, nil
}

// Peer is one member's public details. It is both the sender's own description
// (embedded in Payload) and one entry of a JOIN_REPLY list.
type Peer struct {
	Pubkey      string `json:"pubkey,omitempty"`
	Hostname    string `json:"hostname,omitempty"`
	MeshIP      string `json:"mesh_ip,omitempty"`
	LANEndpoint string `json:"lan_endpoint,omitempty"`
	ControlPort int    `json:"control_port,omitempty"`
}

// ControlAddr is where this peer's control listener lives, on the LAN.
func (p Peer) ControlAddr() string {
	host, _, err := net.SplitHostPort(p.LANEndpoint)
	if err != nil {
		return ""
	}
	return net.JoinHostPort(host, strconv.Itoa(p.ControlPort))
}

// MeshControlAddr is where this peer's control listener lives inside the tunnel.
func (p Peer) MeshControlAddr() string {
	return net.JoinHostPort(p.MeshIP, strconv.Itoa(p.ControlPort))
}

// Payload is the sealed message. Every field is inside the ciphertext, so all of
// it is confidential *and* tamper-evident (SPEC §4.3).
type Payload struct {
	Protocol  string `json:"protocol"`
	Type      Type   `json:"type"`
	Timestamp int64  `json:"timestamp"`

	Peer // sender's own pubkey/hostname/mesh_ip/lan_endpoint/control_port

	Peers        []Peer `json:"peers,omitempty"`         // JOIN_REPLY only
	Target       string `json:"target,omitempty"`        // PROBE only
	Known        bool   `json:"known,omitempty"`         // PROBE_REPLY only
	HandshakeAge int64  `json:"handshake_age,omitempty"` // PROBE_REPLY only, -1 = never
}

// Opened is a Payload that has survived the open and every validation rule.
// Its field is unexported, so no code outside this package can fabricate one.
type Opened struct{ p Payload }

// P returns the validated payload.
func (o Opened) P() Payload { return o.p }

type outer struct {
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
}

func aead(k Key) (cipher.AEAD, error) {
	blk, err := aes.NewCipher(k[:])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(blk)
}

// Seal validates p, seals it, and returns a complete length-prefixed frame ready
// to write to a connection.
func Seal(k Key, p Payload) ([]byte, error) {
	p.Protocol = Protocol
	if p.Timestamp == 0 {
		p.Timestamp = time.Now().Unix()
	}
	if err := validate(&p); err != nil {
		return nil, err
	}
	body, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	g, err := aead(k)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, nonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	env, err := json.Marshal(outer{Nonce: nonce, Ciphertext: g.Seal(nil, nonce, body, nil)})
	if err != nil {
		return nil, err
	}
	if len(env) > MaxFrameReply {
		return nil, fmt.Errorf("%w: sealed message is %d bytes, cap %d", ErrFrame, len(env), MaxFrameReply)
	}
	out := make([]byte, 4+len(env))
	binary.BigEndian.PutUint32(out, uint32(len(env)))
	copy(out[4:], env)
	return out, nil
}

// ReadFrame reads one length-prefixed message body. The length is checked before
// the body is allocated, so an oversized frame costs four bytes.
func ReadFrame(r io.Reader, max int) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrFrame, err)
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 || n > uint32(max) {
		return nil, fmt.Errorf("%w: length %d, cap %d", ErrFrame, n, max)
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrFrame, err)
	}
	return body, nil
}

// Verifier holds the envelope key and the replay seen-set.
//
// SPEC §4.4 defers the seen-set until JOIN gains a non-idempotent side effect;
// §3.4's update-in-place is exactly that (a JOIN is last-writer-wins, so replaying
// a pre-renumber capture reverts the change), so the set is here from the start.
type Verifier struct {
	key  Key
	mu   sync.Mutex
	seen map[[nonceLen]byte]int64
}

func NewVerifier(k Key) *Verifier {
	return &Verifier{key: k, seen: make(map[[nonceLen]byte]int64)}
}

// fresh records a nonce and reports whether it is new. Eviction is lazy, on
// insert: everything older than the freshness window is already rejected, so the
// set stays bounded without a timer.
//
// ponytail: O(n) sweep per insert, n = messages accepted in the last 10 minutes.
// Churn is ~1 join/day; revisit only if that stops being true.
func (v *Verifier) fresh(nonce []byte, now int64) bool {
	var key [nonceLen]byte
	copy(key[:], nonce)
	v.mu.Lock()
	defer v.mu.Unlock()
	for n, t := range v.seen {
		if now-t > int64(Freshness.Seconds()) {
			delete(v.seen, n)
		}
	}
	if _, dup := v.seen[key]; dup {
		return false
	}
	v.seen[key] = now
	return true
}

// Open opens one frame body and returns a fully validated message. Every
// rejection below is uniform on the wire; the error is for the local log only.
func (v *Verifier) Open(body []byte, now time.Time) (Opened, error) {
	var zero Opened

	var e outer
	if err := json.Unmarshal(body, &e); err != nil || len(e.Nonce) != nonceLen {
		return zero, ErrOpen
	}
	g, err := aead(v.key)
	if err != nil {
		return zero, err
	}
	plain, err := g.Open(nil, e.Nonce, e.Ciphertext, nil)
	if err != nil {
		return zero, ErrOpen
	}

	// Protocol first, before any other field is read.
	var probe struct {
		Protocol string `json:"protocol"`
	}
	if err := json.Unmarshal(plain, &probe); err != nil {
		return zero, fmt.Errorf("%w: payload is not JSON", ErrField)
	}
	if probe.Protocol != Protocol {
		return zero, fmt.Errorf("%w: %q", ErrProtocol, probe.Protocol)
	}

	var p Payload
	if err := json.Unmarshal(plain, &p); err != nil {
		return zero, fmt.Errorf("%w: %w", ErrField, err)
	}
	if d := now.Unix() - p.Timestamp; d > int64(Freshness.Seconds()) || -d > int64(Freshness.Seconds()) {
		return zero, fmt.Errorf("%w: %ds skew", ErrStale, d)
	}
	if !v.fresh(e.Nonce, now.Unix()) {
		return zero, ErrReplay
	}
	if err := validate(&p); err != nil {
		return zero, err
	}
	return Opened{p: p}, nil
}

var hostnameRE = regexp.MustCompile(`^[a-z0-9-]{1,63}$`)

func validate(p *Payload) error {
	switch p.Type {
	case TypeJoin, TypeJoinReply:
		if err := validPeer(p.Peer); err != nil {
			return err
		}
	case TypeLeave:
		// Carries protocol, type, timestamp, pubkey only. Anything else is a
		// field no receiver reads, so refuse it rather than carry it around.
		if err := validPubkey(p.Pubkey); err != nil {
			return err
		}
		if p.Hostname != "" || p.MeshIP != "" || p.LANEndpoint != "" || p.ControlPort != 0 {
			return fmt.Errorf("%w: LEAVE carries pubkey only", ErrField)
		}
	case TypeProbe:
		if err := validPubkey(p.Pubkey); err != nil {
			return err
		}
		if err := validPubkey(p.Target); err != nil {
			return fmt.Errorf("%w (target)", err)
		}
	case TypeProbeReply:
		if err := validPubkey(p.Pubkey); err != nil {
			return err
		}
	default:
		return fmt.Errorf("%w: unknown type %q", ErrField, p.Type)
	}

	if p.Type != TypeJoinReply && len(p.Peers) != 0 {
		return fmt.Errorf("%w: peers is JOIN_REPLY only", ErrField)
	}
	if len(p.Peers) > MaxPeers {
		return fmt.Errorf("%w: %d peers, cap %d", ErrField, len(p.Peers), MaxPeers)
	}
	// peers[] is what reaches `wg set` and /etc/hosts, so it gets the identical
	// treatment. One bad entry rejects the whole message.
	for i, q := range p.Peers {
		if err := validPeer(q); err != nil {
			return fmt.Errorf("%w (peers[%d])", err, i)
		}
	}
	if p.Type != TypeProbe && p.Target != "" {
		return fmt.Errorf("%w: target is PROBE only", ErrField)
	}
	return nil
}

func validPeer(p Peer) error {
	if err := validPubkey(p.Pubkey); err != nil {
		return err
	}
	if !hostnameRE.MatchString(p.Hostname) {
		return fmt.Errorf("%w: hostname %q", ErrField, p.Hostname)
	}
	if err := validMeshIP(p.MeshIP); err != nil {
		return err
	}
	if err := validEndpoint(p.LANEndpoint); err != nil {
		return err
	}
	return validPort(p.ControlPort, "control_port")
}

func validPubkey(s string) error {
	b, err := base64.StdEncoding.DecodeString(s)
	if len(s) != 44 || err != nil || len(b) != 32 {
		return fmt.Errorf("%w: pubkey %q", ErrField, s)
	}
	return nil
}

func validMeshIP(s string) error {
	a, err := netip.ParseAddr(s)
	if err != nil || !a.Is4() || !a.IsValid() || a.IsUnspecified() || a.IsMulticast() {
		return fmt.Errorf("%w: mesh_ip %q", ErrField, s)
	}
	return nil
}

func validEndpoint(s string) error {
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return fmt.Errorf("%w: lan_endpoint %q", ErrField, s)
	}
	if err := validMeshIP(host); err != nil {
		return fmt.Errorf("%w: lan_endpoint %q", ErrField, s)
	}
	n, err := strconv.Atoi(port)
	if err != nil {
		return fmt.Errorf("%w: lan_endpoint %q", ErrField, s)
	}
	return validPort(n, "lan_endpoint port")
}

func validPort(n int, what string) error {
	if n < 1 || n > 65535 {
		return fmt.Errorf("%w: %s %d", ErrField, what, n)
	}
	return nil
}

// ValidHostname reports whether s is usable as a mesh hostname. Exported so the
// CLI can fail on a bad --hostname before anything reaches the wire.
func ValidHostname(s string) error {
	if !hostnameRE.MatchString(s) {
		return fmt.Errorf("%w: hostname %q must match [a-z0-9-]{1,63}", ErrField, s)
	}
	return nil
}

// ValidPubkey reports whether s is a WireGuard public key.
func ValidPubkey(s string) error { return validPubkey(s) }
