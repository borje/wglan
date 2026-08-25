package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"

	"github.com/atvirokodosprendimai/wglan/envelope"
)

// Runner is the single seam between wglan and the host. Everything this binary
// does to a machine goes through it, in argv-array form — never a shell string,
// so a wire field can never be reinterpreted by a shell (SPEC §12.3).
type Runner func(name string, args ...string) ([]byte, error)

func execRunner(name string, args ...string) ([]byte, error) {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, bytes.TrimSpace(out))
	}
	return out, nil
}

// Sys performs every side effect on the host. One file to grep to answer "what
// does this binary do to my machine".
type Sys struct {
	Run       Runner
	Iface     string
	HostsPath string
}

const (
	hostsBegin = "# BEGIN wglan"
	hostsEnd   = "# END wglan"
	keepalive  = "25"
)

// GenKey writes a fresh WireGuard keypair, returning the public key. WireGuard
// keys are X25519, which crypto/ecdh provides — no exec, no stdin plumbing.
func GenKey(path string) (string, error) {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	priv := base64.StdEncoding.EncodeToString(k.Bytes())
	if err := writeFileAtomic(path, []byte(priv+"\n"), 0o600); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(k.PublicKey().Bytes()), nil
}

// PubkeyFromFile re-derives the public key from a stored private key.
func PubkeyFromFile(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
	if err != nil {
		return "", fmt.Errorf("%s: not base64: %w", path, err)
	}
	k, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return "", fmt.Errorf("%s: %w", path, err)
	}
	return base64.StdEncoding.EncodeToString(k.PublicKey().Bytes()), nil
}

// EnsureLink brings the interface up idempotently, and is silent about every step
// whose state already matches.
func (s *Sys) EnsureLink(privPath, meshCIDR string, listenPort int) error {
	if _, err := s.Run("ip", "link", "show", "dev", s.Iface); err != nil {
		if _, err := s.Run("ip", "link", "add", "dev", s.Iface, "type", "wireguard"); err != nil {
			return err
		}
		log.Printf("created interface %s", s.Iface)
	}
	if _, err := s.Run("wg", "set", s.Iface, "listen-port", strconv.Itoa(listenPort), "private-key", privPath); err != nil {
		return err
	}
	have, err := s.addrs()
	if err != nil {
		return err
	}
	// Renumbering: drop any address that is not the configured one, then add it.
	for _, a := range have {
		if a != meshCIDR {
			if _, err := s.Run("ip", "addr", "del", a, "dev", s.Iface); err != nil {
				return err
			}
			log.Printf("removed stale address %s from %s", a, s.Iface)
		}
	}
	if !slices.Contains(have, meshCIDR) {
		if _, err := s.Run("ip", "addr", "add", meshCIDR, "dev", s.Iface); err != nil {
			return err
		}
		log.Printf("assigned %s to %s", meshCIDR, s.Iface)
	}
	_, err = s.Run("ip", "link", "set", "up", "dev", s.Iface)
	return err
}

// addrs lists the IPv4 addresses currently on the interface, as CIDR strings.
func (s *Sys) addrs() ([]string, error) {
	out, err := s.Run("ip", "-o", "-4", "addr", "show", "dev", s.Iface)
	if err != nil {
		return nil, err
	}
	var got []string
	for line := range strings.SplitSeq(string(out), "\n") {
		f := strings.Fields(line)
		if i := slices.Index(f, "inet"); i >= 0 && i+1 < len(f) {
			got = append(got, f[i+1])
		}
	}
	return got, nil
}

// SetPeer adds or updates one peer. One invocation, no full-config rewrite.
func (s *Sys) SetPeer(p envelope.Peer) error {
	_, err := s.Run("wg", "set", s.Iface,
		"peer", p.Pubkey,
		"endpoint", p.LANEndpoint,
		"allowed-ips", p.MeshIP+"/32",
		"persistent-keepalive", keepalive)
	return err
}

func (s *Sys) RemovePeer(pubkey string) error {
	_, err := s.Run("wg", "set", s.Iface, "peer", pubkey, "remove")
	return err
}

// Show returns the output of `wg show <if> <what>`.
func (s *Sys) Show(what string) (string, error) {
	out, err := s.Run("wg", "show", s.Iface, what)
	return string(out), err
}

// WriteHosts rewrites only the region between the markers. Everything outside
// them survives byte-for-byte.
func (s *Sys) WriteHosts(entries []envelope.Peer) error {
	old, err := os.ReadFile(s.HostsPath)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	perm := os.FileMode(0o644)
	if fi, err := os.Stat(s.HostsPath); err == nil {
		perm = fi.Mode().Perm()
	}
	next := hostsBlock(string(old), entries)
	if next == string(old) {
		return nil
	}
	return writeFileAtomic(s.HostsPath, []byte(next), perm)
}

// hostsBlock is pure so it can be tested against a hostile /etc/hosts.
func hostsBlock(old string, entries []envelope.Peer) string {
	sorted := slices.Clone(entries)
	slices.SortFunc(sorted, func(a, b envelope.Peer) int { return compareIP(a.MeshIP, b.MeshIP) })

	var b strings.Builder
	b.WriteString(hostsBegin + "\n")
	for _, p := range sorted {
		fmt.Fprintf(&b, "%s %s.mesh\n", p.MeshIP, p.Hostname)
	}
	b.WriteString(hostsEnd + "\n")
	block := b.String()

	lines := strings.Split(old, "\n")
	begin := slices.Index(lines, hostsBegin)
	if begin < 0 {
		// No markers: append, keeping whatever was there untouched.
		if old != "" && !strings.HasSuffix(old, "\n") {
			old += "\n"
		}
		return old + block
	}
	// First END *after* BEGIN closes the block; a duplicated or stray END is
	// content and stays where it is.
	end := slices.Index(lines[begin:], hostsEnd)
	if end < 0 {
		// BEGIN with no END: treat the marker line alone as the block.
		end = 0
	}
	end += begin
	rest := strings.Join(lines[end+1:], "\n")
	return strings.Join(lines[:begin], "\n") + prefixNL(begin) + block + rest
}

func prefixNL(begin int) string {
	if begin == 0 {
		return ""
	}
	return "\n"
}
