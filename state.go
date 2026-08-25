package main

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"

	"github.com/atvirokodosprendimai/wglan/envelope"
)

// Self is this node's own identity. mesh_ip carries the mask here — the mask is
// local-only state and never goes on the wire (SPEC §4.3).
type Self struct {
	Pubkey      string `json:"pubkey"`
	Hostname    string `json:"hostname"`
	MeshIP      string `json:"mesh_ip"`
	ListenPort  int    `json:"listen_port"`
	ControlPort int    `json:"control_port"`
	// NoFirewall persists --no-firewall, so `run` after a reboot does not
	// silently re-close an interface the operator deliberately opened.
	NoFirewall bool `json:"no_firewall,omitempty"`
}

// State is the whole of /var/lib/wglan/peers.json.
type State struct {
	Self  Self            `json:"self"`
	Peers []envelope.Peer `json:"peers"`
}

// Prefix is this node's mesh address and mask.
func (s Self) Prefix() (netip.Prefix, error) {
	p, err := netip.ParsePrefix(s.MeshIP)
	if err != nil {
		return p, fmt.Errorf("mesh_ip %q: %w", s.MeshIP, err)
	}
	if !p.Addr().Is4() {
		return p, fmt.Errorf("mesh_ip %q is not IPv4", s.MeshIP)
	}
	return p, nil
}

// AsPeer is how this node describes itself on the wire.
func (s Self) AsPeer(lanIP string) envelope.Peer {
	addr, _ := netip.ParsePrefix(s.MeshIP)
	return envelope.Peer{
		Pubkey:      s.Pubkey,
		Hostname:    s.Hostname,
		MeshIP:      addr.Addr().String(),
		LANEndpoint: netip.AddrPortFrom(mustAddr(lanIP), uint16(s.ListenPort)).String(),
		ControlPort: s.ControlPort,
	}
}

func mustAddr(s string) netip.Addr {
	a, _ := netip.ParseAddr(s)
	return a
}

func (st *State) byPubkey(pubkey string) int {
	return slices.IndexFunc(st.Peers, func(p envelope.Peer) bool { return p.Pubkey == pubkey })
}

// holder reports which peer currently holds a value, if any.
func (st *State) holder(match func(envelope.Peer) bool) (envelope.Peer, bool) {
	if i := slices.IndexFunc(st.Peers, match); i >= 0 {
		return st.Peers[i], true
	}
	return envelope.Peer{}, false
}

func statePath(dir string) string { return filepath.Join(dir, "peers.json") }
func keyPath(dir string) string   { return filepath.Join(dir, "private.key") }

// loadState reads peers.json. A missing file is not an error — it is a first run.
func loadState(dir string) (State, bool, error) {
	var st State
	b, err := os.ReadFile(statePath(dir))
	if os.IsNotExist(err) {
		return st, false, nil
	}
	if err != nil {
		return st, false, err
	}
	if err := json.Unmarshal(b, &st); err != nil {
		return st, false, fmt.Errorf("%s: %w", statePath(dir), err)
	}
	return st, true, nil
}

func saveState(dir string, st State) error {
	slices.SortFunc(st.Peers, func(a, b envelope.Peer) int {
		return compareIP(a.MeshIP, b.MeshIP)
	})
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(statePath(dir), append(b, '\n'), 0o600)
}

func compareIP(a, b string) int {
	x, y := mustAddr(a), mustAddr(b)
	return x.Compare(y)
}

// writeFileAtomic writes via a temp file in the same directory, fsync, rename,
// then fsyncs the directory so the rename itself is durable.
func writeFileAtomic(path string, data []byte, perm os.FileMode) (err error) {
	// Name the destination in every failure: the raw error reports the temp file,
	// and "open /etc/hosts.tmp850427619: permission denied" tells nobody anything.
	defer func() {
		if err != nil {
			err = fmt.Errorf("write %s: %w", path, err)
		}
	}()
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, filepath.Base(path)+".tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Chmod(perm); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return nil // rename already succeeded; the fsync is belt-and-braces
	}
	defer d.Close()
	return d.Sync()
}
