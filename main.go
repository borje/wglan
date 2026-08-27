// Command wglan builds a full-mesh WireGuard network across a LAN: one shared
// secret plus one bootstrap address. See SPEC.md.
package main

import (
	_ "embed"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"syscall"

	"github.com/atvirokodosprendimai/wglan/envelope"
)

// firewallConf is nftables/wglan.conf, verbatim. Embedded rather than built from
// a format string so there is exactly one copy of the ruleset: reviewable as
// nftables, checkable with `nft -c -f`, and impossible to drift from what the
// binary prints.
//
//go:embed nftables/wglan.conf
var firewallConf string

// The two lines `wglan firewall` rewrites. Named constants so a change to the
// conf file that breaks the substitution fails loudly instead of silently
// printing a ruleset that ignores the flags.
const defaultIface = "wglan0"

const (
	defaultIfaceLine = `define WGLAN_IFACE = "wglan0"`
	defaultPortLine  = `define WGLAN_CONTROL_PORT = 51821`
)

func renderFirewall(iface string, controlPort int) (string, error) {
	out := firewallConf
	for old, want := range map[string]string{
		defaultIfaceLine: fmt.Sprintf("define WGLAN_IFACE = %q", iface),
		defaultPortLine:  fmt.Sprintf("define WGLAN_CONTROL_PORT = %d", controlPort),
	} {
		if !strings.Contains(out, old) {
			return "", fmt.Errorf("nftables/wglan.conf no longer contains %q", old)
		}
		out = strings.Replace(out, old, want, 1)
	}
	return out, nil
}

const usage = `wglan — a minimal WireGuard mesh for a LAN with no internet access

  wglan secret                          print a fresh wglan://v1/... secret
  wglan join                            set up and announce this node, then exit
  wglan run                             serve the control listener from persisted state
  wglan status                          per-peer view, with stale marking
  wglan sync    IP:PORT                 re-announce to one member and re-apply its list
  wglan forget  PUBKEY                  local removal of one peer
  wglan leave                           announce departure to every peer, then remove the interface
  wglan probe   [PUBKEY|HOSTNAME]       mesh-wide reachability tally (every peer if omitted)
  wglan firewall                        print the nftables skeleton for this node

"join" sets this node up and returns; "run" is the long-lived process, and is
what a systemd unit should start. Re-running "join" against an already-joined
node is safe, and is how you re-announce after renumbering.

Run "wglan <command> -h" for that command's flags — each only accepts the
flags it actually uses, so this list never grows a flag it doesn't act on.

"wglan join" takes the secret via --secret or $WGLAN_SECRET and persists it to
<state-dir>/secret; every other command reads it from there (or $WGLAN_SECRET),
so a reboot needs no operator present.

wglan never edits nftables. "wglan firewall" prints a ruleset that default-denies
the mesh interface; install it where your nftables config is loaded from. Until
you do, joining exposes every port this host already has bound.
`

type opts struct {
	secret      string
	meshIP      string
	bootstrap   string
	hostname    string
	iface       string
	lanIP       string
	dir         string
	listenPort  int
	controlPort int
}

// A flagReg registers one flag on a FlagSet against a field of o. Bundling
// name+registration lets commandFlagSets be the single table that drives both
// "is this a valid subcommand" and "which flags does it accept" — one place to
// update when a subcommand's flags change, instead of two lists that can drift.
type flagReg struct {
	name string
	reg  func(fs *flag.FlagSet, o *opts)
}

var (
	flagInterface = flagReg{"interface", func(fs *flag.FlagSet, o *opts) {
		// No default here: an empty value is what lets the name join persisted
		// win over the fallback. See resolveIface.
		fs.StringVar(&o.iface, "interface", "", "WireGuard interface name (default: the one join used, else "+defaultIface+")")
	}}
	flagStateDir = flagReg{"state-dir", func(fs *flag.FlagSet, o *opts) {
		fs.StringVar(&o.dir, "state-dir", "/var/lib/wglan", "where peers.json, private.key and secret live")
	}}
	// --lan-ip only matters on join/run/sync: they can send n.self() over the
	// wire (a JOIN or JOIN_REPLY), which is what advertises our LAN endpoint to
	// a peer. forget also calls n.self(), but only to rewrite the hosts block,
	// which reads Hostname/MeshIP off it and never touches LANEndpoint.
	flagLanIP = flagReg{"lan-ip", func(fs *flag.FlagSet, o *opts) {
		fs.StringVar(&o.lanIP, "lan-ip", "", "this node's LAN address (default: first global unicast IPv4)")
	}}
	// --secret exists only on join: every other command reads the secret join
	// persisted to <state-dir>/secret (or $WGLAN_SECRET), per SPEC §9 — that's
	// the whole point of persisting it, so run et al. need no operator present.
	flagSecret = flagReg{"secret", func(fs *flag.FlagSet, o *opts) {
		fs.StringVar(&o.secret, "secret", "", "wglan://v1/... shared secret")
	}}
	flagMeshIP = flagReg{"mesh-ip", func(fs *flag.FlagSet, o *opts) {
		fs.StringVar(&o.meshIP, "mesh-ip", "", "this node's mesh address with mask, e.g. 10.90.0.3/24")
	}}
	flagBootstrap = flagReg{"bootstrap", func(fs *flag.FlagSet, o *opts) {
		fs.StringVar(&o.bootstrap, "bootstrap", "", "any existing member's control address, IP:PORT")
	}}
	flagHostname = flagReg{"hostname", func(fs *flag.FlagSet, o *opts) {
		fs.StringVar(&o.hostname, "hostname", "", "mesh hostname (default: the OS hostname)")
	}}
	flagListenPort = flagReg{"listen-port", func(fs *flag.FlagSet, o *opts) {
		fs.IntVar(&o.listenPort, "listen-port", 51820, "WireGuard UDP data-plane port")
	}}
	flagControlPort = flagReg{"control-port", func(fs *flag.FlagSet, o *opts) {
		fs.IntVar(&o.controlPort, "control-port", 51821, "TCP control-plane port")
	}}
)

// commandFlagSets is the single source of truth for both "is cmd a valid
// subcommand" (its keys) and "which flags does cmd accept" (its values) —
// `firewall` and `secret` are handled separately in main since they don't
// build a Node at all.
var commandFlagSets = map[string][]flagReg{
	"join":   {flagInterface, flagStateDir, flagLanIP, flagSecret, flagMeshIP, flagBootstrap, flagHostname, flagListenPort, flagControlPort},
	"run":    {flagInterface, flagStateDir, flagLanIP},
	"sync":   {flagInterface, flagStateDir, flagLanIP},
	"forget": {flagInterface, flagStateDir},
	"leave":  {flagInterface, flagStateDir},
	"probe":  {flagInterface, flagStateDir},
	"status": {flagInterface, flagStateDir},
}

// commandFlags returns the flag set for cmd, one of commandFlagSets' keys.
// Each subcommand registers only the flags newNode/cmdJoin actually read for
// it — a flag with no effect on a subcommand is a parse error there, never a
// silently-accepted no-op.
func commandFlags(cmd string) (*flag.FlagSet, *opts) {
	var o opts
	fs := flag.NewFlagSet("wglan "+cmd, flag.ExitOnError)
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage); fs.PrintDefaults() }
	for _, f := range commandFlagSets[cmd] {
		f.reg(fs, &o)
	}
	return fs, &o
}

func main() {
	log.SetFlags(log.Ltime)
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	cmd := os.Args[1]
	if cmd == "firewall" {
		fs := flag.NewFlagSet("wglan firewall", flag.ExitOnError)
		fs.Usage = func() { fmt.Fprint(os.Stderr, usage); fs.PrintDefaults() }
		iface := fs.String("interface", "wglan0", "WireGuard interface name")
		port := fs.Int("control-port", 51821, "TCP control-plane port")
		if err := fs.Parse(os.Args[2:]); err != nil {
			die(err)
		}
		out, err := renderFirewall(*iface, *port)
		die(err)
		fmt.Print(out)
		return
	}
	if cmd == "secret" {
		s, err := envelope.NewSecret()
		if err != nil {
			die(err)
		}
		fmt.Println(s)
		return
	}
	if _, ok := commandFlagSets[cmd]; !ok {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}

	fs, op := commandFlags(cmd)
	if err := fs.Parse(os.Args[2:]); err != nil {
		die(err)
	}
	o := *op
	args := fs.Args()

	n, fresh, err := newNode(cmd, o)
	if err != nil {
		die(err)
	}

	switch cmd {
	case "join":
		die(n.cmdJoin(o, fresh))
	case "run":
		die(n.cmdRun())
	case "status":
		die(n.printStatus(os.Stdout))
	case "sync":
		if len(args) != 1 {
			die(errors.New("usage: wglan sync IP:PORT"))
		}
		die(n.cmdSync(args[0]))
	case "forget":
		if len(args) != 1 {
			die(errors.New("usage: wglan forget PUBKEY"))
		}
		die(n.forget(args[0]))
	case "leave":
		n.announceLeave()
		die(n.sys.RemoveLink())
	case "probe":
		if len(args) > 1 {
			die(errors.New("usage: wglan probe [PUBKEY|HOSTNAME]"))
		}
		if len(args) == 0 {
			n.probeAll()
			break
		}
		p, err := n.resolve(args[0])
		if err != nil {
			die(err)
		}
		n.probeMesh(p)
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
}

func die(err error) {
	if err != nil {
		log.Fatalf("wglan: %v", err)
	}
}

// newNode assembles the node from flags plus persisted state. It reports whether
// this is a first run (no peers.json).
func newNode(cmd string, o opts) (*Node, bool, error) {
	st, existed, err := loadState(o.dir)
	if err != nil {
		return nil, false, err
	}
	if !existed && cmd != "join" {
		return nil, false, fmt.Errorf("no state in %s — run `wglan join` first", o.dir)
	}

	if cmd == "join" {
		if err := os.MkdirAll(o.dir, 0o700); err != nil {
			return nil, false, err
		}
		// --mesh-ip wins over the persisted value: that precedence is what makes
		// renumbering work (SPEC §10).
		if o.meshIP != "" {
			st.Self.MeshIP = o.meshIP
		}
		if st.Self.MeshIP == "" {
			return nil, false, errors.New("--mesh-ip is mandatory on a first join, e.g. --mesh-ip 10.90.0.3/24")
		}
		if _, err := netip.ParsePrefix(st.Self.MeshIP); err != nil {
			return nil, false, fmt.Errorf("--mesh-ip %q: want an address with a mask, e.g. 10.90.0.3/24", st.Self.MeshIP)
		}
		if o.hostname == "" && st.Self.Hostname == "" {
			h, err := os.Hostname()
			if err != nil {
				return nil, false, err
			}
			o.hostname = strings.ToLower(h)
		}
		if o.hostname != "" {
			st.Self.Hostname = o.hostname
		}
		if err := envelope.ValidHostname(st.Self.Hostname); err != nil {
			return nil, false, err
		}
		st.Self.ListenPort, st.Self.ControlPort = o.listenPort, o.controlPort
	}

	key, err := resolveSecret(o, cmd == "join")
	if err != nil {
		return nil, false, err
	}

	subnet, err := st.Self.Prefix()
	if err != nil {
		return nil, false, err
	}
	if cmd == "join" {
		pub, err := ensureKeypair(keyPath(o.dir))
		if err != nil {
			return nil, false, err
		}
		if st.Self.Pubkey != "" && st.Self.Pubkey != pub {
			log.Printf("private key changed on disk: pubkey %s -> %s", short(st.Self.Pubkey), short(pub))
		}
		st.Self.Pubkey = pub
	}

	// Interface first: it is what LAN-address detection has to exclude.
	iface := resolveIface(o.iface, st.Self.Iface)
	cands, err := lanCandidates(iface)
	if err != nil {
		return nil, false, err
	}
	lan, err := resolveLANIP(o.lanIP, st.Self.LANIP, cands)
	if err != nil {
		return nil, false, err
	}
	if _, err := netip.ParseAddr(lan); err != nil {
		return nil, false, fmt.Errorf("--lan-ip %q: %w", lan, err)
	}
	if cmd == "join" {
		st.Self.Iface, st.Self.LANIP = iface, lan
	}

	n := &Node{
		dir:    o.dir,
		st:     st,
		subnet: subnet.Masked(),
		lanIP:  lan,
		key:    key,
		ver:    envelope.NewVerifier(key),
		sys:    &Sys{Run: execRunner, Iface: iface, HostsPath: defaultHostsPath},
	}
	return n, !existed, nil
}

// resolveSecret takes the secret from --secret, then $WGLAN_SECRET, then
// <state-dir>/secret. On a join it is persisted so `run` needs no operator after
// a reboot.
func resolveSecret(o opts, persist bool) (envelope.Key, error) {
	var zero envelope.Key
	path := filepath.Join(o.dir, "secret")
	s := o.secret
	if s == "" {
		s = os.Getenv("WGLAN_SECRET")
	}
	if s == "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return zero, fmt.Errorf("no secret: pass --secret, set $WGLAN_SECRET, or place one in %s", path)
		}
		s = strings.TrimSpace(string(b))
		persist = false
	}
	k, err := envelope.DeriveKey(s)
	if err != nil {
		return zero, err
	}
	if persist {
		if err := writeFileAtomic(path, []byte(s+"\n"), 0o600); err != nil {
			return zero, err
		}
	}
	return k, nil
}

func ensureKeypair(path string) (string, error) {
	if _, err := os.Stat(path); err == nil {
		return PubkeyFromFile(path)
	}
	pub, err := GenKey(path)
	if err != nil {
		return "", err
	}
	log.Printf("generated keypair, pubkey %s", pub)
	return pub, nil
}

// detectLANIP picks the first global-unicast IPv4 that is not on the mesh
// interface. --lan-ip overrides it.
// lanCandidates lists this host's usable IPv4 addresses, best first. One
// function serves both jobs: detection takes the head, and verifying a
// persisted address asks whether it is still in the set.
func lanCandidates(exclude string) ([]string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var out []string
	for _, ifc := range ifaces {
		if ifc.Name == exclude || ifc.Flags&net.FlagLoopback != 0 || ifc.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			v4 := ipn.IP.To4()
			if v4 != nil && v4.IsGlobalUnicast() && !v4.IsLinkLocalUnicast() {
				out = append(out, v4.String())
			}
		}
	}
	return out, nil
}

// resolveIface settles the interface name: the flag wins, then what join
// persisted, then the default. Without the persisted step, a node joined on
// wglan7 came back on wglan0 after a reboot — a second, empty interface, and no
// error to say so.
func resolveIface(flag, stored string) string {
	switch {
	case flag != "":
		return flag
	case stored != "":
		return stored
	default:
		return defaultIface
	}
}

// resolveLANIP settles the address we advertise as our endpoint, with the same
// precedence --mesh-ip uses: the flag wins, then what join persisted, then
// detection. A persisted address that is on no interface any more is a DHCP move
// or a re-cabling; say so and use reality, because a JOIN_REPLY advertises this
// value and the receiver has nothing to observe it against (SPEC §4.3). Keeping
// it when nothing is detectable is deliberate: status, leave and probe never
// touch the endpoint, and must not fail on a host whose NIC is down.
func resolveLANIP(flag, stored string, cands []string) (string, error) {
	if flag != "" {
		return flag, nil
	}
	if stored != "" {
		if slices.Contains(cands, stored) {
			return stored, nil
		}
		if len(cands) > 0 {
			log.Printf("lan-ip %s is on no interface any more, advertising %s instead", stored, cands[0])
			return cands[0], nil
		}
		return stored, nil
	}
	if len(cands) == 0 {
		return "", errors.New("no LAN address found — pass --lan-ip")
	}
	return cands[0], nil
}

// bringUp makes the host match our state, idempotently and silently where it
// already does.
func (n *Node) bringUp() error {
	if err := n.sys.EnsureLink(keyPath(n.dir), n.st.Self.MeshIP, n.st.Self.ListenPort); err != nil {
		return err
	}
	// On restart, reload peers straight into WireGuard rather than bootstrapping.
	for _, p := range n.st.Peers {
		if err := n.sys.SetPeer(p); err != nil {
			return err
		}
	}
	if err := saveState(n.dir, n.st); err != nil {
		return err
	}
	return n.sys.WriteHosts(append(slices.Clone(n.st.Peers), n.self()))
}

// cmdJoin sets this node up and announces it, then returns. Serving is `run`'s
// job alone (SPEC §9): a join that ended in serve() could not be re-run against
// a node whose daemon already holds the control port, which is exactly when a
// repair is wanted. With existing state and no new address or bootstrap target
// it is bring-up and nothing else.
func (n *Node) cmdJoin(o opts, fresh bool) error {
	renumbered := false
	if !fresh {
		prev, _, err := loadState(o.dir)
		if err == nil && prev.Self.MeshIP != n.st.Self.MeshIP {
			renumbered = true
			log.Printf("renumbered: %s -> %s, re-announcing to every peer", prev.Self.MeshIP, n.st.Self.MeshIP)
		}
	}
	if err := n.bringUp(); err != nil {
		return err
	}
	switch {
	case o.bootstrap != "":
		if err := n.joinTo(o.bootstrap); err != nil {
			return fmt.Errorf("bootstrap %s: %w", o.bootstrap, err)
		}
		n.fanout(o.bootstrap)
	case renumbered:
		n.fanout("")
	case fresh:
		log.Printf("first node: %s is %s, no bootstrap target given", n.st.Self.Hostname, n.st.Self.MeshIP)
	}
	return nil
}

func (n *Node) cmdRun() error {
	if err := n.bringUp(); err != nil {
		return err
	}
	return n.serve()
}

// serve listens on every interface: a JOIN must be reachable before a tunnel
// exists. LEAVE and PROBE are bound to the tunnel inside the handler instead.
func (n *Node) serve() error {
	addr := fmt.Sprintf(":%d", n.st.Self.ControlPort)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	// A node stopping to reboot has not left the mesh, so no LEAVE here (§6).
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-stop
		log.Printf("shutting down; the mesh keeps our peer entry")
		ln.Close()
	}()
	log.Printf("listening on %s, %d peers known", addr, len(n.st.Peers))
	err = n.Serve(ln)
	if errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}
