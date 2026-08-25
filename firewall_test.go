package main

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// The embedded conf is the single source of truth for the ruleset. These tests
// are what keep it honest — there is no Go code building the rules any more, so
// a mistake in the file would otherwise ship unnoticed.

// stripComments returns just the nftables statements, so the prose explaining
// why the file is not `policy drop` cannot be mistaken for it being one.
func stripComments(conf string) string {
	var out []string
	for _, line := range strings.Split(conf, "\n") {
		if i := strings.Index(line, "#"); i >= 0 {
			line = line[:i]
		}
		if strings.TrimSpace(line) == "" {
			continue
		}
		out = append(out, strings.TrimSpace(line))
	}
	return strings.Join(out, "\n")
}

func TestFirewallConfShape(t *testing.T) {
	t.Parallel()
	code := stripComments(firewallConf)

	// A base chain at policy drop would take the whole host offline: a policy
	// cannot be conditioned on an interface and a drop in any base chain is final.
	if !strings.Contains(code, "policy accept;") {
		t.Error("base chain is not policy accept")
	}
	if strings.Contains(code, "policy drop") {
		t.Error("policy drop in the base chain would drop LAN SSH and WireGuard's own port")
	}
	// `iif` matches an index resolved at load time and decays on re-create.
	for _, l := range strings.Split(code, "\n") {
		if strings.Contains(l, "iif ") {
			t.Errorf("uses index-based iif, want iifname: %q", l)
		}
	}

	want := []string{
		"ct state established,related accept",
		"tcp dport $WGLAN_CONTROL_PORT accept",
		"icmp type echo-request accept",
		"iifname $WGLAN_IFACE jump mesh",
		"iifname $WGLAN_IFACE drop",
		"table inet wglan\ndelete table inet wglan", // idempotent reload
	}
	for _, w := range want {
		if !strings.Contains(code, w) {
			t.Errorf("conf is missing %q", w)
		}
	}

	// The jump must precede the terminal drop or the allow-list is unreachable.
	if jump, drop := strings.Index(code, "jump mesh"), strings.Index(code, "$WGLAN_IFACE drop"); jump > drop {
		t.Errorf("jump at %d must precede the drop at %d", jump, drop)
	}
	// Conntrack must come before the port rules inside the mesh chain.
	ct := strings.Index(code, "ct state established,related accept")
	port := strings.Index(code, "tcp dport $WGLAN_CONTROL_PORT accept")
	if ct < 0 {
		t.Error("no conntrack rule: every connection this host initiates would hang")
	} else if ct > port {
		t.Error("conntrack rule sits below the port rules")
	}
}

func TestRenderFirewallSubstitutes(t *testing.T) {
	t.Parallel()
	// Defaults must appear verbatim, or the substitution below is a no-op that
	// silently ignores the flags.
	if !strings.Contains(firewallConf, defaultIfaceLine) || !strings.Contains(firewallConf, defaultPortLine) {
		t.Fatal("conf no longer carries the default define lines")
	}
	out, err := renderFirewall("wg-lab0", 61821)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, `define WGLAN_IFACE = "wg-lab0"`) {
		t.Error("interface define not rewritten")
	}
	if !strings.Contains(out, "define WGLAN_CONTROL_PORT = 61821") {
		t.Error("control-port define not rewritten")
	}
	if strings.Contains(out, defaultIfaceLine) || strings.Contains(out, defaultPortLine) {
		t.Error("a default define line survived the rewrite")
	}
	// Defaults in, byte-identical file out.
	same, err := renderFirewall("wglan0", 51821)
	if err != nil {
		t.Fatal(err)
	}
	if same != firewallConf {
		t.Error("rendering with the defaults changed the file")
	}
}

// nft parses what we ship. Needs root: `nft -c` still initialises a netlink
// cache, so it is skipped in an unprivileged run and covered by CI or a manual
// `sudo go test -run Nft`.
func TestNftAcceptsTheConf(t *testing.T) {
	if _, err := exec.LookPath("nft"); err != nil {
		t.Skip("nft not installed")
	}
	if os.Geteuid() != 0 {
		t.Skip("nft -c needs root for its netlink cache")
	}
	f, err := os.CreateTemp(t.TempDir(), "wglan*.conf")
	if err != nil {
		t.Fatal(err)
	}
	out, err := renderFirewall("wglan0", 51821)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(out); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if b, err := exec.Command("nft", "-c", "-f", f.Name()).CombinedOutput(); err != nil {
		t.Fatalf("nft rejected the shipped conf: %v\n%s", err, b)
	}
}
