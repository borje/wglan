package main

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// The shipped unit is what an operator actually installs — these tests keep
// it honest the same way firewall_test.go keeps nftables/wglan.conf honest.

func TestSystemdUnitShape(t *testing.T) {
	t.Parallel()
	b, err := os.ReadFile("systemd/wglan.service")
	if err != nil {
		t.Fatal(err)
	}
	conf := string(b)

	want := []string{
		"ExecStart=/usr/bin/wglan run",
		"Restart=on-failure",
		"WantedBy=multi-user.target",
	}
	for _, w := range want {
		if !strings.Contains(conf, w) {
			t.Errorf("unit is missing %q", w)
		}
	}

	// join is a manual, one-time step (SPEC §9) — baking it into ExecStartPre
	// would re-run its bootstrap round trip on every service start.
	if strings.Contains(conf, "ExecStartPre=") {
		t.Error("unit must not run `wglan join` itself — join is a manual pre-step")
	}
}

// systemd-analyze verify also resolves ExecStart's binary, so this is only a
// real check once `wglan` is actually installed at the path the unit names —
// skipped otherwise, same as firewall_test.go's root-gated `nft -c -f`.
func TestSystemdAnalyzeVerify(t *testing.T) {
	if _, err := exec.LookPath("systemd-analyze"); err != nil {
		t.Skip("systemd-analyze not installed")
	}
	if fi, err := os.Stat("/usr/bin/wglan"); err != nil || fi.Mode()&0o111 == 0 {
		t.Skip("wglan not installed at /usr/bin/wglan")
	}
	out, err := exec.Command("systemd-analyze", "verify", "systemd/wglan.service").CombinedOutput()
	if err != nil {
		t.Fatalf("systemd-analyze rejected the shipped unit: %v\n%s", err, out)
	}
}
