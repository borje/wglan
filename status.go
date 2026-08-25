package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"
)

// staleAfterSeconds is WireGuard's REJECT_AFTER_TIME. §11 sets
// persistent-keepalive 25 on every peer in both directions, so a reachable peer's
// latest-handshake cannot age past this — which makes handshake age sufficient on
// its own.
//
// SPEC §8 asks for a second signal (transfer counters that have not grown "since
// the last check"), but `status` is one-shot and nothing runs on a timer, so
// there is no previous check to compare against; two runs a second apart would
// mark a healthy mesh stale. The counters are printed instead, so a human still
// sees both numbers.
//
// ponytail: add a counter snapshot only if a peer ever reads stale while healthy.
const staleAfterSeconds = 180

// handshakeAges returns seconds since each peer's last handshake, or -1 for a
// peer that has never completed one.
func (n *Node) handshakeAges() (map[string]int64, error) {
	out, err := n.sys.Show("latest-handshakes")
	if err != nil {
		return nil, err
	}
	now := time.Now().Unix()
	ages := map[string]int64{}
	for line := range strings.SplitSeq(out, "\n") {
		f := strings.Fields(line)
		if len(f) != 2 {
			continue
		}
		ts, err := strconv.ParseInt(f[1], 10, 64)
		if err != nil {
			continue
		}
		if ts == 0 {
			ages[f[0]] = -1
			continue
		}
		ages[f[0]] = now - ts
	}
	return ages, nil
}

// transfers returns rx and tx bytes per peer.
func (n *Node) transfers() (map[string][2]int64, error) {
	out, err := n.sys.Show("transfer")
	if err != nil {
		return nil, err
	}
	xfer := map[string][2]int64{}
	for line := range strings.SplitSeq(out, "\n") {
		f := strings.Fields(line)
		if len(f) != 3 {
			continue
		}
		rx, err1 := strconv.ParseInt(f[1], 10, 64)
		tx, err2 := strconv.ParseInt(f[2], 10, 64)
		if err1 != nil || err2 != nil {
			continue
		}
		xfer[f[0]] = [2]int64{rx, tx}
	}
	return xfer, nil
}

func (n *Node) printStatus(w *os.File) error {
	ages, err := n.handshakeAges()
	if err != nil {
		return err
	}
	xfer, err := n.transfers()
	if err != nil {
		return err
	}
	n.mu.Lock()
	st := n.st
	n.mu.Unlock()

	tw := tabwriter.NewWriter(w, 0, 0, 3, ' ', 0)
	fmt.Fprintf(tw, "%s.mesh\t%s\t%s\t%s\t%s\t\n", st.Self.Hostname, st.Self.MeshIP, "-", "self", "-")
	for _, p := range st.Peers {
		age, seen := ages[p.Pubkey]
		var state string
		switch {
		case !seen:
			state = "not on the interface"
		case age < 0:
			state = "never handshook"
		case age > staleAfterSeconds:
			state = "stale " + dur(age)
		default:
			state = "handshake " + dur(age)
		}
		t := xfer[p.Pubkey]
		fmt.Fprintf(tw, "%s.mesh\t%s\t%s\t%s\trx %s tx %s\t\n",
			p.Hostname, p.MeshIP, p.LANEndpoint, state, size(t[0]), size(t[1]))
	}
	return tw.Flush()
}

func dur(secs int64) string {
	d := time.Duration(secs) * time.Second
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", secs)
	case d < time.Hour:
		return fmt.Sprintf("%dm", secs/60)
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh%dm", secs/3600, (secs%3600)/60)
	default:
		return fmt.Sprintf("%dd%dh", secs/86400, (secs%86400)/3600)
	}
}

func size(b int64) string {
	const k = 1024
	switch {
	case b < k:
		return fmt.Sprintf("%dB", b)
	case b < k*k:
		return fmt.Sprintf("%.1fK", float64(b)/k)
	case b < k*k*k:
		return fmt.Sprintf("%.1fM", float64(b)/(k*k))
	default:
		return fmt.Sprintf("%.1fG", float64(b)/(k*k*k))
	}
}
