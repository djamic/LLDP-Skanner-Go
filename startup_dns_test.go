package main

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// Tests for the startup graph and the reverse DNS lookups of the graph
// labels (RC-1): with a DNS server that does not answer, the first graph
// after a restart used to take 2 s per name (about 27 minutes for the ~800
// names of the fixture) on main()'s goroutine, before any monitoring loop
// started, and every failed lookup stayed cached until the process exited.

// holdFixtureDNS makes the reverse lookups of the last n of the IPs a
// fixture build looks up hang (a DNS server that does not answer: each one
// ends at its 2 s timeout, or when the test frees it) and returns those
// IPs. The lookups start in list order, so the others are answered first.
func holdFixtureDNS(t *testing.T, n int) []string {
	t.Helper()
	snapshot := snapshotCollectedData()
	ips := graphHostnameIPs(snapshot, buildSwitchOwnMACs(snapshot))
	if len(ips) <= 2*n {
		t.Fatalf("precondition: the fixture build looks up %d names, want more than %d", len(ips), 2*n)
	}
	held := ips[len(ips)-n:]
	for _, ip := range held {
		holdReverseDNS(ip)
	}
	return held
}

// setGraphDNSWait shortens how long a build waits for its lookups.
func setGraphDNSWait(t *testing.T, d time.Duration) {
	t.Helper()
	saved := graphDNSWait
	graphDNSWait = d
	t.Cleanup(func() { graphDNSWait = saved })
}

// waitDNSIdle frees every held lookup and waits until no lookup runs.
func waitDNSIdle(t *testing.T) {
	t.Helper()
	releaseDNSHolds()
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(time.Millisecond) {
		dnsCacheMutex.RLock()
		running := len(dnsInflight)
		dnsCacheMutex.RUnlock()
		if running == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d reverse lookups still running", running)
		}
	}
}

// graphHasDNSName reports whether some node label has "[DNS] name".
func graphHasDNSName(g *DJGraph, name string) bool {
	for _, info := range g.SwitchInfo {
		if strings.Contains(info, "[DNS] "+name+"\n") || strings.HasSuffix(info, "[DNS] "+name) {
			return true
		}
	}
	return false
}

// TestGraphBuildBoundsDNSWait: a build waits at most graphDNSWait for the
// reverse lookups it needs, which run in parallel, instead of 2 s for each
// name that gets no answer (80 s for the 40 held here). The names that
// came in time are in the labels; the others arrive in the cache and are in
// the next build.
func TestGraphBuildBoundsDNSWait(t *testing.T) {
	useFixture(t)
	setGraphDNSWait(t, 300*time.Millisecond)
	held := holdFixtureDNS(t, 40)
	snapshot := snapshotCollectedData()

	start := time.Now()
	g := buildGraphFromSnapshot(snapshot)
	built := time.Since(start)
	if built > 20*time.Second {
		t.Errorf("the build took %v with 40 unanswered lookups, want about graphDNSWait plus the build", built)
	}
	if !strings.Contains(fmt.Sprint(g.SwitchInfo), "[DNS] ") {
		t.Error("no label has a DNS name: the lookups that were answered did not reach the build")
	}

	waitDNSIdle(t) // the holds are gone, so the fake DNS answers at once
	heldName := "" // a held IP the fake DNS has a name for
	for _, ip := range held {
		if names, err := fakeReverseDNS(t.Context(), ip); err == nil {
			heldName = strings.SplitN(names[0], ".", 2)[0]
			break
		}
	}
	if heldName == "" {
		t.Fatal("precondition: none of the held IPs has a fake DNS name")
	}
	// A held lookup ends at its timeout, and the fake DNS then answers
	// anyway: only a build that finished before that cannot have the name.
	if built < dnsLookupTimeout-200*time.Millisecond && graphHasDNSName(g, heldName) {
		t.Errorf("the first build (%v) has [DNS] %s: it waited for a lookup that got no answer in time", built, heldName)
	}
	if next := buildGraphFromSnapshot(snapshot); !graphHasDNSName(next, heldName) {
		t.Errorf("the next build has no [DNS] %s line, the answer that came after the first build", heldName)
	}
}

// TestStartupGraphInBackground: main() builds the first graph in the
// background (startStartupGraph), so it goes on to start the monitoring
// loops at once; the graph is published when the build is done.
func TestStartupGraphInBackground(t *testing.T) {
	useFixture(t)
	setGraphDNSWait(t, 300*time.Millisecond)
	holdFixtureDNS(t, 40)

	done := startStartupGraph(snapshotCollectedData())
	select {
	case <-done:
		t.Fatal("startStartupGraph returned after the build, which waits for the DNS lookups")
	default:
	}
	waitDone(t, done, "the startup graph")
	if g := GetGlobalGraph(); g == nil || len(g.Nodes) < 100 {
		t.Fatalf("the startup graph was not published: %v", g)
	}
	waitDNSIdle(t)

	// Without saved hosts there is nothing to build.
	SetGlobalGraph(nil)
	waitDone(t, startStartupGraph(nil), "the startup graph without saved hosts")
	if GetGlobalGraph() != nil {
		t.Error("a startup graph was published without saved hosts")
	}
}

// TestReverseDNSFailureExpires: a failed reverse lookup is tried again once
// dnsNegativeTTL has passed (a DNS outage at startup no longer leaves the
// labels without names for the rest of the day); a name is kept.
func TestReverseDNSFailureExpires(t *testing.T) {
	resetState(t)
	const failing, named = "10.0.9.77", "10.0.9.75" // the fake DNS: no name; "pc-9-75"
	looksUp := func(ip string) bool {
		t.Helper()
		h := holdReverseDNS(ip)
		h.free() // a lookup does not wait
		resolveHostname(ip)
		select {
		case <-h.entered:
			return true
		default:
			dnsHolds.Delete(ip)
			return false
		}
	}
	if name := resolveHostname(failing); name != "" {
		t.Fatalf("resolveHostname(%s) = %q, want no name", failing, name)
	}
	if looksUp(failing) {
		t.Error("a failed lookup was repeated at once, want it cached")
	}
	testClock.advance(dnsNegativeTTL - time.Second)
	if looksUp(failing) {
		t.Error("a failed lookup was repeated before dnsNegativeTTL")
	}
	testClock.advance(time.Second)
	if !looksUp(failing) {
		t.Error("a failed lookup was not tried again after dnsNegativeTTL")
	}

	if name := resolveHostname(named); name != "pc-9-75" {
		t.Fatalf("resolveHostname(%s) = %q, want pc-9-75", named, name)
	}
	testClock.advance(24 * time.Hour)
	if looksUp(named) {
		t.Error("a name was looked up again, want it kept")
	}
}

// TestReverseDNSLookupsBounded: at most dnsLookupWorkers reverse lookups run
// at once, and an IP being looked up is not looked up twice.
func TestReverseDNSLookupsBounded(t *testing.T) {
	resetState(t)
	var ips []string
	var holds []*dnsHold
	for i := 1; i <= 40; i++ {
		ip := fmt.Sprintf("10.0.9.%d", 100+i)
		ips = append(ips, ip)
		holds = append(holds, holdReverseDNS(ip))
	}
	start := time.Now()
	resolveHostnames(ips, 0) // returns at once, the lookups go on
	if a, b := dnsStartLookup(ips[0]), dnsStartLookup(ips[0]); a != b {
		t.Error("an IP being looked up was looked up a second time")
	}
	entered := func() int {
		n := 0
		for _, h := range holds {
			select {
			case <-h.entered:
				n++
			default:
			}
		}
		return n
	}
	// No held lookup ends before its 2 s timeout, so until then the number
	// of lookups that started is the number running.
	safe := func() bool { return time.Since(start) < dnsLookupTimeout-100*time.Millisecond }
	for entered() < dnsLookupWorkers && safe() {
		time.Sleep(time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond)
	if n := entered(); safe() && n != dnsLookupWorkers {
		t.Errorf("%d reverse lookups running at once, want %d", n, dnsLookupWorkers)
	} else if !safe() {
		t.Logf("the machine is too slow to check the bound (%v)", time.Since(start))
	}
	waitDNSIdle(t)
	dnsCacheMutex.RLock()
	cached := len(dnsCache)
	dnsCacheMutex.RUnlock()
	if cached != len(ips) {
		t.Errorf("%d answers cached, want %d", cached, len(ips))
	}
}
