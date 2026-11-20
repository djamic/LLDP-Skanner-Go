package main

import (
	"encoding/json"
	"maps"
	"os"
	"slices"
	"sync/atomic"
	"testing"
	"time"
)

// TestESXiConfirmedPersist: a confirmation, and taking one back, is saved
// to esxiConfirmedFile and announced (a graph build); the same verdict
// again is no change. A start loads the file and checks again each MAC
// still at its confirmed IP; a MAC at another IP now waits for the sweeps.
func TestESXiConfirmedPersist(t *testing.T) {
	resetState(t)
	changes := 0
	esxiConfirmationsChanged = func() { changes++ }
	const a, b, c = "00:0c:29:aa:00:01", "00:0c:29:aa:00:02", "00:0c:29:aa:00:03"
	globalMACtoIPMutex.Lock()
	globalMACtoIP[a], globalMACtoIP[b], globalMACtoIP[c] = "10.1.1.1", "10.1.1.2", "10.1.1.30"
	globalMACtoIPMutex.Unlock()
	up := func(string) bool { return true }
	verdict := func(v bool) func(string) bool { return func(string) bool { return v } }
	saved := func() map[string]string {
		data, err := os.ReadFile(esxiConfirmedFile)
		if err != nil {
			return nil
		}
		var m map[string]string
		if err := json.Unmarshal(data, &m); err != nil {
			t.Fatal(err)
		}
		return m
	}
	now := macIPClock()
	steps := []struct {
		job     esxiJob
		esxi    bool
		changes int
		saved   map[string]string
	}{
		{esxiJob{a, "10.1.1.1"}, true, 1, map[string]string{a: "10.1.1.1"}},
		{esxiJob{a, "10.1.1.1"}, true, 1, map[string]string{a: "10.1.1.1"}},  // the same verdict
		{esxiJob{b, "10.1.1.2"}, false, 1, map[string]string{a: "10.1.1.1"}}, // never confirmed
		{esxiJob{b, "10.1.1.2"}, true, 2, map[string]string{a: "10.1.1.1", b: "10.1.1.2"}},
		{esxiJob{b, "10.1.1.2"}, false, 3, map[string]string{a: "10.1.1.1"}}, // reinstalled
	}
	for i, s := range steps {
		collectCheckESXi(s.job, up, verdict(s.esxi), now)
		if got := saved(); changes != s.changes || !maps.Equal(got, s.saved) {
			t.Errorf("step %d: %d changes, saved %v; want %d, %v", i, changes, got, s.changes, s.saved)
		}
	}

	clearConfirmedESXi()
	esxiJobs.reset()
	file := `{"` + a + `": "10.1.1.1", "` + c + `": "10.1.1.3", "nonsense": "10.1.1.4", "00:0c:29:aa:00:05": "no ip"}`
	if err := os.WriteFile(esxiConfirmedFile, []byte(file), 0o644); err != nil {
		t.Fatal(err)
	}
	if n := loadESXiConfirmed(); n != 2 {
		t.Errorf("loaded %d confirmations, want 2", n)
	}
	for _, mac := range []string{a, c} {
		if !graphIsConfirmedESXi(mac) {
			t.Errorf("%s is not confirmed after the load", mac)
		}
	}
	if jobs := esxiJobs.taken(); !slices.Equal(jobs, []string{a + " 10.1.1.1"}) {
		t.Errorf("checked again after the load: %v, want %s only", jobs, a)
	}
	if changes != 3 {
		t.Errorf("the load announced a change (%d changes)", changes)
	}
}

// TestESXiRebuildSoon: a burst of changes builds the graph once, after the
// wait; a change after that build builds it again.
func TestESXiRebuildSoon(t *testing.T) {
	var builds atomic.Int32
	delay, build := esxiRebuildDelay, esxiRebuild
	esxiRebuildDelay, esxiRebuild = 20*time.Millisecond, func() { builds.Add(1) }
	t.Cleanup(func() { esxiRebuildDelay, esxiRebuild = delay, build })
	wait := func(n int32) {
		t.Helper()
		for deadline := time.Now().Add(2 * time.Second); builds.Load() < n && time.Now().Before(deadline); {
			time.Sleep(5 * time.Millisecond)
		}
		time.Sleep(50 * time.Millisecond) // no second build of the same burst
		if got := builds.Load(); got != n {
			t.Fatalf("%d graph builds, want %d", got, n)
		}
	}
	for range 5 {
		esxiRebuildSoon()
	}
	wait(1)
	esxiRebuildSoon()
	wait(2)
}
