package main

import (
	"io"
	"maps"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// captureStdout runs fn and returns what it printed.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	saved := os.Stdout
	os.Stdout = w
	done := make(chan string)
	go func() {
		out, _ := io.ReadAll(r)
		done <- string(out)
	}()
	defer func() { os.Stdout = saved }()
	fn()
	w.Close()
	os.Stdout = saved
	return <-done
}

// TestMACIPCacheGatewayExpiry (H8, Q18): with the gateway's SNMP ARP walk
// failing, as on every production start, no cache entry expires however old
// it is, and the run prints one warning naming the gateway. Once the gateway
// answers, entries it has not shown for more than the TTL expire, newer ones
// stay. mac_ip_cache.json keeps the old "mac": "ip" form and the times go to
// the sidecar.
func TestMACIPCacheGatewayExpiry(t *testing.T) {
	resetState(t)
	dir := t.TempDir()
	macIPCacheFile = filepath.Join(dir, "mac_ip_cache.json")
	now := testClock.Now()
	writeFile := func(path, content string) {
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	writeFile(macIPCacheFile, `{"00:1b:21:0b:00:01": "10.0.2.1", "00:1b:21:0b:00:02": "10.0.2.2", "00:1b:21:0b:00:03": "10.0.2.3"}`)
	writeFile(filepath.Join(dir, "mac_ip_cache_seen.json"), strings.NewReplacer(
		"OLD", strconv.FormatInt(now.Add(-10*24*time.Hour).Unix(), 10),
		"RECENT", strconv.FormatInt(now.Add(-3*24*time.Hour).Unix(), 10),
	).Replace(`{"00:1b:21:0b:00:01": OLD, "00:1b:21:0b:00:02": RECENT}`))
	loadMacIPCache()

	// Two sweeps with the gateway silent: nothing expires, one warning
	out := captureStdout(t, func() {
		collectARPFromAllSwitches()
		testClock.advance(5 * time.Minute)
		collectARPFromAllSwitches()
	})
	if n := strings.Count(out, "did not answer the SNMP ARP walk"); n != 1 || !strings.Contains(out, "Gateway "+fixedGatewayIP+" ") {
		t.Errorf("want one gateway warning naming %s, got %d in:\n%s", fixedGatewayIP, n, out)
	}
	if got := len(collectCacheMap()); got != 3 {
		t.Errorf("entries after sweeps without the gateway = %d, want 3", got)
	}

	// The gateway answers: the entry it has not shown for 10 days expires;
	// the one seen 3 days ago and the one without a time stay
	fakeSNMP.set(fixedGatewayIP, map[string][]string{oidARP: {
		oidARP + ".5.10.0.2.4 = Hex-STRING: 00 1B 21 0B 00 04 ",
	}})
	collectARPFromAllSwitches()
	want := map[string]string{"00:1b:21:0b:00:02": "10.0.2.2", "00:1b:21:0b:00:03": "10.0.2.3", "00:1b:21:0b:00:04": "10.0.2.4"}
	if got := collectCacheMap(); !maps.Equal(got, want) {
		t.Errorf("cache after the gateway answered = %v, want %v", got, want)
	}
	var saved map[string]string
	decodeJSONFile(t, macIPCacheFile, &saved)
	if !maps.Equal(saved, want) {
		t.Errorf("saved cache = %v, want the old form %v", saved, want)
	}
	var seen map[string]int64
	decodeJSONFile(t, filepath.Join(dir, "mac_ip_cache_seen.json"), &seen)
	if len(seen) != 3 || seen["00:1b:21:0b:00:04"] != testClock.Now().Unix() {
		t.Errorf("saved sidecar = %v", seen)
	}
}
