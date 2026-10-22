package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// Tests for the MAC→IP cache and the ESXi check (mac_ip_service.go).

// collectResetCache clears the cache and ESXi bookkeeping that resetState
// does not know about, now and when the test ends.
func collectResetCache(t *testing.T) {
	t.Helper()
	reset := func() {
		globalMACtoIPMutex.Lock()
		globalMACtoIP = make(map[string]string)
		collectMACIPSeen = make(map[string]time.Time)
		macIPGatewayOK = make(map[string]time.Time)
		macIPGatewayWarned = make(map[string]bool)
		macIPSVIWait = make(map[string]time.Time)
		globalMACtoIPMutex.Unlock()
		collectESXiMu.Lock()
		collectESXiChecked = make(map[string]string)
		collectESXiRetry = make(map[string]collectESXiRetryJob)
		collectESXiInflight = make(map[string]string)
		collectESXiMu.Unlock()
		clearConfirmedESXi()
		esxiJobs.reset()
	}
	reset()
	t.Cleanup(reset)
}

func collectCacheMap() map[string]string {
	globalMACtoIPMutex.RLock()
	defer globalMACtoIPMutex.RUnlock()
	return maps.Clone(globalMACtoIP)
}

// TestCollectMergeLastWriteWins checks Q18/F64/F70: the latest ARP
// observation of a MAC wins (first-write-wins kept old IPs forever), only
// usable MACs are cached (Q11), and new or changed IPs are queued for the
// ESXi check while unchanged ones already checked are not.
func TestCollectMergeLastWriteWins(t *testing.T) {
	resetState(t)
	collectResetCache(t)
	now := time.Now()
	const m1, m2 = "00:50:56:07:00:01", "00:50:56:07:00:02"
	added, changed := collectMergeMACIP([]ARPEntry{
		{IPAddress: "10.7.0.1", MACAddress: m1},
		{IPAddress: "10.7.0.2", MACAddress: "00-50-56-07-00-02"},
		{IPAddress: "10.7.0.3", MACAddress: "01:00:5e:00:00:16"}, // multicast
		{IPAddress: "10.7.0.4", MACAddress: "00:00:00:2d:2a:56"}, // zero OUI
		{IPAddress: "", MACAddress: "00:50:56:07:00:05"},         // no IP
	}, now)
	if added != 2 || changed != 0 {
		t.Errorf("first merge: added %d changed %d, want 2 0", added, changed)
	}
	if got := esxiJobs.taken(); !slices.Equal(got, []string{m1 + " 10.7.0.1", m2 + " 10.7.0.2"}) {
		t.Errorf("first merge queued %v", got)
	}

	// m1 was checked at 10.7.0.1; then m1 moves to 10.7.0.11 (DHCP).
	collectESXiMu.Lock()
	collectESXiChecked[m1] = "10.7.0.1"
	collectESXiMu.Unlock()
	collectMergeMACIP([]ARPEntry{{IPAddress: "10.7.0.1", MACAddress: m1}}, now)
	if got := esxiJobs.taken(); len(got) != 0 {
		t.Errorf("unchanged, already checked mapping queued again: %v", got)
	}
	added, changed = collectMergeMACIP([]ARPEntry{{IPAddress: "10.7.0.11", MACAddress: m1}}, now.Add(time.Minute))
	if added != 0 || changed != 1 {
		t.Errorf("IP change: added %d changed %d, want 0 1", added, changed)
	}
	if got := collectCacheMap(); got[m1] != "10.7.0.11" || got[m2] != "10.7.0.2" || len(got) != 2 {
		t.Errorf("cache = %v", got)
	}
	if got := esxiJobs.taken(); !slices.Equal(got, []string{m1 + " 10.7.0.11"}) {
		t.Errorf("changed IP queued %v, want the new IP", got)
	}
	globalMACtoIPMutex.RLock()
	seen := collectMACIPSeen[m1]
	globalMACtoIPMutex.RUnlock()
	if !seen.Equal(now.Add(time.Minute)) {
		t.Errorf("m1 last seen %v, want the last observation", seen)
	}
	if got := getGlobalIP("00:50:56:07:00:0B"); got != "" {
		t.Errorf("getGlobalIP of an unknown MAC = %q", got)
	}
	if got := getGlobalIP("00-50-56-07-00-02"); got != "10.7.0.2" {
		t.Errorf("getGlobalIP with dashes = %q, want 10.7.0.2", got)
	}
}

// TestCollectGatewayARPPolicy checks F70: the gateway ARP collector uses the
// same policy as the other collectors (it overwrote entries and skipped the
// ESXi queue).
func TestCollectGatewayARPPolicy(t *testing.T) {
	resetState(t)
	collectResetCache(t)
	const gw = "10.9.7.254"
	fakeSNMP.set(gw, map[string][]string{oidARP: {
		oidARP + ".5.10.7.1.1 = Hex-STRING: 00 50 56 07 01 01 ",
		oidARP + ".5.10.7.1.2 = Hex-STRING: 01 00 5E 00 00 FB ",
		oidARP + ".5.10.7.1.3 = Hex-STRING: DA A1 19 07 01 03 ",
	}})
	setGatewayIPs([]string{gw})
	collectGatewayARP()
	setGatewayIPs([]string{fixedGatewayIP})
	want := map[string]string{"00:50:56:07:01:01": "10.7.1.1", "da:a1:19:07:01:03": "10.7.1.3"}
	if got := collectCacheMap(); !maps.Equal(got, want) {
		t.Errorf("cache = %v, want %v", got, want)
	}
	// da:a1:19 is locally administered: cached, but never an ESXi host.
	if got := esxiJobs.taken(); !slices.Equal(got, []string{"00:50:56:07:01:01 10.7.1.1"}) {
		t.Errorf("queued %v", got)
	}
}

// TestCollectMACIPTTL checks Q18 with the gateway rule (H8): an entry expires
// only when a successful gateway ARP walk came more than the TTL after its
// last sighting; while the gateway has not answered in this run nothing
// expires, however old. Entries of unknown age count as seen at the prune.
// (TestGatewayExpiryPerGateway has two gateways.)
func TestCollectMACIPTTL(t *testing.T) {
	resetState(t)
	collectResetCache(t)
	setGatewayIPs([]string{"10.7.2.254"})
	t.Cleanup(func() { setGatewayIPs([]string{fixedGatewayIP}) })
	now := time.Now()
	globalMACtoIPMutex.Lock()
	globalMACtoIP = map[string]string{
		"00:50:56:07:02:01": "10.7.2.1", // seen 8 days ago
		"00:50:56:07:02:02": "10.7.2.2", // seen 1 day ago
		"00:50:56:07:02:03": "10.7.2.3", // unknown age
	}
	collectMACIPSeen["00:50:56:07:02:01"] = now.Add(-8 * 24 * time.Hour)
	collectMACIPSeen["00:50:56:07:02:02"] = now.Add(-24 * time.Hour)
	collectMACIPSeen["00:50:56:07:02:99"] = now // no entry
	globalMACtoIPMutex.Unlock()

	// The gateway never answered: nothing expires.
	if dropped := collectPruneMACIP(now); dropped != 0 {
		t.Errorf("dropped %d without a gateway walk, want 0", dropped)
	}
	if got := collectCacheMap(); len(got) != 3 {
		t.Errorf("cache after prune = %v", got)
	}
	globalMACtoIPMutex.RLock()
	started := collectMACIPSeen["00:50:56:07:02:03"]
	_, orphan := collectMACIPSeen["00:50:56:07:02:99"]
	globalMACtoIPMutex.RUnlock()
	if !started.Equal(now) || orphan {
		t.Errorf("unknown age not started (%v) or orphan time kept (%v)", started, orphan)
	}

	// A gateway walk now: the entry last seen 8 days ago expires.
	recordGatewayARP("10.7.2.254", 5, nil, now)
	if dropped := collectPruneMACIP(now); dropped != 1 {
		t.Errorf("dropped %d after a gateway walk, want 1", dropped)
	}
	if got := collectCacheMap(); len(got) != 2 || got["00:50:56:07:02:01"] != "" {
		t.Errorf("cache after the gateway walk = %v", got)
	}
	// A week later the gateway fails: the others stay; once it answers
	// again they expire as well.
	later := now.Add(7*24*time.Hour + time.Minute)
	recordGatewayARP("10.7.2.254", 0, errors.New("timeout"), later)
	if dropped := collectPruneMACIP(later); dropped != 0 {
		t.Errorf("dropped %d after a failed gateway walk, want 0", dropped)
	}
	recordGatewayARP("10.7.2.254", 5, nil, later)
	if dropped := collectPruneMACIP(later); dropped != 2 {
		t.Errorf("dropped %d once the gateway answered again, want 2", dropped)
	}
}

// TestCollectMergeARPTables checks the merge of one round of ARP walks
// (collectMergeARPTables): the cache ends as if the tables merged one after
// the other (a later table's row for a MAC wins, within a table the later
// row), but each MAC is merged once: a MAC that two tables map to
// different IPs counts as a change only when the winner differs from the
// cache, a table that repeats an earlier one's mapping gets no credit for
// it, unusable rows are skipped, and each MAC is queued for the ESXi check
// once, at the IP that won.
func TestCollectMergeARPTables(t *testing.T) {
	resetState(t)
	collectResetCache(t)
	globalMACtoIPMutex.Lock()
	globalMACtoIP["00:1b:21:44:00:01"] = "10.44.0.11" // as the last round left it: the second gateway's IP
	globalMACtoIPMutex.Unlock()
	row := func(ip, mac string) ARPEntry { return ARPEntry{IPAddress: ip, MACAddress: mac} }
	gatewayA := []ARPEntry{row("10.44.0.1", "00:1b:21:44:00:01"), row("10.44.0.2", "00:1b:21:44:00:02"), row("10.44.0.3", "ff:ff:ff:ff:ff:ff")}
	sviA := []ARPEntry{row("10.44.0.2", "00:1b:21:44:00:02"), row("10.44.0.5", "00:1b:21:44:00:05")}
	gatewayB := []ARPEntry{row("10.44.0.11", "00:1b:21:44:00:01"), row("10.44.0.6", "00:1b:21:44:00:06"), row("10.44.0.7", "00:1b:21:44:00:06")}
	esxiJobs.reset()
	got := collectMergeARPTables([][]ARPEntry{gatewayA, sviA, gatewayB}, testClock.Now())
	if want := []int{1, 1, 1}; !slices.Equal(got, want) {
		t.Errorf("new or changed per table %v, want %v", got, want)
	}
	want := map[string]string{"00:1b:21:44:00:01": "10.44.0.11", "00:1b:21:44:00:02": "10.44.0.2", "00:1b:21:44:00:05": "10.44.0.5", "00:1b:21:44:00:06": "10.44.0.7"}
	if cache := collectCacheMap(); !maps.Equal(cache, want) {
		t.Errorf("cache %v, want %v", cache, want)
	}
	if jobs, want := esxiJobs.taken(), []string{"00:1b:21:44:00:01 10.44.0.11", "00:1b:21:44:00:02 10.44.0.2", "00:1b:21:44:00:05 10.44.0.5", "00:1b:21:44:00:06 10.44.0.7"}; !slices.Equal(jobs, want) {
		t.Errorf("ESXi jobs %v, want one per MAC at the IP that won: %v", jobs, want)
	}
	globalMACtoIPMutex.RLock()
	stamped := len(collectMACIPSeen)
	globalMACtoIPMutex.RUnlock()
	if stamped != 4 {
		t.Errorf("%d MACs marked seen, want the 4 merged", stamped)
	}
}

// TestCollectCacheFile checks the cache files (H8): mac_ip_cache.json keeps
// the plain "mac": "ip" map the previous binary reads, and the last-seen
// times go to the sidecar mac_ip_cache_seen.json; loading takes the times
// from the sidecar, and a missing or unreadable sidecar makes every entry
// just seen. Keys are canonicalized, the Q11 filter applies, the {ip, seen}
// records of development builds load, and loading queues nothing for the
// ESXi check (F67).
func TestCollectCacheFile(t *testing.T) {
	resetState(t)
	collectResetCache(t)
	dir := t.TempDir()
	macIPCacheFile = filepath.Join(dir, "cache.json")
	sidecar := filepath.Join(dir, "cache_seen.json")
	if got := macIPSeenFile(); got != sidecar {
		t.Fatalf("macIPSeenFile() = %q, want %q", got, sidecar)
	}
	now := macIPClock() // the clock loadMacIPCache marks unknown entries with
	hourAgo := now.Add(-time.Hour)

	globalMACtoIPMutex.Lock()
	globalMACtoIP = map[string]string{"00:50:56:07:03:01": "10.7.3.1", "00:50:56:07:03:02": "10.7.3.2"}
	collectMACIPSeen["00:50:56:07:03:01"] = hourAgo
	globalMACtoIPMutex.Unlock()
	saveMacIPCache()
	var saved map[string]string // what the previous binary decodes
	decodeJSONFile(t, macIPCacheFile, &saved)
	if want := map[string]string{"00:50:56:07:03:01": "10.7.3.1", "00:50:56:07:03:02": "10.7.3.2"}; !maps.Equal(saved, want) {
		t.Errorf("saved cache %v, want %v", saved, want)
	}
	var seen map[string]int64
	decodeJSONFile(t, sidecar, &seen)
	if want := map[string]int64{"00:50:56:07:03:01": hourAgo.Unix()}; !maps.Equal(seen, want) {
		t.Errorf("saved sidecar %v, want %v", seen, want)
	}

	// Loaded back: the sidecar time, and "just seen" for the entry without one
	collectResetCache(t)
	loadMacIPCache()
	if got := collectCacheMap(); !maps.Equal(got, saved) {
		t.Errorf("loaded %v, want %v", got, saved)
	}
	loadedSeen := func(mac string) time.Time {
		globalMACtoIPMutex.RLock()
		defer globalMACtoIPMutex.RUnlock()
		return collectMACIPSeen[mac]
	}
	if loadedSeen("00:50:56:07:03:01").Unix() != hourAgo.Unix() || !loadedSeen("00:50:56:07:03:02").Equal(now) {
		t.Errorf("loaded seen times %v, %v", loadedSeen("00:50:56:07:03:01"), loadedSeen("00:50:56:07:03:02"))
	}

	// Unreadable or missing sidecar: every entry is just seen
	for name, write := range map[string]func(){
		"unreadable": func() { os.WriteFile(sidecar, []byte("{not json"), 0o644) },
		"missing":    func() { os.Remove(sidecar) },
	} {
		write()
		collectResetCache(t)
		loadMacIPCache()
		if !loadedSeen("00:50:56:07:03:01").Equal(now) || len(collectCacheMap()) != 2 {
			t.Errorf("%s sidecar: seen %v, cache %v", name, loadedSeen("00:50:56:07:03:01"), collectCacheMap())
		}
	}

	// Old and development-build forms, keys canonicalized, Q11 filter
	old := fmt.Sprintf(`{"AA:BB:CC:07:03:05": "10.7.3.5", "01:00:5e:00:00:fb": "10.7.3.6", "00:00:00:12:34:56": "10.7.3.7",
		"00:50:56:07:03:08": "", "not-a-mac": "10.7.3.9", "00:50:56:07:03:0a": "10.7.3.10",
		"00:50:56:07:03:0b": {"ip": "10.7.3.11", "seen": %d}}`, hourAgo.Unix())
	collectResetCache(t)
	globalMACtoIPMutex.Lock()
	globalMACtoIP["00:50:56:07:03:0a"] = "10.7.3.110" // seen in memory: kept
	globalMACtoIPMutex.Unlock()
	if err := os.WriteFile(macIPCacheFile, []byte(old), 0o644); err != nil {
		t.Fatal(err)
	}
	loadMacIPCache()
	if got := collectCacheMap(); !maps.Equal(got, map[string]string{"aa:bb:cc:07:03:05": "10.7.3.5", "00:50:56:07:03:0a": "10.7.3.110", "00:50:56:07:03:0b": "10.7.3.11"}) {
		t.Errorf("loaded old format %v", got)
	}
	if loadedSeen("00:50:56:07:03:0b").Unix() != hourAgo.Unix() {
		t.Errorf("record seen time not kept: %v", loadedSeen("00:50:56:07:03:0b"))
	}
	if got := esxiJobs.taken(); len(got) != 0 {
		t.Errorf("loading the cache queued %d ESXi checks: %v", len(got), got)
	}
}

// decodeJSONFile decodes the JSON file at path into v.
func decodeJSONFile(t *testing.T, path string, v any) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, v); err != nil {
		t.Fatalf("%s: %v\n%s", path, err, data)
	}
}

// TestCollectNoStartupProbeStorm checks F67 at the scale of the real cache:
// loading tens of thousands of entries queues no ESXi check.
func TestCollectNoStartupProbeStorm(t *testing.T) {
	resetState(t)
	collectResetCache(t)
	loadFixture(t)
	macIPCacheFile = filepath.Join(t.TempDir(), "cache.json")
	data, err := json.Marshal(fixture.cache)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(macIPCacheFile, data, 0o644); err != nil {
		t.Fatal(err)
	}
	loadMacIPCache()
	loaded := len(collectCacheMap())
	if loaded < 30000 {
		t.Errorf("loaded only %d of %d fixture entries", loaded, len(fixture.cache))
	}
	if got := esxiJobs.taken(); len(got) != 0 {
		t.Errorf("startup queued %d ESXi checks", len(got))
	}
}

// TestCollectESXiQueueFilter checks which MACs reach the ESXi queue: no
// special or zero-OUI MACs (Q11), no random ones (locally administered
// phone MACs; a 52:54:00 KVM NIC is a VM, never random, so it is probed,
// Q4, MI-7), no MAC without an IP, and no MAC confirmed at the same IP.
func TestCollectESXiQueueFilter(t *testing.T) {
	resetState(t)
	collectResetCache(t)
	ConfirmedESXiMACs.Store("00:50:56:07:04:09", "10.7.4.9")
	ConfirmedESXiMACs.Store("00:50:56:07:04:0a", true)
	for mac, ip := range map[string]string{
		"00:50:56:07:04:01": "10.7.4.1",  // VMware: queued
		"B4-7A-F1-07-04-02": "10.7.4.2",  // HPE, dashes: queued (canonical)
		"01:00:5e:00:00:16": "10.7.4.3",  // multicast
		"ff:ff:ff:ff:ff:ff": "10.7.4.4",  // broadcast
		"00:00:00:07:04:05": "10.7.4.5",  // zero OUI
		"da:a1:19:07:04:06": "10.7.4.6",  // locally administered (random)
		"52:54:00:07:04:07": "10.7.4.7",  // KVM NIC: locally administered, but a VM, never random (Q4): queued (MI-7)
		"00:50:56:07:04:08": "",          // no IP
		"00:50:56:07:04:09": "10.7.4.9",  // confirmed at this IP
		"00:50:56:07:04:0a": "10.7.4.10", // confirmed without a recorded IP
		"desktop-v380chd":   "10.7.4.11",
	} {
		queueESXiValidation(mac, ip)
	}
	queueESXiValidation("00:50:56:07:04:09", "10.7.4.99") // confirmed MAC with a new IP: queued
	want := []string{"00:50:56:07:04:01 10.7.4.1", "00:50:56:07:04:09 10.7.4.99", "52:54:00:07:04:07 10.7.4.7", "b4:7a:f1:07:04:02 10.7.4.2"}
	if got := esxiJobs.taken(); !slices.Equal(got, want) {
		t.Errorf("queued %v, want %v", got, want)
	}

	// The queue filter is the Q11 filter plus "not random" (isRandomMAC): a
	// virtual-NIC OUI is never dropped as random (Q4).
	for mac, want := range map[string]bool{
		"00:50:56:aa:bb:cc": true,  // VMware
		"bc:24:11:00:00:01": true,  // Proxmox
		"52:54:00:12:34:56": true,  // QEMU/KVM default NIC, U/L bit set
		"b4:7a:f1:07:04:02": true,  // HPE server NIC
		"da:a1:19:07:04:06": false, // random phone MAC
		"02:42:ac:11:00:02": false, // locally administered, no virtual-NIC OUI
		"01:00:5e:00:00:16": false, // multicast
		"00:00:00:30:00:00": false, // zero OUI
		"ff:ff:ff:ff:ff:ff": false, // broadcast
		"desktop-v380chd":   false, // no MAC
	} {
		if got := collectESXiCandidate(mac); got != want {
			t.Errorf("collectESXiCandidate(%s) = %v, want %v", mac, got, want)
		}
	}
}

// TestCollectESXiCheck checks the worker side: retry when the host did not
// answer (F65), a verdict per IP, a changed IP checked again and an old
// confirmation cleared by a negative answer (Q18), and jobs dropped when
// the MAC has moved on meanwhile.
func TestCollectESXiCheck(t *testing.T) {
	resetState(t)
	collectResetCache(t)
	now := time.Now()
	const up, down, other = "00:50:56:07:05:01", "00:50:56:07:05:02", "00:50:56:07:05:03"
	collectMergeMACIP([]ARPEntry{{IPAddress: "10.7.5.1", MACAddress: up}, {IPAddress: "10.7.5.2", MACAddress: down}, {IPAddress: "10.7.5.3", MACAddress: other}}, now)
	esxiJobs.taken()

	answering := map[string]bool{"10.7.5.1": true, "10.7.5.3": true, "10.7.5.11": true}
	esxiHosts := map[string]bool{"10.7.5.1": true}
	reachable := func(ip string) bool { return answering[ip] }
	isESXi := func(ip string) bool { return esxiHosts[ip] }
	check := func(mac, ip string, at time.Time) {
		collectCheckESXi(esxiJob{mac: mac, ip: ip}, reachable, isESXi, at)
	}
	confirmedAt := func(mac string) any { v, _ := ConfirmedESXiMACs.Load(mac); return v }

	check(up, "10.7.5.1", now)
	check(down, "10.7.5.2", now)
	check(other, "10.7.5.3", now)
	if v := confirmedAt(up); v != "10.7.5.1" {
		t.Errorf("ESXi host: ConfirmedESXiMACs = %v", v)
	}
	if v := confirmedAt(other); v != nil {
		t.Errorf("non-ESXi host confirmed: %v", v)
	}
	collectESXiMu.Lock()
	retry := collectESXiRetry[down]
	collectESXiMu.Unlock()
	if retry.ip != "10.7.5.2" || retry.tries != 1 || !retry.due.Equal(now.Add(5*time.Minute)) {
		t.Errorf("down host retry = %+v", retry)
	}

	// Nothing is queued again while the verdicts and the retry stand.
	for _, mac := range []string{up, down, other} {
		queueESXiValidation(mac, collectCacheMap()[mac])
	}
	if got := esxiJobs.taken(); len(got) != 0 {
		t.Errorf("queued again: %v", got)
	}

	// The retry pass: not due yet, then due.
	if n := collectRetryESXi(now.Add(time.Minute)); n != 0 {
		t.Errorf("retry before due queued %d", n)
	}
	if n := collectRetryESXi(now.Add(6 * time.Minute)); n != 1 || !slices.Equal(esxiJobs.taken(), []string{down + " 10.7.5.2"}) {
		t.Errorf("due retry not queued (%d)", n)
	}
	// Still down: the next delay doubles. Then it answers as ESXi.
	check(down, "10.7.5.2", now.Add(6*time.Minute))
	collectESXiMu.Lock()
	retry = collectESXiRetry[down]
	collectESXiMu.Unlock()
	if retry.tries != 2 || !retry.due.Equal(now.Add(16*time.Minute)) {
		t.Errorf("second retry = %+v", retry)
	}
	answering["10.7.5.2"], esxiHosts["10.7.5.2"] = true, true
	check(down, "10.7.5.2", now.Add(20*time.Minute))
	collectESXiMu.Lock()
	_, stillRetrying := collectESXiRetry[down]
	collectESXiMu.Unlock()
	if confirmedAt(down) != "10.7.5.2" || stillRetrying {
		t.Errorf("host that came up: confirmed %v, retrying %v", confirmedAt(down), stillRetrying)
	}

	// The confirmed MAC moves to another IP that answers but is not ESXi:
	// queued again, then its confirmation is cleared.
	collectMergeMACIP([]ARPEntry{{IPAddress: "10.7.5.11", MACAddress: up}}, now.Add(30*time.Minute))
	if got := esxiJobs.taken(); !slices.Equal(got, []string{up + " 10.7.5.11"}) {
		t.Errorf("changed IP of a confirmed MAC: queued %v", got)
	}
	check(up, "10.7.5.11", now.Add(31*time.Minute))
	if v := confirmedAt(up); v != nil {
		t.Errorf("confirmation kept after the new IP answered as non-ESXi: %v", v)
	}

	// A job for an IP the MAC no longer has is dropped without a verdict.
	collectMergeMACIP([]ARPEntry{{IPAddress: "10.7.5.13", MACAddress: other}}, now.Add(40*time.Minute))
	esxiJobs.taken()
	esxiHosts["10.7.5.3"] = true
	check(other, "10.7.5.3", now.Add(41*time.Minute))
	if v := confirmedAt(other); v != nil {
		t.Errorf("stale job confirmed the MAC: %v", v)
	}

	// Retries of MACs that expired or moved are forgotten.
	answering["10.7.5.20"] = false
	collectMergeMACIP([]ARPEntry{{IPAddress: "10.7.5.20", MACAddress: "00:50:56:07:05:20"}}, now)
	esxiJobs.taken()
	check("00:50:56:07:05:20", "10.7.5.20", now)
	globalMACtoIPMutex.Lock()
	delete(globalMACtoIP, "00:50:56:07:05:20")
	globalMACtoIPMutex.Unlock()
	collectRetryESXi(now.Add(time.Hour))
	collectESXiMu.Lock()
	_, kept := collectESXiRetry["00:50:56:07:05:20"]
	collectESXiMu.Unlock()
	if kept || len(esxiJobs.taken()) != 0 {
		t.Error("retry of an expired mapping was kept or queued")
	}
}

// TestCollectESXiWarmup checks the paced check of cached MACs (F67): each
// sweep queues a bounded batch of cached MACs that are in a switch FDB and
// have no verdict yet, so hosts whose ARP entry no answering router has keep
// being confirmed, without the startup burst. A cached IP claimed by two
// MACs is not probed (the verdict could go to the wrong MAC, F64).
func TestCollectESXiWarmup(t *testing.T) {
	resetState(t)
	collectResetCache(t)
	const a, b, c, d, e, f, g = "00:50:56:07:09:01", "00:50:56:07:09:02", "00:50:56:07:09:03",
		"00:50:56:07:09:04", "da:a1:19:07:09:05", "00:50:56:07:09:06", "00:50:56:07:09:07"
	collectedDataMutex.Lock()
	collectedData = map[string]*DeviceData{"10.9.9.1": {IP: "10.9.9.1",
		MACTable: macEntries(3, a, b, c, d, e, "00:50:56:07:09:07")}}
	collectedDataMutex.Unlock()
	globalMACtoIPMutex.Lock()
	globalMACtoIP = map[string]string{
		a: "10.7.9.1", // in the FDB, unique IP: probed
		b: "10.7.9.2", // b and c claim the same IP: neither is probed
		c: "10.7.9.2",
		d: "10.7.9.4", // already checked at this IP
		e: "10.7.9.5", // locally administered
		f: "10.7.9.6", // not in any FDB
		g: "10.7.9.7", // in the FDB, unique IP: probed
	}
	globalMACtoIPMutex.Unlock()
	collectESXiMu.Lock()
	collectESXiChecked[d] = "10.7.9.4"
	collectESXiMu.Unlock()

	saved := collectESXiWarmupBatch
	collectESXiWarmupBatch = 1
	t.Cleanup(func() { collectESXiWarmupBatch = saved })
	if n := collectWarmupESXi(); n != 1 || !slices.Equal(esxiJobs.taken(), []string{a + " 10.7.9.1"}) {
		t.Fatalf("first batch queued %d", n)
	}
	// a got its verdict; the next sweep takes the next MAC.
	collectCheckESXi(esxiJob{mac: a, ip: "10.7.9.1"}, func(string) bool { return true }, func(string) bool { return false }, time.Now())
	if n := collectWarmupESXi(); n != 1 || !slices.Equal(esxiJobs.taken(), []string{g + " 10.7.9.7"}) {
		t.Fatalf("second batch queued %d", n)
	}
	collectCheckESXi(esxiJob{mac: g, ip: "10.7.9.7"}, func(string) bool { return true }, func(string) bool { return true }, time.Now())
	if n := collectWarmupESXi(); n != 0 || len(esxiJobs.taken()) != 0 {
		t.Errorf("nothing left to warm up, but %d queued", n)
	}
	if v, _ := ConfirmedESXiMACs.Load(g); v != "10.7.9.7" {
		t.Errorf("warmed-up ESXi host not confirmed: %v", v)
	}
}

// TestCollectESXiRetryDelay pins the retry schedule.
func TestCollectESXiRetryDelay(t *testing.T) {
	for tries, want := range map[int]time.Duration{
		1: 5 * time.Minute, 2: 10 * time.Minute, 3: 20 * time.Minute, 6: 160 * time.Minute,
		7: 320 * time.Minute, 8: 6 * time.Hour, 50: 6 * time.Hour,
	} {
		if got := collectESXiRetryDelay(tries); got != want {
			t.Errorf("collectESXiRetryDelay(%d) = %v, want %v", tries, got, want)
		}
	}
}

// TestCollectESXiClaim checks that a MAC/IP is queued to the workers once
// until it has been checked.
func TestCollectESXiClaim(t *testing.T) {
	resetState(t)
	collectResetCache(t)
	job := esxiJob{mac: "00:50:56:07:06:01", ip: "10.7.6.1"}
	if !collectClaimESXi(job) || collectClaimESXi(job) {
		t.Error("the same job was claimed twice")
	}
	if !collectClaimESXi(esxiJob{mac: job.mac, ip: "10.7.6.2"}) {
		t.Error("a new IP of the MAC was not claimed")
	}
	collectReleaseESXi(esxiJob{mac: job.mac, ip: "10.7.6.2"})
	if !collectClaimESXi(job) {
		t.Error("released job could not be claimed again")
	}
}

// collectFakeTransport answers HTTPS requests from canned responses, so the
// probe's HTTP handling is tested without sockets.
type collectFakeTransport struct {
	pages     map[string]*http.Response // "host/path" → response
	requested []string
}

func (f *collectFakeTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	key := req.URL.Host + req.URL.Path
	f.requested = append(f.requested, key)
	page, ok := f.pages[key]
	if !ok {
		return nil, errors.New("fake: connection refused")
	}
	resp := *page
	resp.Request = req
	resp.Body = io.NopCloser(strings.NewReader(page.Header.Get("X-Body")))
	return &resp, nil
}

func collectFakePage(status int, body, location string) *http.Response {
	h := http.Header{"X-Body": {body}}
	if location != "" {
		h.Set("Location", location)
	}
	return &http.Response{StatusCode: status, Header: h}
}

// TestCollectESXiFingerprint checks F66: only an HTTP 200 /ui/ page from the
// probed host with the ESXi host client app counts. A 404 page or a page on
// another host that mentions "VMware ESXi" does not.
func TestCollectESXiFingerprint(t *testing.T) {
	const app = `<html lang="en" ng-app="esxUiApp" ng-strict-di><title>ESXi</title></html>`
	fake := &collectFakeTransport{pages: map[string]*http.Response{
		"10.7.8.1/ui/":           collectFakePage(200, app, ""),
		"10.7.8.2/ui/":           collectFakePage(404, "Not Found. Supported: VMware ESXi 7", ""),
		"10.7.8.3/ui/":           collectFakePage(302, "", "https://10.7.8.33/portal"),
		"10.7.8.33/portal":       collectFakePage(200, app+" 12 VMware ESXi hosts registered", ""),
		"10.7.8.4/ui/":           collectFakePage(302, "", "/ui/index.html"),
		"10.7.8.4/ui/index.html": collectFakePage(200, app, ""),
		"10.7.8.5/ui/":           collectFakePage(200, "<title>VMware ESXi</title>", ""),
		"10.7.8.7/ui/":           collectFakePage(500, app, ""),
	}}
	client := newESXiClient(fake)
	for ip, want := range map[string]bool{
		"10.7.8.1": true,  // the host client
		"10.7.8.2": false, // 404 that mentions ESXi
		"10.7.8.3": false, // redirect to another host's page
		"10.7.8.4": true,  // redirect on the same host
		"10.7.8.5": false, // the phrase without the host client app
		"10.7.8.6": false, // no answer
		"10.7.8.7": false, // server error
	} {
		if got := probeESXiHost(client, ip); got != want {
			t.Errorf("probeESXiHost(%s) = %v, want %v", ip, got, want)
		}
	}
	if slices.Contains(fake.requested, "10.7.8.33/portal") {
		t.Error("the probe followed a redirect to another host")
	}
	for body, want := range map[string]bool{
		app:                          true,
		"<title>VMware ESXi</title>": false,
		"Blog post: how to install VMware ESXi at home": false,
		"": false,
	} {
		if got := isESXiResponse(body); got != want {
			t.Errorf("isESXiResponse(%q) = %v, want %v", body, got, want)
		}
	}
}
