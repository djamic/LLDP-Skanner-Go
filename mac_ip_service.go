package main

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// ─── ESXi HTTP Fingerprinting ──────────────────────────────────────────────────

// ConfirmedESXiMACs holds the MACs whose IP answered as an ESXi host. The
// value is that IP (readers only test presence).
var ConfirmedESXiMACs sync.Map
var validationQueue = make(chan esxiJob, 2000)

type esxiJob struct {
	mac string
	ip  string
}

func init() {
	// Start 100 background workers for fast LAN ESXi HTTP fingerprinting
	for i := 0; i < 100; i++ {
		go esxiCheckWorker()
	}
}

func esxiCheckWorker() {
	client := newESXiClient(&http.Transport{
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
		DisableKeepAlives:     true,
		ResponseHeaderTimeout: 1 * time.Second,
	})
	runESXiWorker(validationQueue, collectESXiReachable, func(ip string) bool { return esxiProbe(client, ip) })
}

// newESXiClient returns the HTTP client of an ESXi check worker, which sends
// its requests through transport and follows redirects on the probed host
// only (collectESXiSameHost).
func newESXiClient(transport http.RoundTripper) *http.Client {
	return &http.Client{
		Timeout:       2 * time.Second,
		Transport:     transport,
		CheckRedirect: collectESXiSameHost,
	}
}

// runESXiWorker checks the MAC and IP of every job it receives
// (collectCheckESXi): a host that does not accept :443 (reachable) is
// retried later, a host that answers gets the verdict of isESXi for that IP.
func runESXiWorker(jobs <-chan esxiJob, reachable, isESXi func(ip string) bool) {
	for job := range jobs {
		collectCheckESXi(job, reachable, isESXi, macIPClock())
		collectReleaseESXi(job)
	}
}

// Test seams: esxiProbe checks one IP over HTTPS and esxiEnqueue hands a job
// to the workers. Tests replace both so nothing is queued or probed.
var (
	esxiProbe   = probeESXiHost
	esxiEnqueue = enqueueESXiJob
)

// collectESXiSameHost stops at a redirect to another host: a portal or
// vCenter page that mentions ESXi is not the probed host's own UI (F66).
func collectESXiSameHost(req *http.Request, via []*http.Request) error {
	if len(via) >= 3 || req.URL.Hostname() != via[0].URL.Hostname() {
		return http.ErrUseLastResponse
	}
	return nil
}

// collectESXiReachable reports whether ip accepts TCP on port 443 (500ms is
// plenty for the local network).
func collectESXiReachable(ip string) bool {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, "443"), 500*time.Millisecond)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// probeESXiHost reports whether https://ip/ui/ is the ESXi host client: an
// HTTP 200 page from that host with the host client's app (isESXiResponse).
// Error pages and other hosts' pages that mention ESXi do not count (F66).
// The TCP :443 check comes before it (collectESXiReachable).
func probeESXiHost(client *http.Client, ip string) bool {
	resp, err := client.Get("https://" + ip + "/ui/")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.Request.URL.Hostname() != ip {
		return false
	}
	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return isESXiResponse(string(bodyBytes))
}

// isESXiResponse is the ESXi fingerprint applied to the /ui/ response body:
// the Angular app of the ESXi host client. The bare phrase "VMware ESXi" is
// not enough (404 pages, blogs, inventory portals, F66).
func isESXiResponse(body string) bool {
	return strings.Contains(body, "esxUiApp")
}

// ESXi check bookkeeping (guarded by collectESXiMu; never held together
// with globalMACtoIPMutex).
var (
	collectESXiMu       sync.Mutex
	collectESXiChecked  = make(map[string]string)              // MAC → IP that answered (ESXi or not)
	collectESXiRetry    = make(map[string]collectESXiRetryJob) // MAC → check to retry: the host did not answer
	collectESXiInflight = make(map[string]string)              // MAC → IP queued and not checked yet
)

// collectESXiRetryJob is a check whose host did not answer on :443.
type collectESXiRetryJob struct {
	ip    string
	due   time.Time
	tries int
}

// collectESXiCandidate reports whether mac can be an ESXi host NIC worth a
// probe: a usable MAC (Q11) that is not random (isRandomMAC). Randomized
// phone and laptop MACs (locally administered, 24,978 of the 37,110 cache
// entries) are never the management NIC of an ESXi host, so they are not
// probed (F67). A virtual-NIC OUI is a VM and never random (Q4), so a
// 52:54:00 QEMU/KVM NIC, whose U/L bit is set, is probed like the other VM
// NICs: a nested ESXi host on KVM has one (MI-7).
func collectESXiCandidate(mac string) bool {
	return usableMAC(mac) != "" && !isRandomMAC(mac)
}

// queueESXiValidation asks the workers whether ip, the MAC's current IP, is
// an ESXi host. It skips MACs that cannot be one (collectESXiCandidate),
// MACs confirmed or checked at this IP, and MACs waiting for a retry at this
// IP (collectRetryESXi queues those). A changed IP is checked again (Q18).
func queueESXiValidation(mac, ip string) {
	mac = canonicalMAC(mac)
	if collectESXiWanted(mac, ip) {
		esxiEnqueue(esxiJob{mac: mac, ip: ip})
	}
}

// collectESXiWanted reports whether the canonical mac at ip needs an ESXi
// check (see queueESXiValidation).
func collectESXiWanted(mac, ip string) bool {
	if ip == "" || !collectESXiCandidate(mac) {
		return false
	}
	// true: confirmed by code that did not record the IP
	if confirmed, ok := ConfirmedESXiMACs.Load(mac); ok && (confirmed == ip || confirmed == true) {
		return false
	}
	collectESXiMu.Lock()
	defer collectESXiMu.Unlock()
	retry, waiting := collectESXiRetry[mac]
	return collectESXiChecked[mac] != ip && !(waiting && retry.ip == ip)
}

// collectESXiWarmupBatch is how many cached MACs one ARP sweep queues for
// the ESXi check besides the MACs it observed (F67: loading the cache no
// longer queues all of it at once).
var collectESXiWarmupBatch = 500

// collectWarmupESXi queues the ESXi check for cached MACs that no sweep
// observed, at most collectESXiWarmupBatch per call (in MAC order): MACs in
// a switch FDB (on the network now) that have no verdict for their cached IP
// and whose IP no other cached MAC claims (with two claimants the verdict
// could go to the wrong MAC, F64). Hosts whose ARP entry is only on routers
// that do not answer SNMP keep being confirmed this way. Returns the jobs
// queued.
func collectWarmupESXi() int {
	collectedDataMutex.RLock()
	active := make(map[string]bool)
	for _, d := range collectedData {
		for _, e := range d.MACTable {
			active[canonicalMAC(e.MACAddress)] = true
		}
	}
	collectedDataMutex.RUnlock()

	globalMACtoIPMutex.RLock()
	claims := make(map[string]int, len(globalMACtoIP))
	for _, ip := range globalMACtoIP {
		claims[ip]++
	}
	var jobs []esxiJob
	for mac, ip := range globalMACtoIP {
		if active[mac] && claims[ip] == 1 {
			jobs = append(jobs, esxiJob{mac: mac, ip: ip})
		}
	}
	globalMACtoIPMutex.RUnlock()

	slices.SortFunc(jobs, func(a, b esxiJob) int { return strings.Compare(a.mac, b.mac) })
	queued := 0
	for _, job := range jobs {
		if queued >= collectESXiWarmupBatch {
			break
		}
		if collectESXiWanted(job.mac, job.ip) {
			esxiEnqueue(job)
			queued++
		}
	}
	return queued
}

// enqueueESXiJob sends a job to the validation workers without blocking. A
// MAC already queued for the same IP is not queued again, and when the queue
// is full the job is dropped: the MAC still has no verdict, so a later ARP
// sweep queues it again. (A goroutine per overflow job used to park about
// 35k goroutines at startup, F67.)
func enqueueESXiJob(job esxiJob) {
	if !collectClaimESXi(job) {
		return
	}
	select {
	case validationQueue <- job:
		// sent successfully
	default:
		collectReleaseESXi(job)
	}
}

// collectClaimESXi marks job as queued; false when it already is.
func collectClaimESXi(job esxiJob) bool {
	collectESXiMu.Lock()
	defer collectESXiMu.Unlock()
	if collectESXiInflight[job.mac] == job.ip {
		return false
	}
	collectESXiInflight[job.mac] = job.ip
	return true
}

// collectReleaseESXi ends the queued mark of job.
func collectReleaseESXi(job esxiJob) {
	collectESXiMu.Lock()
	defer collectESXiMu.Unlock()
	if collectESXiInflight[job.mac] == job.ip {
		delete(collectESXiInflight, job.mac)
	}
}

// collectCheckESXi checks one queued MAC/IP and records the verdict. A job
// whose MAC has another IP by now (or none) is dropped. A host that does not
// accept :443 is retried later with a growing delay (F65: it used to be
// checked once only). A host that answers gets a verdict for that IP: ESXi
// (ConfirmedESXiMACs) or not, which also clears a confirmation made at an
// older IP of the MAC (Q18).
func collectCheckESXi(job esxiJob, reachable, isESXi func(ip string) bool, now time.Time) {
	if !collectMACIPCurrent(job.mac, job.ip) {
		return
	}
	if !reachable(job.ip) {
		collectESXiMu.Lock()
		retry := collectESXiRetry[job.mac]
		if retry.ip != job.ip {
			retry = collectESXiRetryJob{ip: job.ip}
		}
		retry.tries++
		retry.due = now.Add(collectESXiRetryDelay(retry.tries))
		collectESXiRetry[job.mac] = retry
		collectESXiMu.Unlock()
		return
	}
	confirmed := isESXi(job.ip)
	collectESXiMu.Lock()
	collectESXiChecked[job.mac] = job.ip
	delete(collectESXiRetry, job.mac)
	collectESXiMu.Unlock()
	if !confirmed {
		ConfirmedESXiMACs.Delete(job.mac)
		return
	}
	if previous, _ := ConfirmedESXiMACs.Swap(job.mac, job.ip); previous != job.ip {
		fmt.Printf("✅ [Active-Check] Confirmed ESXi via HTTP: %s (MAC: %s)\n", job.ip, job.mac)
	}
}

// collectESXiRetryDelay is the wait before retry n of a host that did not
// answer: 5 minutes, doubled per try, at most 6 hours.
func collectESXiRetryDelay(tries int) time.Duration {
	delay := 5 * time.Minute
	for i := 1; i < tries && delay < 6*time.Hour; i++ {
		delay *= 2
	}
	if delay > 6*time.Hour {
		delay = 6 * time.Hour
	}
	return delay
}

// collectRetryESXi queues again the checks whose host did not answer, once
// their retry time has come, and forgets the ones whose MAC has another IP
// now (or none). Called after every ARP sweep. Returns the jobs queued.
func collectRetryESXi(now time.Time) int {
	collectESXiMu.Lock()
	retries := maps.Clone(collectESXiRetry)
	collectESXiMu.Unlock()

	queued := 0
	for _, mac := range slices.Sorted(maps.Keys(retries)) {
		retry := retries[mac]
		if !collectMACIPCurrent(mac, retry.ip) {
			collectESXiMu.Lock()
			if current, ok := collectESXiRetry[mac]; ok && current.ip == retry.ip {
				delete(collectESXiRetry, mac)
			}
			collectESXiMu.Unlock()
			continue
		}
		if now.Before(retry.due) {
			continue
		}
		esxiEnqueue(esxiJob{mac: mac, ip: retry.ip})
		queued++
	}
	return queued
}

// ─── MAC-IP Cache ──────────────────────────────────────────────────────────────

// macIPCacheFile is the persistent JSON cache path (a variable so tests can
// use a temporary file)
var macIPCacheFile = "mac_ip_cache.json"

// macIPServiceMu protects macIPServiceRunning flag
var macIPServiceRunning bool
var macIPServiceMu sync.Mutex

// collectMACIPSeen holds when each globalMACtoIP entry was last seen in an
// ARP table (guarded by globalMACtoIPMutex). It is saved in a sidecar file
// next to the cache (macIPSeenFile). An entry without a time (no sidecar, or
// put there by other code) counts as just seen.
var collectMACIPSeen = make(map[string]time.Time)

// macIPGatewayOK is when an ARP walk of the gateway last returned rows in
// this run (guarded by globalMACtoIPMutex); zero while the gateway has not
// answered. Cache entries expire only against it (collectPruneMACIP).
var macIPGatewayOK time.Time

// macIPGatewayWarned is set once the gateway ARP warning was printed: one
// warning per start, not one per sweep.
var macIPGatewayWarned atomic.Bool

// macIPClock is the time source of the MAC-IP cache (last-seen times, TTL)
// and of the ESXi check retries. Tests replace it with a clock they control.
var macIPClock = time.Now

// collectMACIPTTL: an entry the gateway's ARP table has not shown for this
// long is dropped (Q18), so old IPs stop labelling nodes and feeding the
// ESXi probe.
var collectMACIPTTL = 7 * 24 * time.Hour

// collectMACIPRecord is a cache entry in the {"ip", "seen"} form a
// development build wrote; it still loads. mac_ip_cache.json itself keeps
// the "mac": "ip" form older binaries read, and the last-seen times go to
// the sidecar file (macIPSeenFile).
type collectMACIPRecord struct {
	IP   string `json:"ip"`
	Seen int64  `json:"seen,omitempty"`
}

// macIPSeenFile is the sidecar of the cache file: the last-seen time of
// each MAC in Unix seconds ("mac_ip_cache_seen.json" next to
// "mac_ip_cache.json").
func macIPSeenFile() string {
	return strings.TrimSuffix(macIPCacheFile, filepath.Ext(macIPCacheFile)) + "_seen.json"
}

// recordGatewayARP notes an ARP walk of the gateway ip at time now: rows
// mean it answered (cache entries may expire against this walk); no rows,
// from an error or an empty table, print the one warning of this run.
func recordGatewayARP(ip string, rows int, err error, now time.Time) {
	if rows > 0 {
		globalMACtoIPMutex.Lock()
		if now.After(macIPGatewayOK) {
			macIPGatewayOK = now
		}
		globalMACtoIPMutex.Unlock()
		return
	}
	if !macIPGatewayWarned.CompareAndSwap(false, true) {
		return
	}
	reason := "empty ARP table"
	if err != nil {
		reason = err.Error()
	}
	fmt.Printf("⚠️ [MacIPService] Gateway %s did not answer the SNMP ARP walk (%s). IPs only the gateway knows are not refreshed, and no MAC-IP cache entry expires until %s answers (SNMP read access to ipNetToMediaPhysAddress and ipAddrTable).\n", ip, reason, ip)
}

// collectMACIPCurrent reports whether globalMACtoIP maps mac to ip.
func collectMACIPCurrent(mac, ip string) bool {
	globalMACtoIPMutex.RLock()
	defer globalMACtoIPMutex.RUnlock()
	current, ok := globalMACtoIP[mac]
	return ok && current == ip
}

// collectMergeMACIP records ARP observations in globalMACtoIP. Every ARP
// collector uses it (F70): the last observation wins (Q18; it used to be
// the first, so IPs never changed), only usable MACs and IPv4 addresses are
// kept (Q11), each observed mapping is marked seen now, and the ESXi check
// is asked for it (queueESXiValidation skips what was already checked at
// that IP, so only new and changed IPs reach the probe). It returns the
// number of new and of changed mappings.
func collectMergeMACIP(entries []ARPEntry, now time.Time) (added, changed int) {
	var jobs []esxiJob
	globalMACtoIPMutex.Lock()
	for _, e := range entries {
		mac := usableMAC(e.MACAddress)
		if mac == "" || parseIPv4(e.IPAddress) == "" {
			continue
		}
		switch old, exists := globalMACtoIP[mac]; {
		case !exists:
			added++
		case old != e.IPAddress:
			changed++
		}
		globalMACtoIP[mac] = e.IPAddress
		collectMACIPSeen[mac] = now
		jobs = append(jobs, esxiJob{mac: mac, ip: e.IPAddress})
	}
	globalMACtoIPMutex.Unlock()
	for _, job := range jobs {
		queueESXiValidation(job.mac, job.ip)
	}
	return added, changed
}

// collectPruneMACIP drops the globalMACtoIP entries whose last sighting is
// more than the TTL before the last successful gateway ARP walk
// (macIPGatewayOK): the gateway's table holds the ARP entry of every host,
// so only a gateway walk that has not shown a MAC for the whole TTL says it
// is gone, while switch ARP tables cover few hosts. Without a successful
// gateway walk in this run nothing expires. Entries without a time count as
// seen now, and times of MACs without an entry are forgotten. Returns the
// number of entries dropped.
func collectPruneMACIP(now time.Time) int {
	globalMACtoIPMutex.Lock()
	defer globalMACtoIPMutex.Unlock()
	dropped := 0
	for mac := range globalMACtoIP {
		seen, known := collectMACIPSeen[mac]
		switch {
		case !known:
			collectMACIPSeen[mac] = now
		case !macIPGatewayOK.IsZero() && macIPGatewayOK.After(seen.Add(collectMACIPTTL)):
			delete(globalMACtoIP, mac)
			delete(collectMACIPSeen, mac)
			dropped++
		}
	}
	for mac := range collectMACIPSeen {
		if _, ok := globalMACtoIP[mac]; !ok {
			delete(collectMACIPSeen, mac)
		}
	}
	return dropped
}

// loadMacIPCache loads mac→ip mappings from JSON file into globalMACtoIP,
// with their last-seen times from the sidecar file; when the sidecar is
// missing or unreadable, or has no time for a MAC, the entry counts as just
// seen. Keys are canonicalized, unusable MACs (Q11) and empty IPs are
// skipped, and entries already in memory are kept (they are at least as
// fresh). Nothing expires here (collectPruneMACIP). Nothing is queued for
// the ESXi check: the ARP sweeps queue the MACs they actually see (F67: the
// whole cache, ~36.8k :443 dials, was queued at every start).
func loadMacIPCache() {
	data, err := os.ReadFile(macIPCacheFile)
	if err != nil {
		// File doesn't exist yet — not an error
		return
	}
	var cache map[string]json.RawMessage
	if err := json.Unmarshal(data, &cache); err != nil {
		fmt.Printf("⚠️ [MacIPService] Failed to parse %s: %v\n", macIPCacheFile, err)
		return
	}
	seenTimes := loadMacIPSeen()
	now := macIPClock()
	globalMACtoIPMutex.Lock()
	loaded := 0
	for key, raw := range cache {
		var rec collectMACIPRecord
		if json.Unmarshal(raw, &rec.IP) != nil && json.Unmarshal(raw, &rec) != nil {
			continue
		}
		mac := usableMAC(key)
		if mac == "" || parseIPv4(rec.IP) == "" {
			continue
		}
		if _, exists := globalMACtoIP[mac]; exists {
			continue
		}
		globalMACtoIP[mac] = rec.IP
		switch seen, ok := seenTimes[mac]; {
		case ok:
			collectMACIPSeen[mac] = seen
		case rec.Seen > 0:
			collectMACIPSeen[mac] = time.Unix(rec.Seen, 0)
		default:
			collectMACIPSeen[mac] = now
		}
		loaded++
	}
	globalMACtoIPMutex.Unlock()
	fmt.Printf("📂 [MacIPService] Loaded %d MAC-IP entries from cache\n", loaded)
}

// loadMacIPSeen reads the sidecar file's last-seen times by canonical MAC;
// nil when it is missing or unreadable.
func loadMacIPSeen() map[string]time.Time {
	data, err := os.ReadFile(macIPSeenFile())
	if err != nil {
		return nil
	}
	var raw map[string]int64
	if err := json.Unmarshal(data, &raw); err != nil {
		fmt.Printf("⚠️ [MacIPService] Ignoring %s (%v): every cached entry counts as just seen\n", macIPSeenFile(), err)
		return nil
	}
	seen := make(map[string]time.Time, len(raw))
	for key, unix := range raw {
		if mac := canonicalMAC(key); mac != "" && unix > 0 {
			seen[mac] = time.Unix(unix, 0)
		}
	}
	return seen
}

// saveMacIPCache saves globalMACtoIP to JSON file atomically, as the plain
// "mac": "ip" map older binaries read too, and the last-seen times to the
// sidecar file (macIPSeenFile).
func saveMacIPCache() {
	globalMACtoIPMutex.RLock()
	snapshot := maps.Clone(globalMACtoIP)
	seen := make(map[string]int64, len(snapshot))
	for mac := range snapshot {
		if t, ok := collectMACIPSeen[mac]; ok {
			seen[mac] = t.Unix()
		}
	}
	globalMACtoIPMutex.RUnlock()

	if writeJSONAtomic(macIPCacheFile, snapshot) {
		writeJSONAtomic(macIPSeenFile(), seen)
	}
}

// writeJSONAtomic writes v as indented JSON to path through a temporary
// file and a rename (writeFileReplacing); false when it could not be
// written.
func writeJSONAtomic(path string, v any) bool {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return false
	}
	if err := writeFileReplacing(path, data, os.Rename); err != nil {
		fmt.Printf("⚠️ [MacIPService] Cannot write %s: %v\n", path, err)
		return false
	}
	return true
}

// writeFileReplacing writes data to path through path+".tmp" and rename, so
// a reader never sees a half-written file. When path is a mount point the
// rename fails with EBUSY (EXDEV across file systems): docker-compose.yml
// bind-mounts mac_ip_cache.json as a single file, and the cache was never
// updated in the container. The file is then rewritten in place, which is
// not atomic but keeps it current (RC-5). The temporary file never stays
// behind. rename is os.Rename; tests pass a failing one.
func writeFileReplacing(path string, data []byte, rename func(oldpath, newpath string) error) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		os.Remove(tmp)
		return err
	}
	err := rename(tmp, path)
	if err == nil {
		return nil
	}
	os.Remove(tmp)
	if errors.Is(err, syscall.EBUSY) || errors.Is(err, syscall.EXDEV) {
		return os.WriteFile(path, data, 0644)
	}
	return err
}

// ─── ARP Collection from all switches ─────────────────────────────────────────

// collectARPFromSwitch collects ARP table from a single switch IP and
// merges results into globalMACtoIP. Returns number of new or changed entries.
func collectARPFromSwitch(snmpObj *SNMPObject, ip string) int {
	updated, _, _ := collectARPMerge(snmpObj, ip)
	return updated
}

// collectARPMerge merges the ARP table of ip into globalMACtoIP and returns
// the number of new or changed mappings and of ARP rows read, and the walk
// error.
func collectARPMerge(snmpObj *SNMPObject, ip string) (updated, rows int, err error) {
	entries, err := snmpObj.collectARPTable(ip)
	if err != nil {
		return 0, 0, err
	}
	added, changed := collectMergeMACIP(entries, macIPClock())
	return added + changed, len(entries), nil
}

// collectARPFromAllSwitches collects ARP from gateway (all SVI IPs) + all discovered switches
func collectARPFromAllSwitches() {
	snmpObj := &SNMPObject{
		Community: "public",
		Port:      161,
		Timeout:   10 * time.Second,
		Retries:   1,
	}

	totalNew := 0
	totalRows := 0

	// 1. Gateway — collect from its own IP first. Only its answer lets
	// cache entries expire (collectPruneMACIP).
	n, rows, err := collectARPMerge(snmpObj, gatewayIP)
	recordGatewayARP(gatewayIP, rows, err, macIPClock())
	totalRows += rows
	if n > 0 {
		fmt.Printf("🌐 [MacIPService] Gateway %s: +%d new/changed MAC-IP entries\n", gatewayIP, n)
		totalNew += n
	}

	// 2. Gateway SVI IPs — gateway may route multiple VLANs (172.20.x.x, 10.20.x.x...)
	//    Query ipAddrTable to find all its interface IPs and collect ARP from each
	sviIPs := collectGatewaySVIIPs(snmpObj, gatewayIP)
	for _, svi := range sviIPs {
		if svi == gatewayIP {
			continue // already done above
		}
		n, rows, _ := collectARPMerge(snmpObj, svi)
		totalRows += rows
		if n > 0 {
			fmt.Printf("🌐 [MacIPService] Gateway SVI %s: +%d new/changed MAC-IP entries\n", svi, n)
			totalNew += n
		}
	}

	// 3. All discovered switches
	collectedDataMutex.RLock()
	switchIPs := make([]string, 0, len(collectedData))
	for ip := range collectedData {
		if ip != gatewayIP {
			switchIPs = append(switchIPs, ip)
		}
	}
	collectedDataMutex.RUnlock()

	for _, ip := range switchIPs {
		n, rows, _ := collectARPMerge(snmpObj, ip)
		totalRows += rows
		if n > 0 {
			fmt.Printf("🔗 [MacIPService] Switch %s: +%d new/changed MAC-IP entries\n", ip, n)
			totalNew += n
		}
	}

	// Drop entries the gateway has not shown for the TTL (Q18). The cache is
	// saved after every sweep that read ARP rows, so the last-seen times
	// survive a restart.
	now := macIPClock()
	dropped := collectPruneMACIP(now)
	if totalNew > 0 || dropped > 0 {
		fmt.Printf("✅ [MacIPService] New/changed: %d, expired: %d entries. Saving cache...\n", totalNew, dropped)
	}
	if totalRows > 0 || dropped > 0 {
		saveMacIPCache()
		// Note: IP enrichment happens automatically during rebuildGraph()
	}

	// Retry the ESXi checks whose host did not answer (F65), and check the
	// next batch of cached MACs that no sweep observes (F67)
	collectRetryESXi(now)
	collectWarmupESXi()
}

// collectGatewaySVIIPs returns all IP addresses configured on the gateway device.
// Uses ipAddrTable (.1.3.6.1.2.1.4.20.1.2) — returns interface addresses (SVI/VLAN IPs).
// This allows ARP collection from each routed VLAN interface.
func collectGatewaySVIIPs(snmpObj *SNMPObject, gwIP string) []string {
	lines, err := snmpObj.runSNMPWalk(gwIP, ".1.3.6.1.2.1.4.20.1.2")
	if err != nil {
		return []string{gwIP}
	}
	ips := []string{gwIP}
	seen := map[string]bool{gwIP: true}
	for _, line := range lines {
		// OID: .1.3.6.1.2.1.4.20.1.2.<ip1>.<ip2>.<ip3>.<ip4> = ifIndex
		// IP is in the OID itself
		oid, _, err := parseSNMPLine(line)
		if err != nil {
			continue
		}
		parts := strings.Split(oid, ".")
		if len(parts) < 4 {
			continue
		}
		// Last 4 parts of OID are the IP octets
		ipStr := strings.Join(parts[len(parts)-4:], ".")
		if net := parseIPv4(ipStr); net != "" && !seen[net] {
			// Skip link-local, loopback, multicast
			if !strings.HasPrefix(net, "127.") &&
				!strings.HasPrefix(net, "169.254.") &&
				!strings.HasPrefix(net, "224.") &&
				net != "0.0.0.0" {
				ips = append(ips, net)
				seen[net] = true
				fmt.Printf("📡 [MacIPService] Found gateway SVI IP: %s\n", net)
			}
		}
	}
	return ips
}

// parseIPv4 validates and returns an IPv4 string, or empty string if invalid.
func parseIPv4(s string) string {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return ""
	}
	for _, p := range parts {
		if len(p) == 0 || len(p) > 3 {
			return ""
		}
		for _, c := range p {
			if c < '0' || c > '9' {
				return ""
			}
		}
	}
	return s
}

// ─── Gateway Subnet Discovery ──────────────────────────────────────────────────

// SubnetInfo holds IP + prefix length from gateway ipAddr table
type SubnetInfo struct {
	IP     string
	Prefix int
	Net    string // network address e.g. "172.20.0.0"
}

// discoverGatewaySubnets reads gateway ipAddrTable + netmask, returns all subnets
func discoverGatewaySubnets(snmpObj *SNMPObject, gwIP string) []SubnetInfo {
	// Get IP list from ipAddrTable (.1.3.6.1.2.1.4.20.1.1)
	maskLines, err := snmpObj.runSNMPWalk(gwIP, ".1.3.6.1.2.1.4.20.1.3")
	if err != nil {
		return nil
	}
	var subnets []SubnetInfo
	for _, line := range maskLines {
		oid, val, err := parseSNMPLine(line)
		if err != nil {
			continue
		}
		parts := strings.Split(oid, ".")
		if len(parts) < 4 {
			continue
		}
		ipStr := strings.Join(parts[len(parts)-4:], ".")
		if parseIPv4(ipStr) == "" {
			continue
		}
		// Skip loopback
		if strings.HasPrefix(ipStr, "127.") {
			continue
		}
		maskStr := strings.TrimSpace(val)
		// Count prefix bits
		bits := 0
		for _, oct := range strings.Split(maskStr, ".") {
			var n int
			fmt.Sscanf(oct, "%d", &n)
			bits += countBits(n)
		}
		// Compute network address
		ipParts := strings.Split(ipStr, ".")
		maskParts := strings.Split(maskStr, ".")
		if len(ipParts) != 4 || len(maskParts) != 4 {
			continue
		}
		netParts := make([]string, 4)
		for i := 0; i < 4; i++ {
			var a, b int
			fmt.Sscanf(ipParts[i], "%d", &a)
			fmt.Sscanf(maskParts[i], "%d", &b)
			netParts[i] = fmt.Sprintf("%d", a&b)
		}
		netStr := strings.Join(netParts, ".")
		subnets = append(subnets, SubnetInfo{IP: ipStr, Prefix: bits, Net: netStr})
		fmt.Printf("📡 [SubnetDisc] Found subnet: %s/%d (gateway SVI: %s)\n", netStr, bits, ipStr)
	}
	return subnets
}

// countBits counts set bits in an integer (for mask)
func countBits(n int) int {
	count := 0
	for n > 0 {
		count += n & 1
		n >>= 1
	}
	return count
}

// probeSubnetForSwitches probes a subnet for SNMP-capable devices.
// For small subnets (/22 or less = ≤1022 hosts), scans all IPs.
// For large subnets, only probes IPs known from ARP cache.
func probeSubnetForSwitches(snmpObj *SNMPObject, subnet SubnetInfo) []string {
	var newSwitchIPs []string

	// Get existing known IPs from collectedData
	collectedDataMutex.RLock()
	knownIPs := make(map[string]bool, len(collectedData))
	for ip := range collectedData {
		knownIPs[ip] = true
	}
	collectedDataMutex.RUnlock()

	// For large subnets, only probe IPs from ARP cache
	var candidateIPs []string
	if subnet.Prefix < 22 {
		// Large subnet: use ARP cache IPs in this subnet
		globalMACtoIPMutex.RLock()
		for _, ip := range globalMACtoIP {
			if isIPInSubnet(ip, subnet.Net, subnet.Prefix) {
				candidateIPs = append(candidateIPs, ip)
			}
		}
		globalMACtoIPMutex.RUnlock()
		fmt.Printf("📡 [SubnetDisc] Large subnet %s/%d — probing %d ARP-known IPs\n",
			subnet.Net, subnet.Prefix, len(candidateIPs))
	} else {
		// Small subnet: generate all host IPs
		candidateIPs = generateSubnetIPs(subnet.Net, subnet.Prefix)
		fmt.Printf("📡 [SubnetDisc] Small subnet %s/%d — probing %d IPs\n",
			subnet.Net, subnet.Prefix, len(candidateIPs))
	}

	for _, ip := range candidateIPs {
		if knownIPs[ip] || ip == gatewayIP {
			continue
		}
		// Quick SNMP probe: request sysDescr via walk (1 OID)
		lines, err := snmpObj.runSNMPWalk(ip, ".1.3.6.1.2.1.1.1.0")
		if err == nil && len(lines) > 0 {
			fmt.Printf("✅ [SubnetDisc] New SNMP device found: %s — adding to scan list\n", ip)
			newSwitchIPs = append(newSwitchIPs, ip)
		}
	}
	return newSwitchIPs
}

// isIPInSubnet checks if an IP is in a given network/prefix
func isIPInSubnet(ip, net string, prefix int) bool {
	ipP := strings.Split(ip, ".")
	netP := strings.Split(net, ".")
	if len(ipP) != 4 || len(netP) != 4 {
		return false
	}
	fullBits := prefix
	for i := 0; i < 4; i++ {
		bits := 8
		if fullBits <= 0 {
			break
		}
		if fullBits < 8 {
			bits = fullBits
		}
		var a, b int
		fmt.Sscanf(ipP[i], "%d", &a)
		fmt.Sscanf(netP[i], "%d", &b)
		mask := (0xFF << (8 - bits)) & 0xFF
		if (a & mask) != (b & mask) {
			return false
		}
		fullBits -= bits
	}
	return true
}

// generateSubnetIPs generates all host IPs in a /prefix subnet
func generateSubnetIPs(net string, prefix int) []string {
	if prefix < 22 {
		return nil // too large
	}
	parts := strings.Split(net, ".")
	if len(parts) != 4 {
		return nil
	}
	// Convert to uint32
	var base uint32
	for _, p := range parts {
		var n int
		fmt.Sscanf(p, "%d", &n)
		base = (base << 8) | uint32(n)
	}
	hostBits := 32 - prefix
	count := uint32(1) << hostBits
	ips := make([]string, 0, count-2)
	for i := uint32(1); i < count-1; i++ {
		addr := base | i
		ip := fmt.Sprintf("%d.%d.%d.%d", (addr>>24)&0xFF, (addr>>16)&0xFF, (addr>>8)&0xFF, addr&0xFF)
		ips = append(ips, ip)
	}
	return ips
}

// RunSubnetDiscovery discovers new SNMP switches from gateway subnets
// and adds them to swich_ips for future scanning
func RunSubnetDiscovery() {
	snmpObj := &SNMPObject{
		Community: "public",
		Port:      161,
		Timeout:   3 * time.Second,
		Retries:   0,
	}

	subnets := discoverGatewaySubnets(snmpObj, gatewayIP)
	if len(subnets) == 0 {
		return
	}

	var allNew []string
	for _, s := range subnets {
		if s.Prefix < 16 {
			continue // skip /8, /12 etc — too large, no use
		}
		new := probeSubnetForSwitches(snmpObj, s)
		allNew = append(allNew, new...)
	}

	if len(allNew) == 0 {
		fmt.Println("📡 [SubnetDisc] No new SNMP devices found in gateway subnets")
		return
	}

	// Append to swich_ips
	f, err := os.OpenFile("swich_ips", os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf("⚠️ [SubnetDisc] Cannot open swich_ips: %v\n", err)
		return
	}
	defer f.Close()
	added := 0
	for _, ip := range allNew {
		fmt.Fprintf(f, "%s\n", ip)
		added++
	}
	fmt.Printf("✅ [SubnetDisc] Added %d new devices to swich_ips\n", added)
}

// ─── Graph Enrichment ──────────────────────────────────────────────────────────

// enrichGraphWithIPs adds IP labels to graph nodes whose MAC is in globalMACtoIP.
// Called after detectHypervisors() so VM and hypervisor nodes get IPs too.
func enrichGraphWithIPs(graph *DJGraph) {
	if graph == nil {
		return
	}

	globalMACtoIPMutex.RLock()
	ipMap := make(map[string]string, len(globalMACtoIP))
	for k, v := range globalMACtoIP {
		ipMap[k] = v
	}
	globalMACtoIPMutex.RUnlock()

	enriched := 0
	for mac := range graph.Nodes {
		ip := ipMap[mac] // may be empty
		info := graph.SwitchInfo[mac]
		changed := false

		// Check if actively confirmed ESXi (works even without IP); a switch
		// (polled, or an LLDP neighbor naming a switch platform) is never
		// relabelled, whatever MAC binding the cache holds
		if graphIsConfirmedESXi(mac) && !graphIsSwitchNode(graph, mac) {
			if !strings.Contains(info, "[HYPERVISOR]") {
				info = "[HYPERVISOR] VMware ESXi\n" + info
				changed = true
			}
		}

		// Add IP label if available and not already a label line
		if ip != "" && !slices.Contains(strings.Split(info, "\n"), ip) {
			info = info + "\n" + ip
			changed = true
		}

		if changed {
			graph.SwitchInfo[mac] = info
			enriched++
		}
	}

	// Also enrich hypervisor nodes — list VM IPs in their label
	for nodeID := range graph.Nodes {
		if !strings.HasPrefix(nodeID, "hyp-") {
			continue
		}
		// Find VM MACs connected to this hypervisor (in MAC order, so the
		// "VMs:" line is the same on every build) and list the IP each VM's
		// label shows first, so the line and the VM labels agree
		vmIPs := []string{}
		vmEdges := graph.Edges[nodeID]
		for _, vmMAC := range slices.Sorted(maps.Keys(vmEdges)) {
			if edgeLabel := vmEdges[vmMAC]; edgeLabel == "vNIC" {
				if ip := graphLabelIP(graph.SwitchInfo[vmMAC]); ip != "" {
					vmIPs = append(vmIPs, ip)
				}
			}
		}
		if len(vmIPs) > 0 {
			info := graph.SwitchInfo[nodeID]
			ipLine := "VMs: " + strings.Join(vmIPs, ", ")
			if !strings.Contains(info, "VMs:") {
				graph.SwitchInfo[nodeID] = info + "\n" + ipLine
			}
		}
	}

	if enriched > 0 {
		fmt.Printf("🖊️  [MacIPService] Enriched %d graph nodes with IPs\n", enriched)
	}
}

// ─── Service Goroutine ─────────────────────────────────────────────────────────

// startMacIPService starts a background goroutine that periodically collects
// ARP tables from gateway and all discovered switches. Safe to call once.
func startMacIPService() {
	macIPServiceMu.Lock()
	if macIPServiceRunning {
		macIPServiceMu.Unlock()
		return
	}
	macIPServiceRunning = true
	macIPServiceMu.Unlock()

	// Load persistent cache first
	loadMacIPCache()

	startMacIPCollector()
}

// startMacIPCollector starts the background ARP collection of the MAC-IP
// service. Tests replace it so no collection loop is started.
var startMacIPCollector = func() { go runMacIPCollector() }

// runMacIPCollector collects the ARP tables at once and then every 5 minutes,
// and starts the one-time gateway subnet discovery.
func runMacIPCollector() {
	fmt.Println("🚀 [MacIPService] Started — collecting ARP from all switches every 5 min")

	// First run immediately
	collectARPFromAllSwitches()

	// Discover new SNMP devices from gateway subnets (one-time after first ARP)
	go func() {
		time.Sleep(10 * time.Second) // wait for ARP cache to populate
		fmt.Println("🔍 [SubnetDisc] Starting gateway subnet discovery...")
		RunSubnetDiscovery()
	}()

	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		fmt.Println("⏱️  [MacIPService] Periodic ARP collection started...")
		collectARPFromAllSwitches()
	}
}

// TriggerMacIPCollection can be called externally to force an immediate ARP sweep
// (e.g. after a new switch is discovered)
func TriggerMacIPCollection() {
	go collectARPFromAllSwitches()
}
