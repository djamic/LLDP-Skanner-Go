package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"lldp_scanner/modules/vsphere"
)

// ─── ESXi HTTP Fingerprinting ──────────────────────────────────────────────────

// ConfirmedESXiMACs holds the MACs whose IP answered as an ESXi host. The
// value is that IP (readers only test presence). esxiConfirmedFile keeps
// it over a restart (loadESXiConfirmed); a change builds the graph again
// (esxiConfirmationsChanged).
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

// probeESXiHost reports whether ip is an ESXi host, by the one test of the
// esxi module too: the vSphere API at https://ip/sdk says so (API type
// HostAgent; a vCenter Server's VirtualCenter is none), read with no login.
// When ip has no vSphere API answer, https://ip/ui/ is the ESXi host
// client: an HTTP 200 page from that host with the host client's app
// (isESXiResponse); error pages and other hosts' pages that mention ESXi
// do not count (F66). The TCP :443 check comes before it
// (collectESXiReachable).
func probeESXiHost(client *http.Client, ip string) bool {
	if c := vsphere.NewClientHTTP(ip, client); c.Connect(context.Background()) == nil {
		return c.Content.About.APIType == vsphere.APIHostAgent
	}
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
		if _, was := ConfirmedESXiMACs.LoadAndDelete(job.mac); was {
			fmt.Printf("❎ [Active-Check] No longer ESXi: %s (MAC: %s)\n", job.ip, job.mac)
			esxiConfirmedChanged()
		}
		return
	}
	if previous, _ := ConfirmedESXiMACs.Swap(job.mac, job.ip); previous != job.ip {
		fmt.Printf("✅ [Active-Check] Confirmed ESXi via HTTP: %s (MAC: %s)\n", job.ip, job.mac)
		esxiConfirmedChanged()
	}
}

// esxiConfirmedFile keeps ConfirmedESXiMACs over a restart, as a "mac":
// "ip" map (a variable for tests).
var esxiConfirmedFile = "esxi_confirmed.json"

// esxiConfirmedSaveMu orders the writes of esxiConfirmedFile (the check
// workers confirm concurrently).
var esxiConfirmedSaveMu sync.Mutex

// esxiConfirmationsChanged runs when a check confirmed an ESXi host or
// took a confirmation back: the graph is built again (esxiRebuildSoon), so
// its hypervisor tags, its hubs (an ESXi port is no Shadow IT) and its
// groups follow at once instead of at the next scan (a variable for
// tests).
var esxiConfirmationsChanged = esxiRebuildSoon

// esxiRebuildDelay gathers the confirmations of a burst of checks (a
// sweep, the re-checks of a start) into one graph build (variables for
// tests: the wait and the build).
var (
	esxiRebuildDelay = 10 * time.Second
	esxiRebuild      = func() { rebuildGraph() }
)

var esxiRebuildPending atomic.Bool

// esxiRebuildSoon builds the graph again esxiRebuildDelay from now, once
// for all the changes until then.
func esxiRebuildSoon() {
	if esxiRebuildPending.CompareAndSwap(false, true) {
		time.AfterFunc(esxiRebuildDelay, func() {
			esxiRebuildPending.Store(false)
			esxiRebuild()
		})
	}
}

// esxiConfirmedChanged saves the confirmations and announces the change.
func esxiConfirmedChanged() {
	saveESXiConfirmed()
	esxiConfirmationsChanged()
}

// saveESXiConfirmed writes ConfirmedESXiMACs to esxiConfirmedFile
// (writeJSONAtomic).
func saveESXiConfirmed() {
	esxiConfirmedSaveMu.Lock()
	defer esxiConfirmedSaveMu.Unlock()
	confirmed := map[string]string{}
	ConfirmedESXiMACs.Range(func(mac, ip any) bool {
		if ip, ok := ip.(string); ok {
			confirmed[fmt.Sprint(mac)] = ip
		}
		return true
	})
	writeJSONAtomic(esxiConfirmedFile, confirmed)
}

// loadESXiConfirmed reads esxiConfirmedFile into ConfirmedESXiMACs, so a
// restart knows the ESXi hosts at once: their ports are no Shadow-IT hubs
// and their nodes hypervisors in the first graph, not after the probes
// (the warm-up checks 500 cached MACs per sweep). Each MAC whose cached IP
// is still the confirmed one is checked again (a host reinstalled at the
// same address loses its confirmation; one that does not answer keeps it
// and is retried); a MAC at another IP now is checked by the sweeps (Q18).
// Called after loadMacIPCache. Returns the confirmations loaded.
func loadESXiConfirmed() int {
	data, err := os.ReadFile(esxiConfirmedFile)
	if err != nil {
		return 0
	}
	var confirmed map[string]string
	if err := json.Unmarshal(data, &confirmed); err != nil {
		fmt.Printf("⚠️ [MacIPService] Ignoring %s: %v\n", esxiConfirmedFile, err)
		return 0
	}
	var jobs []esxiJob
	for key, ip := range confirmed {
		mac := canonicalMAC(key)
		if mac == "" || parseIPv4(ip) == "" {
			continue
		}
		if _, known := ConfirmedESXiMACs.LoadOrStore(mac, ip); !known {
			jobs = append(jobs, esxiJob{mac: mac, ip: ip})
		}
	}
	slices.SortFunc(jobs, func(a, b esxiJob) int { return strings.Compare(a.mac, b.mac) })
	for _, job := range jobs {
		if collectMACIPCurrent(job.mac, job.ip) {
			esxiEnqueue(job)
		}
	}
	if len(jobs) > 0 {
		fmt.Printf("📂 [MacIPService] Loaded %d ESXi confirmations from %s (checked again)\n", len(jobs), esxiConfirmedFile)
	}
	return len(jobs)
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

// macIPGatewayOK holds, by gateway IP, when an ARP walk of that gateway
// last returned rows in this run (guarded by globalMACtoIPMutex). Cache
// entries expire only against the oldest of these clocks over every
// configured gateway (macIPExpiryClock): the two gateways route different
// subnets (the Debian 10.20.0.0/16 and 172.15.0.0/16, the FortiGate the
// 172.16.x /22s), so the answers of one say nothing about the hosts only
// the other one knows.
var macIPGatewayOK = make(map[string]time.Time)

// macIPExpiryClock is the time cache entries expire against
// (collectPruneMACIP): the oldest last answer of the configured gateways,
// so an entry only a silent gateway shows does not expire while it is
// silent; zero, and nothing expires, while one of them has not answered in
// this run or none is configured. Called with globalMACtoIPMutex held.
func macIPExpiryClock() time.Time {
	var clock time.Time
	for i, gw := range gatewayList() {
		ok, answered := macIPGatewayOK[gw]
		if !answered {
			return time.Time{}
		}
		if i == 0 || ok.Before(clock) {
			clock = ok
		}
	}
	return clock
}

// macIPGatewayWarned holds the gateways whose ARP warning was printed
// (guarded by globalMACtoIPMutex): one warning per start and gateway, not
// one per sweep.
var macIPGatewayWarned = make(map[string]bool)

// macIPSVIWait holds the gateway SVI IPs the sweeps leave out for a
// while, with the time to look at each one again (guarded by
// globalMACtoIPMutex): one that did not answer (the FortiGate answers SNMP
// on 172.20.0.1 only: its 15 other interface IPs would cost a 10-second
// timeout each in every sweep), and one that answers with its gateway's
// table (the Debian answers on its nine other addresses with its whole
// 1,388-row table: walked after the gateway, it only repeated the
// gateway's rows).
var macIPSVIWait = make(map[string]time.Time)

// collectSVIRetry is how long a gateway SVI IP that did not answer, or
// added nothing to its gateway's table, is left out of the sweeps.
const collectSVIRetry = time.Hour

// What the ARP walk of a gateway SVI IP showed (recordSVIWalk).
const (
	sviOwnTable  = iota // rows the gateway's table lacks: walked in every sweep
	sviSilent           // no answer: left out for collectSVIRetry
	sviSameTable        // nothing the gateway's table lacks: left out for collectSVIRetry
)

// collectSVIWanted reports whether the sweep at now walks the ARP table of
// gateway SVI svi: not while it waits to be looked at again.
func collectSVIWanted(svi string, now time.Time) bool {
	globalMACtoIPMutex.RLock()
	defer globalMACtoIPMutex.RUnlock()
	retry, waiting := macIPSVIWait[svi]
	return !waiting || !now.Before(retry)
}

// recordSVIWalk notes what the ARP walk of gateway gw's SVI svi at now
// showed: no answer, or nothing gw's table lacks, leaves it out for
// collectSVIRetry (one line per start names it); rows of its own bring it
// back.
func recordSVIWalk(svi, gw string, outcome int, now time.Time) {
	globalMACtoIPMutex.Lock()
	if outcome == sviOwnTable {
		delete(macIPSVIWait, svi)
	} else {
		macIPSVIWait[svi] = now.Add(collectSVIRetry)
	}
	globalMACtoIPMutex.Unlock()
	switch outcome {
	case sviSilent:
		gatewayNotice("📡 [MacIPService] Gateway SVI %s does not answer SNMP: left out of the sweeps, tried again every %d minutes", svi, int(collectSVIRetry.Minutes()))
	case sviSameTable:
		gatewayNotice("📡 [MacIPService] Gateway SVI %s answers with the ARP table of gateway %s: left out of the sweeps, looked at again every %d minutes", svi, gw, int(collectSVIRetry.Minutes()))
	}
}

// collectARPAddsNothing reports whether the ARP rows of table add nothing
// to the rows of base: every row of table with a usable MAC and an IPv4
// address maps that MAC to the same IP in base. A gateway SVI address
// that answers with its gateway's own table (the same agent) adds nothing.
func collectARPAddsNothing(table, base []ARPEntry) bool {
	have := make(map[string]bool, len(base))
	for _, e := range base {
		if mac := usableMAC(e.MACAddress); mac != "" && parseIPv4(e.IPAddress) != "" {
			have[mac+" "+e.IPAddress] = true
		}
	}
	for _, e := range table {
		if mac := usableMAC(e.MACAddress); mac != "" && parseIPv4(e.IPAddress) != "" && !have[mac+" "+e.IPAddress] {
			return false
		}
	}
	return true
}

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
// mean it answered (its clock in macIPGatewayOK moves on); no rows, from an
// error or an empty table, print the one warning of this run for this
// gateway.
func recordGatewayARP(ip string, rows int, err error, now time.Time) {
	globalMACtoIPMutex.Lock()
	if rows > 0 {
		if now.After(macIPGatewayOK[ip]) {
			macIPGatewayOK[ip] = now
		}
		globalMACtoIPMutex.Unlock()
		return
	}
	warned := macIPGatewayWarned[ip]
	macIPGatewayWarned[ip] = true
	globalMACtoIPMutex.Unlock()
	if warned {
		return
	}
	reason := "empty ARP table"
	if err != nil {
		reason = err.Error()
	}
	fmt.Printf("⚠️ [MacIPService] Gateway %s did not answer the SNMP ARP walk (%s). IPs only this gateway knows are not refreshed, and MAC-IP cache entries expire only against its last answer: none expires before it has answered in this run (SNMP read access to ipNetToMediaPhysAddress and ipAddrTable).\n", ip, reason)
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

// collectMergeARPTables merges ARP tables into globalMACtoIP as if one
// after the other in order (collectMergeMACIP: a later table's row for a
// MAC replaces an earlier one's), but each MAC once, with the row that
// wins. Merged one table after the other, a MAC that two gateways map to
// different IPs flipped to the first one's IP and back in every sweep,
// and each flip counted as a change; now only changes against the cache as
// the tables found it count. A row that repeats the mapping that wins does
// not take it over, so a table that only repeats an earlier one gets no
// changes. Returns the new or changed mappings of each table.
func collectMergeARPTables(tables [][]ARPEntry, now time.Time) []int {
	type winner struct {
		table, row int
		ip         string
	}
	wins := make(map[string]winner)
	for i, entries := range tables {
		for j, e := range entries {
			mac := usableMAC(e.MACAddress)
			if mac == "" || parseIPv4(e.IPAddress) == "" {
				continue
			}
			if w, ok := wins[mac]; !ok || w.ip != e.IPAddress {
				wins[mac] = winner{i, j, e.IPAddress}
			}
		}
	}
	updated := make([]int, len(tables))
	for i, entries := range tables {
		var rows []ARPEntry
		for j, e := range entries {
			if w, ok := wins[usableMAC(e.MACAddress)]; ok && w.table == i && w.row == j {
				rows = append(rows, e)
			}
		}
		added, changed := collectMergeMACIP(rows, now)
		updated[i] = added + changed
	}
	return updated
}

// collectPruneMACIP drops the globalMACtoIP entries whose last sighting is
// more than the TTL before the expiry clock (macIPExpiryClock, the oldest
// last answer of the configured gateways): the gateways' tables together
// hold the ARP entry of every host, so only gateway walks that have not
// shown a MAC for the whole TTL say it is gone, while switch ARP tables
// cover few hosts; and each gateway knows only the hosts of its own
// subnets, so while one gateway is silent its hosts do not expire because
// the other one answers. Until every configured gateway has answered in
// this run nothing expires. Entries without a time count as seen now, and
// times of MACs without an entry are forgotten. Returns the number of
// entries dropped.
func collectPruneMACIP(now time.Time) int {
	globalMACtoIPMutex.Lock()
	defer globalMACtoIPMutex.Unlock()
	clock := macIPExpiryClock()
	dropped := 0
	for mac := range globalMACtoIP {
		seen, known := collectMACIPSeen[mac]
		switch {
		case !known:
			collectMACIPSeen[mac] = now
		case !clock.IsZero() && clock.After(seen.Add(collectMACIPTTL)):
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

// collectARPFromAllSwitches collects ARP from every gateway (and all their
// SVI IPs) + all discovered switches + the ARP sources (SNMP devices of the
// swich_ips ranges that are no switches, arpSourceIPs). Each IP is walked
// once per sweep: a configured gateway is an ARP source by definition, so
// a gateway that is also stored or kept as an ARP source (the FortiGate
// once the rescue scan rejects it) is walked as a gateway only. The tables
// merge in that order, each gateway's SVIs right after the gateway, and
// each MAC once (collectMergeARPTables), so after every sweep a MAC two
// gateways disagree on maps to the later gateway's IP, as after the
// startup walk.
func collectARPFromAllSwitches() {
	snmpObj := &SNMPObject{
		Community: "public",
		Port:      161,
		Timeout:   pollTiming.Timeout, // the walks ran with -t 5 -r 1 whatever this said
		Retries:   pollTiming.Retries,
	}

	// The tables of the sweep in merge order, with the line that names each
	type sweepTable struct {
		line    string // "🌐 [MacIPService] Gateway 172.20.1.254"
		entries []ARPEntry
	}
	var tables []sweepTable
	totalRows := 0
	walk := func(ip, line string) {
		entries, err := snmpObj.collectARPTable(ip)
		if err == nil {
			totalRows += len(entries)
			tables = append(tables, sweepTable{line, entries})
		}
	}

	// 1. Every gateway — their own IPs first, walked at the same time. Only
	// a gateway's answer lets cache entries expire (collectPruneMACIP); its
	// sysName labels its router node.
	walked := make(map[string]bool)
	for _, gw := range gatewayList() {
		walked[gw] = true
	}
	for _, res := range walkGatewaysARP(snmpObj) {
		if res.Err != nil {
			continue
		}
		totalRows += res.Rows
		tables = append(tables, sweepTable{"🌐 [MacIPService] Gateway " + res.IP, res.entries})

		// 2. The gateway's SVI IPs, right after it — a gateway may route
		// multiple VLANs (172.20.x.x, 10.20.x.x...). Its ipAddrTable gives
		// its interface IPs; each is walked once per sweep, and one that did
		// not answer or answered with the gateway's own table only once an
		// hour.
		for _, svi := range collectGatewaySVIIPs(snmpObj, res.IP) {
			if walked[svi] {
				continue // a gateway, or an SVI of an earlier one
			}
			walked[svi] = true
			if !collectSVIWanted(svi, macIPClock()) {
				continue
			}
			entries, err := snmpObj.collectARPTable(svi)
			switch {
			case err != nil:
				recordSVIWalk(svi, res.IP, sviSilent, macIPClock())
			case collectARPAddsNothing(entries, res.entries):
				totalRows += len(entries)
				recordSVIWalk(svi, res.IP, sviSameTable, macIPClock())
			default:
				totalRows += len(entries)
				recordSVIWalk(svi, res.IP, sviOwnTable, macIPClock())
				tables = append(tables, sweepTable{"🌐 [MacIPService] Gateway SVI " + svi, entries})
			}
		}
	}

	// 3. All discovered switches (a gateway was walked above)
	collectedDataMutex.RLock()
	switchIPs := make([]string, 0, len(collectedData))
	for ip := range collectedData {
		if !walked[ip] {
			switchIPs = append(switchIPs, ip)
			walked[ip] = true
		}
	}
	collectedDataMutex.RUnlock()
	slices.SortFunc(switchIPs, compareIPs)
	for _, ip := range switchIPs {
		walk(ip, "🔗 [MacIPService] Switch "+ip)
	}

	// 4. The SNMP devices of the swich_ips ranges that are no switches
	// (arpSourceIPs): never polled, but such a device's ARP table can hold
	// MACs that no other table shows. An IP walked above (a gateway, its
	// SVIs, a switch) is not walked again.
	for _, ip := range arpSourceIPs() {
		if !walked[ip] {
			walked[ip] = true
			walk(ip, "🔗 [MacIPService] ARP source "+ip+" (no switch)")
		}
	}

	entries := make([][]ARPEntry, len(tables))
	for i, t := range tables {
		entries[i] = t.entries
	}
	totalNew := 0
	for i, n := range collectMergeARPTables(entries, macIPClock()) {
		if n > 0 {
			fmt.Printf("%s: +%d new/changed MAC-IP entries\n", tables[i].line, n)
			totalNew += n
		}
	}

	// Drop entries no gateway has shown for the TTL (Q18). The cache is
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
				gatewayNotice("📡 [MacIPService] Found gateway SVI IP: %s (gateway %s)", net, gwIP) // once per start
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

// discoverGatewaySubnets reads the ipAddrTable masks of gateway gwIP and
// returns one subnet per address (loopback left out); nil when the gateway
// does not answer. Subnet discovery prints one line per run, so this
// prints nothing.
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

// Subnet discovery runs once after each start (runMacIPCollector) and looks
// for switches no other path knows of: the rescue scan polls the owner's
// swich_ips ranges, LLDP discovery the management addresses that the
// polled switches' neighbors advertise. It used to probe every host of the
// gateway's small subnets and every ARP-known IP of its large ones, one
// after the other at the 10 s of a poll walk: with the gateway table and
// the MAC-IP cache of 2026-10-22 that was about 33,000 probes, 92 hours
// for a process that lives 24, mostly of Wi-Fi clients. As the owner
// approved, a run now probes only hosts that can be switches:
//
//   - the subnets of every gateway's ipAddrTable, each prefix once; a
//     subnet that is not private (RFC 1918: the FortiGate's WAN
//     195.158.2.192/27) or is a /31 or /32 link is left out;
//   - in them, only the ARP-known IPs (globalMACtoIP, which every ARP
//     source feeds: the gateways, their SVIs, the switches and the ARP
//     sources, kept across restarts) whose MAC is a network-equipment
//     maker's (isNetworkMakerMAC), each IP once however many subnets hold
//     it;
//   - never a stored device (by IP, chassis MAC or interface MAC), a
//     gateway or one of its addresses, or an IP that swich_ips lists alone
//     or in a range (the rescue scan's);
//   - the candidates in subnets that overlap swich_ips first, then in IP
//     order, Workers at a time: sysDescr first with the short Probe
//     timing, then checkSwitch for a host that answers, and a switch is
//     appended to swich_ips at once (the rescue scan polls it from there);
//   - no probe starts once the run's Budget is spent;
//   - one summary line per run (subnetDiscoveryRun.summary).

// subnetDiscoveryLimits bounds one subnet discovery run.
type subnetDiscoveryLimits struct {
	Workers int              // candidates probed at once
	Probe   walkTiming       // the sysDescr probe: does the host run SNMP at all
	Budget  time.Duration    // no probe starts once this much has passed (0: no limit)
	Now     func() time.Time // the run's clock
}

// subnetDiscoveryDefaults are the limits of the production runs: 8
// workers, a 2 s probe without retry (a host without SNMP costs 2 s, not
// the 10 s of a poll walk) and 5 minutes, room for 1,200 silent
// candidates. The fixture's cache with the two gateways' subnets of
// 2026-10-22 gives 634 candidates (of 6,666 ARP-known IPs; most are HP
// and Dell PCs and printers), 160 s if none of them answered.
var subnetDiscoveryDefaults = subnetDiscoveryLimits{
	Workers: 8,
	Probe:   walkTiming{Timeout: 2 * time.Second},
	Budget:  5 * time.Minute,
	Now:     time.Now,
}

// subnetCandidate is an IP that subnet discovery probes.
type subnetCandidate struct {
	IP, MAC string
	Listed  bool // in a subnet that overlaps a line of swich_ips: probed first
}

// subnetPlan is what one subnet discovery run searches and probes.
type subnetPlan struct {
	Subnets    []netip.Prefix    // the gateway subnets searched, in ipAddrTable order
	Skipped    []string          // the subnets left out, with the reason
	ARPIPs     int               // ARP-known IPs in the subnets
	Makers     int               // of those, the IPs a network-equipment maker's MAC maps to
	Known      int               // makers not probed: stored, a gateway's, listed in swich_ips
	Candidates []subnetCandidate // the IPs to probe, in probe order
}

// prefix is the subnet as a netip.Prefix; false for a subnet that is not
// IPv4.
func (s SubnetInfo) prefix() (netip.Prefix, bool) {
	p, err := netip.ParsePrefix(fmt.Sprintf("%s/%d", s.Net, s.Prefix))
	if err != nil || !p.Addr().Is4() {
		return netip.Prefix{}, false
	}
	return p.Masked(), true
}

// switchIPPrefixes parses lines of swich_ips, IPv4 addresses and CIDRs, as
// prefixes (an address as a /32); other lines are left out.
func switchIPPrefixes(lines []string) []netip.Prefix {
	var prefixes []netip.Prefix
	for _, line := range lines {
		if p, err := netip.ParsePrefix(line); err == nil && p.Addr().Is4() {
			prefixes = append(prefixes, p.Masked())
		} else if a, err := netip.ParseAddr(line); err == nil && a.Is4() {
			prefixes = append(prefixes, netip.PrefixFrom(a, 32))
		}
	}
	return prefixes
}

// privateIPv4 are the RFC 1918 blocks.
var privateIPv4 = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
}

// subnetPrivate reports whether all of p lies in an RFC 1918 block.
func subnetPrivate(p netip.Prefix) bool {
	return slices.ContainsFunc(privateIPv4, func(b netip.Prefix) bool {
		return b.Bits() <= p.Bits() && b.Contains(p.Addr())
	})
}

// subnetDiscoveryPrefixes returns the distinct subnets of the gateways'
// ipAddrTable rows that subnet discovery searches, in row order, and the
// ones it leaves out with the reason: not private (a WAN subnet), or a /31
// or /32 link.
func subnetDiscoveryPrefixes(subnets []SubnetInfo) (search []netip.Prefix, skipped []string) {
	seen := make(map[netip.Prefix]bool)
	for _, s := range subnets {
		p, ok := s.prefix()
		if !ok || seen[p] {
			continue
		}
		seen[p] = true
		switch {
		case !subnetPrivate(p):
			skipped = append(skipped, p.String()+" not private")
		case p.Bits() >= 31:
			skipped = append(skipped, p.String()+" a link")
		default:
			search = append(search, p)
		}
	}
	return search, skipped
}

// planSubnetDiscovery returns the subnets, counts and candidates of a
// discovery run over the gateways' ipAddrTable rows subnets (see the
// subnet discovery doc above); ranges are the lines of swich_ips.
func planSubnetDiscovery(subnets []SubnetInfo, ranges []string) subnetPlan {
	var plan subnetPlan
	plan.Subnets, plan.Skipped = subnetDiscoveryPrefixes(subnets)
	in := func(prefixes []netip.Prefix, a netip.Addr) bool {
		return slices.ContainsFunc(prefixes, func(p netip.Prefix) bool { return p.Contains(a) })
	}
	listed := switchIPPrefixes(ranges)
	var listedSubnets []netip.Prefix
	for _, p := range plan.Subnets {
		if slices.ContainsFunc(listed, p.Overlaps) {
			listedSubnets = append(listedSubnets, p)
		}
	}

	known := make(map[string]bool) // IPs that are no candidates
	for _, gw := range gatewayList() {
		known[gw] = true // a gateway is no switch: drawn as a router
	}
	for _, s := range subnets {
		known[s.IP] = true // the gateways' own addresses
	}
	knownMACs := make(map[string]bool) // the stored devices' own MACs
	collectedDataMutex.RLock()
	for ip, d := range collectedData {
		known[ip] = true
		if mac := graphChassisKey(d.ChassisID); mac != "" {
			knownMACs[mac] = true
		}
		for _, iface := range d.Interfaces {
			if mac := usableMAC(iface.IfPhysAddress); mac != "" {
				knownMACs[mac] = true
			}
		}
	}
	collectedDataMutex.RUnlock()

	// The ARP-known IPs in the subnets with the MACs that map to them
	arpMACs := make(map[netip.Addr][]string)
	globalMACtoIPMutex.RLock()
	for mac, ip := range globalMACtoIP {
		if a, err := netip.ParseAddr(ip); err == nil && a.Is4() && in(plan.Subnets, a) {
			arpMACs[a] = append(arpMACs[a], mac)
		}
	}
	globalMACtoIPMutex.RUnlock()

	for _, a := range slices.SortedFunc(maps.Keys(arpMACs), netip.Addr.Compare) {
		plan.ARPIPs++
		macs := slices.Sorted(slices.Values(arpMACs[a]))
		i := slices.IndexFunc(macs, isNetworkMakerMAC)
		if i < 0 {
			continue
		}
		plan.Makers++
		ip := a.String()
		if known[ip] || knownMACs[macs[i]] || in(listed, a) {
			plan.Known++
			continue
		}
		plan.Candidates = append(plan.Candidates, subnetCandidate{IP: ip, MAC: macs[i], Listed: in(listedSubnets, a)})
	}
	slices.SortStableFunc(plan.Candidates, func(x, y subnetCandidate) int {
		switch {
		case x.Listed == y.Listed:
			return 0
		case x.Listed:
			return -1
		}
		return 1
	})
	return plan
}

// probeSubnetCandidates probes candidates in order, limits.Workers at a
// time, and starts no probe once limits.Budget is spent: a candidate that
// answers the sysDescr probe (snmpProbeWalk with limits.Probe) is asked
// checkSwitch, found is called for each switch as soon as it is found (one
// call at a time), and the others are recorded in skips (the SNMP devices
// that are no switches, the hosts that did not answer). Returns how many
// candidates the budget left unprobed.
func probeSubnetCandidates(snmpObj *SNMPObject, candidates []subnetCandidate, limits subnetDiscoveryLimits, skips *switchSkips, found func(switchCheck)) (late int) {
	now := limits.Now
	if now == nil {
		now = time.Now
	}
	var deadline time.Time
	if limits.Budget > 0 {
		deadline = now().Add(limits.Budget)
	}
	jobs := make(chan subnetCandidate)
	var mu sync.Mutex
	var wg sync.WaitGroup
	for range min(max(limits.Workers, 1), len(candidates)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for c := range jobs {
				if !deadline.IsZero() && now().After(deadline) {
					mu.Lock()
					late++
					mu.Unlock()
					continue
				}
				if lines, err := snmpProbeWalk(snmpObj.Community, c.IP, oidSysDescr, limits.Probe); err != nil || len(lines) == 0 {
					skips.add(switchCheck{IP: c.IP}) // no SNMP agent
					continue
				}
				// An SNMP device: a switch only with a switch MIB
				check := snmpObj.checkSwitch(c.IP)
				if !check.isSwitch() {
					skips.add(check)
					continue
				}
				mu.Lock()
				found(check)
				mu.Unlock()
			}
		}()
	}
	for _, c := range candidates {
		jobs <- c
	}
	close(jobs)
	wg.Wait()
	return late
}

// subnetDiscoveryRun is what one discovery run did, for its summary line.
type subnetDiscoveryRun struct {
	Gateways []string // the gateways whose ipAddrTable answered
	Plan     subnetPlan
	Late     int // candidates the budget left unprobed
	Budget   time.Duration
	Added    []string // the switches appended to swich_ips, in IP order
	Skips    *switchSkips
}

// subnetDiscoverySummaryExamples is how many subnets and switches the
// summary line names.
const subnetDiscoverySummaryExamples = 5

// summary is the one line of a discovery run: the subnets searched (and
// left out), the ARP-known IPs in them, the network-equipment makers'
// IPs, the candidates probed, the switches added, and the devices not
// added with a few examples (switchSkips).
func (r subnetDiscoveryRun) summary() string {
	p := r.Plan
	var b strings.Builder
	fmt.Fprintf(&b, "🔍 [SubnetDisc] %s of %s", switchSkipCount(len(p.Subnets), "subnet"), strings.Join(r.Gateways, ", "))
	if n := len(p.Skipped); n > 0 {
		fmt.Fprintf(&b, " (%d left out: %s)", n, switchSkipList(p.Skipped[:min(n, subnetDiscoverySummaryExamples)], n))
	}
	fmt.Fprintf(&b, ", %s in them, %d with a network-equipment maker's MAC", switchSkipCount(p.ARPIPs, "ARP-known IP"), p.Makers)
	if p.Known > 0 {
		fmt.Fprintf(&b, " (%d of them stored, a gateway's address or in swich_ips)", p.Known)
	}
	fmt.Fprintf(&b, ", %d probed", len(p.Candidates)-r.Late)
	if r.Late > 0 {
		fmt.Fprintf(&b, " (time budget of %s spent: %d not probed)", r.Budget, r.Late)
	}
	switch n := len(r.Added); n {
	case 0:
		b.WriteString(", no switch added")
	case 1:
		fmt.Fprintf(&b, ", 1 switch added: %s", r.Added[0])
	default:
		fmt.Fprintf(&b, ", %d switches added: %s", n, switchSkipList(r.Added[:min(n, subnetDiscoverySummaryExamples)], n))
	}
	if detail := r.Skips.detail(); detail != "" {
		b.WriteString("; not added: " + detail)
	}
	return b.String()
}

// subnetDiscovery is one discovery run (see the subnet discovery doc
// above) over the subnets of every gateway, within limits: add is called
// for each switch as soon as it is found; ranges are the lines of
// swich_ips. It prints the run's one summary line and returns the IPs add
// took, in IP order.
func subnetDiscovery(snmpObj *SNMPObject, ranges []string, limits subnetDiscoveryLimits, add func(ip string) bool) []string {
	run := subnetDiscoveryRun{Budget: limits.Budget, Skips: &switchSkips{}}
	var subnets []SubnetInfo
	for _, gw := range gatewayList() {
		if rows := discoverGatewaySubnets(snmpObj, gw); len(rows) > 0 {
			run.Gateways = append(run.Gateways, gw)
			subnets = append(subnets, rows...)
		}
	}
	if len(subnets) == 0 {
		fmt.Printf("🔍 [SubnetDisc] No subnet to search: no gateway answered the ipAddrTable walk (%s)\n", gatewayListText())
		return nil
	}

	run.Plan = planSubnetDiscovery(subnets, ranges)
	run.Late = probeSubnetCandidates(snmpObj, run.Plan.Candidates, limits, run.Skips, func(c switchCheck) {
		if add(c.IP) {
			run.Added = append(run.Added, c.IP)
		}
	})
	slices.SortFunc(run.Added, compareIPs)
	fmt.Println(run.summary())
	return run.Added
}

// RunSubnetDiscovery discovers new switches in the subnets of every gateway
// and appends each one to swich_ips as soon as it is found, for the rescue
// scan to poll (subnetDiscovery, with subnetDiscoveryDefaults). Only
// devices that pass checkSwitch are added, and the gateways themselves are
// never probed. swich_ips is the owner's configuration: entries are only
// ever appended (appendSwitchIP, which skips an IP that is listed
// already), never removed or rewritten. Returns the IPs appended.
func RunSubnetDiscovery() []string {
	snmpObj := &SNMPObject{
		Community: "public",
		Port:      161,
		Timeout:   pollTiming.Timeout, // the gateways' ipAddrTable and checkSwitch
		Retries:   pollTiming.Retries,
	}
	ranges, _ := readSwitchIPsFile()
	return subnetDiscovery(snmpObj, ranges, subnetDiscoveryDefaults, appendSwitchIP)
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
		if graph.graphRouters[mac] {
			continue // a gateway's label is its sysName and IPs (addGatewayNodes)
		}
		ip := ipMap[mac] // may be empty
		info := graph.SwitchInfo[mac]
		if ip == "" {
			if p, ok := graph.graphVoIP[mac]; ok && p.IP != "" && p.IP != p.Firmware {
				ip = p.IP
			}
		}
		changed := false

		// Check if actively confirmed ESXi (works even without IP); a switch
		// (polled, or an LLDP neighbor naming a switch platform) is never
		// relabelled, whatever MAC binding the cache holds
		if graphIsConfirmedESXi(mac) && !graphIsSwitchNode(graph, mac) {
			if !graphHasTag(graph, mac, tagHypervisor) {
				info = graphESXiTag + "\n" + info
				graphPrependTag(graph, mac, esxiTag)
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

	// Also enrich hypervisor nodes — list VM IPs in their label: the hyp-
	// nodes and the confirmed ESXi hosts with VMs, the nodes with vNIC links
	// (detectHypervisors)
	for nodeID := range graph.Nodes {
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
	loadESXiConfirmed()

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
		RunSubnetDiscovery()         // one summary line
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
