package main

// Test harness for the golden tests.
//
// TestMain installs a stub or recorder on every side-effect seam before any
// test runs, so no test sends a ping, a DNS query, an HTTP request (analyserbot,
// ESXi probe, IEEE download), an SNMP walk or an InfluxDB write, and every file
// a test makes goes to t.TempDir(). The only files written anywhere else are
// the golden files in testdata/golden, and only with -update:
//
//	go test -run Golden -update   # rewrite the golden files
//	git diff testdata/golden      # review what changed
//
// The fixtures are frozen gzip copies of network_data.json and
// mac_ip_cache.json in testdata/. Time-dependent code that has a clock seam
// (eventClock) runs on testClock, which stands still unless a test moves it.
// TestGoldenUIApp and TestGoldenUITree also start Node.js, when it is
// installed, to run static/app.js and static/tree.js against a stub DOM
// (testdata/ui/app_probe.js, testdata/ui/tree_probe.js); those scripts send
// nothing either.

import (
	"bufio"
	"bytes"
	"cmp"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/influxdata/influxdb-client-go/v2/api/write"
	"github.com/klauspost/oui"
)

var update = flag.Bool("update", false, "rewrite the golden files in testdata/golden")

// fixedGatewayIP is the production gateway_ip value. Tests set it explicitly
// instead of depending on the file the init() functions read.
const fixedGatewayIP = "172.20.1.254"

// Fallback paths for file writes nobody asked for. They point into a temporary
// directory that must still be empty when the tests finish.
var (
	guardDir            string
	guardExportsDir     string
	guardGraphDebugFile string
	guardMacIPCacheFile string
	guardCapturesDir    string
)

// guard counts attempts to reach the network through a seam that tests never
// expect to be used.
var guard struct {
	esxiProbes   atomic.Int64
	ouiDownloads atomic.Int64
}

// macIPCollectorStarts counts the MAC-IP collection loops production would
// have started (the stub starts none), and liveAnalyses the background
// analyses the reactive scan would have started.
var macIPCollectorStarts, liveAnalyses atomic.Int64

func TestMain(m *testing.M) {
	flag.Parse()
	os.Exit(runHarness(m))
}

func runHarness(m *testing.M) int {
	dir, err := os.MkdirTemp("", "lldp-golden-guard-")
	if err != nil {
		fmt.Fprintln(os.Stderr, "harness:", err)
		return 1
	}
	defer os.RemoveAll(dir)
	installSeams(dir)

	// The OUI database loads exactly as in production: oui.txt from the
	// working directory (the package directory under go test).
	initOUIDatabase()
	if guard.ouiDownloads.Load() != 0 {
		fmt.Fprintln(os.Stderr, "harness: oui.txt did not load and the IEEE download was attempted")
		return 1
	}

	code := m.Run()
	if problems := guardProblems(); problems != "" {
		fmt.Fprintln(os.Stderr, "harness: side-effect guard: "+problems)
		if code == 0 {
			code = 1
		}
	}
	return code
}

// installSeams replaces every side-effect seam with a stub or a recorder.
// The function variables are set once here and never again, so goroutines
// started by the code under test never race with a test changing them.
func installSeams(dir string) {
	guardDir = dir
	guardExportsDir = filepath.Join(dir, "results")
	guardGraphDebugFile = filepath.Join(dir, "graphs_data.txt")
	guardMacIPCacheFile = filepath.Join(dir, "mac_ip_cache.json")
	guardCapturesDir = filepath.Join(dir, "captures")

	runPing = fakePing
	lookupAddr = fakeReverseDNS
	postBotNotify = bot.post
	botDispatch = func(send func()) { send() }
	influxReady = influxRec.ready
	influxWritePoint = influxRec.write
	esxiEnqueue = esxiJobs.add
	appendSwitchIP = switchIPAdds.add
	esxiProbe = func(*http.Client, string) bool {
		guard.esxiProbes.Add(1)
		return false
	}
	snmpWalk = fakeSNMP.walk
	snmpProbeWalk = snmpProbes.walk
	ouiOpenHTTP = func(string) (oui.StaticDB, error) {
		guard.ouiDownloads.Add(1)
		return nil, errors.New("harness: IEEE download disabled")
	}
	eventClock = testClock.Now
	macIPClock = testClock.Now
	dnsClock = testClock.Now
	startMacIPCollector = func() { macIPCollectorStarts.Add(1) }
	startLiveAnalysis = func(*DJGraph) { liveAnalyses.Add(1) }
	exportsDir = guardExportsDir
	graphDebugFile = guardGraphDebugFile
	macIPCacheFile = guardMacIPCacheFile
	globalCaptureManager = &CaptureManager{paramDir: guardCapturesDir}
	setGatewayIPs([]string{fixedGatewayIP})
	ignoredIssuesMutex.Lock()
	ignoredIssuesData = map[string]bool{}
	ignoredIssuesMutex.Unlock()
}

func guardProblems() string {
	var problems []string
	if n := guard.esxiProbes.Load(); n > 0 {
		problems = append(problems, fmt.Sprintf("%d ESXi probe(s) attempted", n))
	}
	if n := len(validationQueue); n > 0 {
		problems = append(problems, fmt.Sprintf("%d ESXi job(s) reached the worker queue", n))
	}
	if influxEnabled {
		problems = append(problems, "InfluxDB client was enabled")
	}
	if entries, err := os.ReadDir(guardDir); err == nil && len(entries) > 0 {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		problems = append(problems, "unexpected files written: "+strings.Join(names, ", "))
	}
	return strings.Join(problems, "; ")
}

// ─── Global state ─────────────────────────────────────────────────────────────

// resetState puts every package-level variable that the code under test reads
// or writes into a clean, fixed state. Call it at the start of each test.
func resetState(t *testing.T) {
	t.Helper()
	collectedDataMutex.Lock()
	collectedData = make(map[string]*DeviceData)
	collectedDataMutex.Unlock()

	globalMACtoIPMutex.Lock()
	globalMACtoIP = make(map[string]string)
	collectMACIPSeen = make(map[string]time.Time)
	macIPGatewayOK = make(map[string]time.Time)
	macIPGatewayWarned = make(map[string]bool)
	macIPSVIWait = make(map[string]time.Time)
	globalMACtoIPMutex.Unlock()
	gatewayPollsMu.Lock()
	gatewayPolls = make(map[string]gatewayPoll)
	gatewayPollsMu.Unlock()
	gatewayNoticesMu.Lock()
	gatewayNotices = make(map[string]bool)
	gatewayNoticesMu.Unlock()
	inventoryAPsChanged = func() {} // no graph build behind a test's back
	classifySettingsChanged = func() {}
	currentSettingsMutex.Lock()
	currentSettings.Classify = DefaultClassifySettings() // not a saved file's choices
	currentSettingsMutex.Unlock()

	clearConfirmedESXi()
	collectESXiMu.Lock()
	collectESXiChecked = make(map[string]string)
	collectESXiRetry = make(map[string]collectESXiRetryJob)
	collectESXiInflight = make(map[string]string)
	collectESXiMu.Unlock()
	collectVLANLastMu.Lock()
	collectVLANLastIPs = make(map[string]bool)
	collectVLANLastMu.Unlock()

	interfaceTrafficMapMutex.Lock()
	interfaceTrafficMap = make(map[string]map[int]*InterfaceTraffic)
	interfaceTrafficMapMutex.Unlock()

	dnsCacheMutex.Lock()
	dnsCache = make(map[string]dnsEntry)
	dnsInflight = make(map[string]chan struct{})
	dnsCacheMutex.Unlock()
	ttlOSCacheMutex.Lock()
	ttlOSCache = make(map[string]ttlOSEntry)
	ttlOSCacheMutex.Unlock()

	setGatewayIPs([]string{fixedGatewayIP})
	ignoredIssuesMutex.Lock()
	ignoredIssuesData = map[string]bool{}
	ignoredIssuesMutex.Unlock()

	resetBot()

	networkEventLogMutex.Lock()
	networkEventLog = nil
	networkEventLogMutex.Unlock()
	openEventTimesMutex.Lock()
	openEventTimes = make(map[string]time.Time)
	openEventTimesMutex.Unlock()
	testClock.set(fixedTime)

	macIPServiceMu.Lock()
	macIPServiceRunning = false
	macIPServiceMu.Unlock()
	macIPCollectorStarts.Store(0)
	liveAnalyses.Store(0)

	SetLastReport(0, map[string][]string{}, 0)
	SetGlobalGraph(nil)
	esxiJobs.reset()
	switchIPAdds.taken()
	snmpProbes.taken()
	arpSourcesMu.Lock()
	arpSources = make(map[string]bool)
	arpSourcesMu.Unlock()
	influxRec.stop()
	fakeSNMP.reset()

	exportsDir = guardExportsDir
	graphDebugFile = guardGraphDebugFile
	macIPCacheFile = guardMacIPCacheFile
	globalCaptureManager = &CaptureManager{paramDir: guardCapturesDir}
	t.Cleanup(func() {
		exportsDir = guardExportsDir
		graphDebugFile = guardGraphDebugFile
		macIPCacheFile = guardMacIPCacheFile
		globalCaptureManager = &CaptureManager{paramDir: guardCapturesDir}
		clearConfirmedESXi()
		influxRec.stop()
		releaseDNSHolds()
	})
}

func clearConfirmedESXi() {
	ConfirmedESXiMACs.Range(func(k, _ any) bool {
		ConfirmedESXiMACs.Delete(k)
		return true
	})
}

// ─── Fixtures ─────────────────────────────────────────────────────────────────

var fixture struct {
	once    sync.Once
	devices map[string]*DeviceData
	cache   map[string]string
	err     error
}

func readGzipJSON(path string, v any) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	defer zr.Close()
	if err := json.NewDecoder(bufio.NewReader(zr)).Decode(v); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

func loadFixture(t *testing.T) {
	t.Helper()
	fixture.once.Do(func() {
		var saved SavedData
		if fixture.err = readGzipJSON(filepath.Join("testdata", "network_data.json.gz"), &saved); fixture.err != nil {
			return
		}
		fixture.devices = saved.Hosts
		fixture.err = readGzipJSON(filepath.Join("testdata", "mac_ip_cache.json.gz"), &fixture.cache)
	})
	if fixture.err != nil {
		t.Fatalf("fixture: %v", fixture.err)
	}
}

// fixtureDevices returns the fixture switches keyed by IP. Each DeviceData is
// a fresh copy; the slices are shared and must not be modified in place.
func fixtureDevices(t *testing.T) map[string]*DeviceData {
	t.Helper()
	loadFixture(t)
	devices := make(map[string]*DeviceData, len(fixture.devices))
	for ip, d := range fixture.devices {
		cp := *d
		devices[ip] = &cp
	}
	return devices
}

// fixtureCache returns a copy of the fixture MAC→IP cache.
func fixtureCache(t *testing.T) map[string]string {
	t.Helper()
	loadFixture(t)
	cache := make(map[string]string, len(fixture.cache))
	for k, v := range fixture.cache {
		cache[k] = v
	}
	return cache
}

// useFixture resets the state and loads the fixture the way production holds
// it: collectedData from network_data.json and globalMACtoIP seeded directly
// from mac_ip_cache.json (no ESXi probe is queued).
func useFixture(t *testing.T) {
	t.Helper()
	resetState(t)
	devices := fixtureDevices(t)
	cache := fixtureCache(t)
	collectedDataMutex.Lock()
	collectedData = devices
	collectedDataMutex.Unlock()
	globalMACtoIPMutex.Lock()
	globalMACtoIP = cache
	globalMACtoIPMutex.Unlock()
}

// buildFixtureGraph builds the graph from the fixture with the production
// build function, minus the publish step.
func buildFixtureGraph(t *testing.T) *DJGraph {
	t.Helper()
	useFixture(t)
	return buildGraphFromSnapshot(snapshotCollectedData())
}

// sortedDevices returns the devices in IP order (the order production code
// must not depend on, fixed here so results are reproducible).
func sortedDevices(devices map[string]*DeviceData) []*DeviceData {
	out := make([]*DeviceData, 0, len(devices))
	for _, ip := range sortedDeviceIPs(devices) {
		out = append(out, devices[ip])
	}
	return out
}

func deviceValues(devices []*DeviceData) []DeviceData {
	out := make([]DeviceData, 0, len(devices))
	for _, d := range devices {
		out = append(out, *d)
	}
	return out
}

// fixedTime is used wherever the code under test takes a time from its input.
var fixedTime = time.Date(2026, 10, 20, 18, 35, 34, 0, time.FixedZone("UZT", 5*3600))

// fakeClock is the clock behind the eventClock seam. It stands still at
// fixedTime until a test sets or advances it.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

var testClock = &fakeClock{now: fixedTime}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) set(t time.Time) {
	c.mu.Lock()
	c.now = t
	c.mu.Unlock()
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

// captureData is the analyzer input production builds: devices plus the
// GetGraphData topology.
func captureData(id string, devices []*DeviceData, graph *DJGraph) FullCaptureData {
	data := FullCaptureData{
		Session:     CaptureSession{ID: id, Name: id, StartTime: fixedTime},
		DevicesData: deviceValues(devices),
	}
	if graph != nil {
		data.Topology = graph.GetGraphData()
	}
	return data
}

// ─── Ping and DNS stubs ───────────────────────────────────────────────────────

// pingCount counts the pings fakePing answered.
var pingCount atomic.Int64

// fakePing answers like "ping -c 1" for IPv4 addresses, chosen by the last
// octet: 0 → no reply, 1 → TTL 64 (Linux), 2 → TTL 128 (Windows),
// 3 → TTL 255 (no OS guess).
func fakePing(ip string) (string, error) {
	pingCount.Add(1)
	addr, err := netip.ParseAddr(ip)
	if err != nil || !addr.Is4() {
		return "", fmt.Errorf("fake ping: unknown host %s", ip)
	}
	b := addr.As4()
	ttl := 0
	switch b[3] % 4 {
	case 0:
		return "", errors.New("fake ping: no reply")
	case 1:
		ttl = 64
	case 2:
		ttl = 128
	case 3:
		ttl = 255
	}
	return fmt.Sprintf("PING %[1]s (%[1]s) 56(84) bytes of data.\n64 bytes from %[1]s: icmp_seq=1 ttl=%[2]d time=0.42 ms\n", ip, ttl), nil
}

// fakeDNSNames are fixed PTR answers for fixture endpoints that get a DNS
// lookup (direct FDB endpoints with a known IP). Several are BMC-like on
// purpose, so the goldens show whether BMC detection sees DNS names.
var fakeDNSNames = map[string]string{
	"172.20.6.139":  "ILOCZJ33411C3.tuit.local.",  // 5c:ed:8c HPE server NIC
	"172.20.0.48":   "srv-db01-idrac.tuit.local.", // 48:df:37 HPE server NIC
	"172.16.25.231": "esx01-irmc.tuit.local.",     // 90:1b:0e BMC LLDP endpoint (not looked up today)
	"172.16.18.202": "PC-ILONA.tuit.local.",       // plain endpoint, "-ilo" inside a name
	"172.16.1.153":  "mgmt-bmc-01",                // plain endpoint
	"172.16.16.223": "nas01.",                     // [WiFi] endpoint
	"195.158.2.202": "PC-JAMIL.tuit.local.",       // plain endpoint
	"10.0.9.13":     "srv01-idrac.tuit.local.",    // scenario endpoint
}

// dnsHold makes the next reverse lookup of one IP wait (a slow DNS server):
// entered is closed when the lookup starts, and the lookup answers once
// release is closed or the caller's context (resolveHostname: 2 s) ends.
type dnsHold struct {
	entered, release chan struct{}
	once             sync.Once
}

func (h *dnsHold) free() { h.once.Do(func() { close(h.release) }) }

var (
	dnsHolds     sync.Map // ip → *dnsHold, until a lookup takes it
	dnsHoldsMu   sync.Mutex
	dnsHoldsMade []*dnsHold
)

// holdReverseDNS makes the next reverse lookup of ip wait until the returned
// hold is freed. resetState frees every hold when the test ends, so a failed
// test never leaves a build waiting.
func holdReverseDNS(ip string) *dnsHold {
	h := &dnsHold{entered: make(chan struct{}), release: make(chan struct{})}
	dnsHoldsMu.Lock()
	dnsHoldsMade = append(dnsHoldsMade, h)
	dnsHoldsMu.Unlock()
	dnsHolds.Store(ip, h)
	return h
}

func releaseDNSHolds() {
	dnsHolds.Range(func(k, _ any) bool {
		dnsHolds.Delete(k)
		return true
	})
	dnsHoldsMu.Lock()
	for _, h := range dnsHoldsMade {
		h.free()
	}
	dnsHoldsMade = nil
	dnsHoldsMu.Unlock()
}

// fakeReverseDNS resolves the fixture address space without any network
// traffic: the fixed names above, and "pc-<c>-<d>.tuit.local." for private
// IPv4 addresses whose last octet is divisible by 5. Everything else fails
// like an unknown host.
func fakeReverseDNS(ctx context.Context, ip string) ([]string, error) {
	if v, ok := dnsHolds.LoadAndDelete(ip); ok {
		h := v.(*dnsHold)
		close(h.entered)
		select {
		case <-h.release:
		case <-ctx.Done():
		}
	}
	if name, ok := fakeDNSNames[ip]; ok {
		return []string{name}, nil
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil || !addr.Is4() {
		return nil, &net.DNSError{Err: "unrecognized address", Name: ip}
	}
	b := addr.As4()
	if (b[0] == 172 || b[0] == 10) && b[3]%5 == 0 {
		return []string{fmt.Sprintf("pc-%d-%d.tuit.local.", b[2], b[3])}, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: ip, IsNotFound: true}
}

// ─── Analyserbot recorder ─────────────────────────────────────────────────────

// botMessage is one message the analyserbot would have received.
type botMessage struct {
	IssueID   string   `json:"issue_id,omitempty"`
	Callbacks []string `json:"callbacks,omitempty"`
	Text      string   `json:"text"`
}

type botRecorder struct {
	mu   sync.Mutex
	msgs []botMessage
	// answers makes the bot reject messages: the HTTP status it answers to
	// a message about an issue id ("" for the summary), or a post error for
	// a status of 0. Messages not listed get 200 OK.
	answers map[string]int
}

var bot = &botRecorder{}

// answer makes the bot answer status to the messages about issueID ("" for
// the summary) until resetBot; 0 makes their posts fail with an error.
func (r *botRecorder) answer(issueID string, status int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.answers == nil {
		r.answers = map[string]int{}
	}
	r.answers[issueID] = status
}

// post records the payload and answers 200 OK, like the bot, or what answer
// set for the message.
func (r *botRecorder) post(body []byte) (*http.Response, error) {
	var payload struct {
		Message string                `json:"message"`
		Buttons [][]map[string]string `json:"buttons"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, err
	}
	msg := botMessage{Text: payload.Message}
	for _, row := range payload.Buttons {
		for _, b := range row {
			cb := b["callback_data"]
			msg.Callbacks = append(msg.Callbacks, cb)
			if id, ok := strings.CutPrefix(cb, "ignore|"); ok {
				msg.IssueID = id
			}
		}
	}
	r.mu.Lock()
	r.msgs = append(r.msgs, msg)
	status, set := r.answers[msg.IssueID]
	r.mu.Unlock()
	if !set {
		status = http.StatusOK
	}
	if status == 0 {
		return nil, errors.New("harness: the bot is not answering")
	}
	return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader("{}"))}, nil
}

// taken returns the recorded messages sorted by issue id (summary first) and
// clears the recorder.
func (r *botRecorder) taken() []botMessage {
	r.mu.Lock()
	msgs := r.msgs
	r.msgs = nil
	r.mu.Unlock()
	slices.SortStableFunc(msgs, func(a, b botMessage) int {
		return strings.Compare(a.IssueID+"\x00"+a.Text, b.IssueID+"\x00"+b.Text)
	})
	return msgs
}

// resetBot clears the recorder, the notification cooldowns and the Telegram
// timing log, so the next Analyze sends every eligible message.
func resetBot() {
	bot.mu.Lock()
	bot.msgs = nil
	bot.answers = nil
	bot.mu.Unlock()
	notifiedMu.Lock()
	notifiedIssues = make(map[string]time.Time)
	notifiedMu.Unlock()
	lastSummarySent = time.Time{}
	telegramTimingsMutex.Lock()
	telegramTimings = nil
	telegramTimingsMutex.Unlock()
}

// ─── InfluxDB recorder ────────────────────────────────────────────────────────

// recordedPoint is one point the code under test wrote to InfluxDB.
type recordedPoint struct {
	Measurement string            `json:"measurement"`
	Tags        map[string]string `json:"tags,omitempty"`
	Fields      map[string]any    `json:"fields,omitempty"`
}

// influxRecorder records the points of selected measurements while started.
// Measurements not selected (for example those written by background
// goroutines) are dropped, so goroutines cannot leak points between tests.
type influxRecorder struct {
	mu     sync.Mutex
	keep   map[string]bool
	points []recordedPoint
}

var influxRec = &influxRecorder{}

func (r *influxRecorder) ready() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.keep != nil
}

func (r *influxRecorder) write(p *write.Point) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.keep == nil || !r.keep[p.Name()] {
		return
	}
	rp := recordedPoint{Measurement: p.Name(), Tags: map[string]string{}, Fields: map[string]any{}}
	for _, tag := range p.TagList() {
		rp.Tags[tag.Key] = tag.Value
	}
	for _, f := range p.FieldList() {
		rp.Fields[f.Key] = f.Value
	}
	r.points = append(r.points, rp)
}

func (r *influxRecorder) start(measurements ...string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.keep = map[string]bool{}
	for _, m := range measurements {
		r.keep[m] = true
	}
	r.points = nil
}

// stop ends recording and returns the points in a canonical order.
func (r *influxRecorder) stop() []recordedPoint {
	r.mu.Lock()
	points := r.points
	r.keep = nil
	r.points = nil
	r.mu.Unlock()
	slices.SortStableFunc(points, func(a, b recordedPoint) int {
		ka, _ := json.Marshal(a)
		kb, _ := json.Marshal(b)
		return bytes.Compare(ka, kb)
	})
	return points
}

// ─── ESXi queue recorder ──────────────────────────────────────────────────────

type esxiJobRecorder struct {
	mu   sync.Mutex
	jobs []string
}

var esxiJobs = &esxiJobRecorder{}

// add records a validation job instead of handing it to the HTTP workers.
func (r *esxiJobRecorder) add(job esxiJob) {
	r.mu.Lock()
	r.jobs = append(r.jobs, job.mac+" "+job.ip)
	r.mu.Unlock()
}

func (r *esxiJobRecorder) reset() {
	r.mu.Lock()
	r.jobs = nil
	r.mu.Unlock()
}

// taken returns the queued jobs ("mac ip"), sorted, and clears the recorder.
func (r *esxiJobRecorder) taken() []string {
	r.mu.Lock()
	jobs := r.jobs
	r.jobs = nil
	r.mu.Unlock()
	slices.Sort(jobs)
	return jobs
}

// ─── swich_ips recorder ───────────────────────────────────────────────────────

// switchIPsRecorder records the IPs LLDP discovery adds to swich_ips, in
// place of the live file.
type switchIPsRecorder struct {
	mu  sync.Mutex
	ips []string
}

var switchIPAdds = &switchIPsRecorder{}

func (r *switchIPsRecorder) add(ip string) bool {
	r.mu.Lock()
	r.ips = append(r.ips, ip)
	r.mu.Unlock()
	return true
}

// taken returns the added IPs, sorted, and clears the recorder.
func (r *switchIPsRecorder) taken() []string {
	r.mu.Lock()
	ips := r.ips
	r.ips = nil
	r.mu.Unlock()
	slices.Sort(ips)
	return ips
}

// ─── Fake SNMP agents ─────────────────────────────────────────────────────────

// fakeAgents answers snmpbulkwalk requests from canned "-On" output lines.
// A walk with no canned answer fails like an agent that does not respond.
// Every walk is counted by IP and OID. The walks of an agent marked with
// checkOrder fail like net-snmp's when its rows come out of OID order and
// the walk is not unordered (-Cc, walkTiming.Unordered). An agent with a
// stall (fakeStall) takes time to answer and stalls on one table. The walks
// given to killAfter run into the walk limit while their rows still come.
type fakeAgents struct {
	mu      sync.Mutex
	agents  map[string]map[string][]string      // ip → OID → lines
	walks   map[string]int                      // "ip oid" → walks
	timed   map[string]int                      // "ip oid timeout/retries" → walks
	ordered map[string]bool                     // ip → net-snmp's OID order check (checkOrder)
	stalls  map[string]*fakeStall               // ip → its stall
	killed  map[string]map[string]time.Duration // ip → OID → walk limit (killAfter)
}

// fakeStall makes an agent behave as the Aruba 6300 172.20.230.253 did on
// 2026-10-22 (snmp_object.go, collectVLANLastIPs): every walk is in flight
// for perRequest per request (the agent puts at most 10 varbinds into a
// response, so a walk of n rows takes n/10+1 requests: 163 for the 1,619
// FDB rows of testdata/agents/aruba_253.walks), a
// walk of oid (dot1qVlanCurrentEgressPorts) keeps the agent busy for hold
// and fails like a timeout (the agent's 10.8 s are more than the walk's
// two 5 s attempts), and while the agent is busy no other walk is answered:
// a walk that is in flight when the stall begins, or starts during it,
// fails like a timeout too. victims lists the OIDs of those walks.
type fakeStall struct {
	oid              string
	perRequest, hold time.Duration
	busy             bool
	next             chan struct{} // closed when the next stall begins
	victims          []string
}

var fakeSNMP = &fakeAgents{}

func (f *fakeAgents) walk(_, ip, oid string, timing walkTiming) ([]string, error) {
	f.mu.Lock()
	if f.walks == nil {
		f.walks = map[string]int{}
	}
	f.walks[ip+" "+oid]++
	if f.timed == nil {
		f.timed = map[string]int{}
	}
	f.timed[fmt.Sprintf("%s %s %s/%d", ip, oid, timing.Timeout, timing.Retries)]++
	lines, ok := f.agents[ip][oid]
	var err error
	switch {
	case !ok:
		err = fmt.Errorf("fake snmp: timeout from %s for %s", ip, oid)
	case f.ordered[ip] && !timing.Unordered:
		if orderErr := netsnmpOrderCheck(lines, 25); orderErr != nil {
			err = fmt.Errorf("fake snmp: %s for %s: %w", ip, oid, orderErr)
		}
	}
	if limit, ok := f.killed[ip][oid]; ok {
		f.mu.Unlock()
		time.Sleep(limit)
		err := fmt.Errorf("fake snmp: %s for %s killed at the walk limit (%v)", ip, oid, limit)
		if rows := walkRows(lines); rows > 0 {
			return nil, &walkCutError{err: err, rows: rows}
		}
		return nil, err
	}
	stall := f.stalls[ip]
	if stall == nil {
		f.mu.Unlock()
		if err != nil {
			return nil, err
		}
		return slices.Clone(lines), nil
	}
	if oid == stall.oid {
		close(stall.next) // the walks in flight get no answer
		stall.next, stall.busy = make(chan struct{}), true
		f.mu.Unlock()
		time.Sleep(stall.hold)
		f.mu.Lock()
		stall.busy = false
		f.mu.Unlock()
		return nil, fmt.Errorf("fake snmp: timeout from %s for %s (the agent works on it longer than the walk waits)", ip, oid)
	}
	if stall.busy {
		stall.victims = append(stall.victims, oid)
		f.mu.Unlock()
		return nil, fmt.Errorf("fake snmp: timeout from %s for %s (the agent is busy)", ip, oid)
	}
	rows := 0
	for _, line := range lines {
		if strings.Contains(line, " = ") {
			rows++
		}
	}
	next, flight := stall.next, stall.perRequest*time.Duration(rows/10+1)
	f.mu.Unlock()
	timer := time.NewTimer(flight)
	defer timer.Stop()
	select {
	case <-next:
		f.mu.Lock()
		stall.victims = append(stall.victims, oid)
		f.mu.Unlock()
		return nil, fmt.Errorf("fake snmp: timeout from %s for %s (the agent stalled meanwhile)", ip, oid)
	case <-timer.C:
	}
	if err != nil {
		return nil, err
	}
	return slices.Clone(lines), nil
}

// stall gives the agent at ip a stall on oid (fakeStall).
func (f *fakeAgents) stall(ip, oid string, perRequest, hold time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.stalls == nil {
		f.stalls = map[string]*fakeStall{}
	}
	f.stalls[ip] = &fakeStall{oid: oid, perRequest: perRequest, hold: hold, next: make(chan struct{})}
}

// killAfter makes the walks of oids on ip run into the walk limit while
// the agent still answers, as the ifDescr, FDB and egress walks of
// 172.20.254.226 (Jamic, snmp_object.go, collectVLANLastIPs) run into the
// 30 s of snmpWalkLimit: such a walk is in flight for limit and then fails
// as snmpBulkWalk's kill does, with a walkCutError that counts the rows of
// its canned answer (a plain error when it has none: no answer).
func (f *fakeAgents) killAfter(ip string, limit time.Duration, oids ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.killed == nil {
		f.killed = map[string]map[string]time.Duration{}
	}
	if f.killed[ip] == nil {
		f.killed[ip] = map[string]time.Duration{}
	}
	for _, oid := range oids {
		f.killed[ip][oid] = limit
	}
}

// stallVictims returns the OIDs of the walks of ip that its stall failed
// since the last call, sorted, and clears them.
func (f *fakeAgents) stallVictims(ip string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	s := f.stalls[ip]
	if s == nil {
		return nil
	}
	victims := s.victims
	s.victims = nil
	slices.Sort(victims)
	return victims
}

// checkOrder makes the walks of ip check OID order as snmpbulkwalk does
// without -Cc (netsnmpOrderCheck).
func (f *fakeAgents) checkOrder(ip string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.ordered == nil {
		f.ordered = map[string]bool{}
	}
	f.ordered[ip] = true
}

// netsnmpOrderCheck is snmpbulkwalk's OID order check (net-snmp 5.9
// snmpbulkwalk.c) on the rows of one walk: they come in responses of
// repetitions rows (-Cr25), each row of a response is compared with the
// last OID of the response before (the OID the request started from), and
// a row that does not come after it ends the walk with "OID not
// increasing" and exit status 1 (snmpBulkWalk then returns no lines).
// Continuation lines of multi-line values are no rows.
func netsnmpOrderCheck(lines []string, repetitions int) error {
	var oids []string
	for _, line := range lines {
		if oid, _, ok := strings.Cut(line, " = "); ok && strings.HasPrefix(oid, ".") {
			oids = append(oids, oid)
		}
	}
	for start := repetitions; start < len(oids); start += repetitions {
		from := oids[start-1]
		for _, oid := range oids[start:min(start+repetitions, len(oids))] {
			if compareOIDs(oid, from) <= 0 {
				return fmt.Errorf("Error: OID not increasing: %s >= %s (exit status 1)", from, oid)
			}
		}
	}
	return nil
}

// compareOIDs orders numeric OIDs ("1.3.6.1...", with or without the
// leading dot) by their components.
func compareOIDs(a, b string) int {
	pa := strings.Split(strings.TrimPrefix(a, "."), ".")
	pb := strings.Split(strings.TrimPrefix(b, "."), ".")
	for i := 0; i < len(pa) && i < len(pb); i++ {
		na, errA := strconv.Atoi(pa[i])
		nb, errB := strconv.Atoi(pb[i])
		if errA != nil || errB != nil {
			if c := strings.Compare(pa[i], pb[i]); c != 0 {
				return c
			}
			continue
		}
		if na != nb {
			return cmp.Compare(na, nb)
		}
	}
	return cmp.Compare(len(pa), len(pb))
}

// agentWalks loads a fake agent from testdata/agents/<name>: the answers
// that a live agent gave, as snmpbulkwalk -On printed them. A line
// "## walk <oid> (...)" starts the answer of one walk; other "## " lines
// are comments.
func agentWalks(t *testing.T, name string) map[string][]string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "agents", name))
	if err != nil {
		t.Fatalf("fake agent: %v", err)
	}
	walks := map[string][]string{}
	oid := ""
	for _, line := range strings.Split(strings.TrimSuffix(string(data), "\n"), "\n") {
		if rest, ok := strings.CutPrefix(line, "## walk "); ok {
			oid = strings.Fields(rest)[0]
			walks[oid] = []string{}
			continue
		}
		if strings.HasPrefix(line, "## ") {
			continue
		}
		if oid == "" {
			t.Fatalf("fake agent %s: line %q before the first walk", name, line)
		}
		walks[oid] = append(walks[oid], line)
	}
	return walks
}

// walkCounts returns the walks since the last call (or reset) by "ip oid"
// and clears them.
func (f *fakeAgents) walkCounts() map[string]int {
	f.mu.Lock()
	defer f.mu.Unlock()
	counts := f.walks
	f.walks = nil
	return counts
}

// walkTimings returns the walks since the last call (or reset) by "ip oid
// timeout/retries" (the timing snmpbulkwalk would get) and clears them.
func (f *fakeAgents) walkTimings() map[string]int {
	f.mu.Lock()
	defer f.mu.Unlock()
	counts := f.timed
	f.timed = nil
	return counts
}

func (f *fakeAgents) set(ip string, walks map[string][]string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.agents == nil {
		f.agents = map[string]map[string][]string{}
	}
	f.agents[ip] = walks
}

func (f *fakeAgents) reset() {
	f.mu.Lock()
	f.agents = nil
	f.walks = nil
	f.timed = nil
	f.ordered = nil
	f.stalls = nil
	f.killed = nil
	f.mu.Unlock()
}

// probeRecorder records the hosts that subnet discovery probes
// (snmpProbeWalk) in probe order and answers from the fake agents.
type probeRecorder struct {
	mu  sync.Mutex
	ips []string
}

var snmpProbes = &probeRecorder{}

func (r *probeRecorder) walk(community, ip, oid string, timing walkTiming) ([]string, error) {
	r.mu.Lock()
	r.ips = append(r.ips, ip)
	r.mu.Unlock()
	return fakeSNMP.walk(community, ip, oid, timing)
}

// count is the number of probes recorded.
func (r *probeRecorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.ips)
}

// taken returns the probed hosts in probe order and clears the recorder.
func (r *probeRecorder) taken() []string {
	r.mu.Lock()
	ips := r.ips
	r.ips = nil
	r.mu.Unlock()
	return ips
}

// ─── Golden files ─────────────────────────────────────────────────────────────

// checkGolden compares got with testdata/golden/<name>, or rewrites the file
// when the tests run with -update.
func checkGolden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", "golden", name)
	if *update {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run `go test -run '%s' -update` to create it)", err, t.Name())
	}
	if !bytes.Equal(got, want) {
		t.Errorf("%s does not match the golden file:\n%s\nrun `go test -run '%s' -update` and review `git diff %s`",
			path, lineDiff(want, got, 30), t.Name(), path)
	}
}

// lineDiff shows the region where want and got differ (common leading and
// trailing lines removed), at most max lines per side.
func lineDiff(want, got []byte, max int) string {
	a := strings.Split(string(want), "\n")
	b := strings.Split(string(got), "\n")
	start := 0
	for start < len(a) && start < len(b) && a[start] == b[start] {
		start++
	}
	endA, endB := len(a), len(b)
	for endA > start && endB > start && a[endA-1] == b[endB-1] {
		endA--
		endB--
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "@@ line %d: golden has %d differing line(s), output has %d\n", start+1, endA-start, endB-start)
	for i := start; i < endA && i < start+max; i++ {
		fmt.Fprintf(&sb, "- %s\n", a[i])
	}
	if endA-start > max {
		fmt.Fprintf(&sb, "- ... %d more\n", endA-start-max)
	}
	for i := start; i < endB && i < start+max; i++ {
		fmt.Fprintf(&sb, "+ %s\n", b[i])
	}
	if endB-start > max {
		fmt.Fprintf(&sb, "+ ... %d more\n", endB-start-max)
	}
	return sb.String()
}

// goldenJSON renders v as indented JSON for a golden file. Struct fields keep
// their declaration order and map keys are sorted (encoding/json). Containers
// nested less than expand levels deep get one element per line; deeper ones
// stay on one line, so big tables diff one record per line.
func goldenJSON(t *testing.T, v any, expand int) []byte {
	t.Helper()
	var raw bytes.Buffer
	enc := json.NewEncoder(&raw)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		t.Fatalf("golden json: %v", err)
	}
	dec := json.NewDecoder(&raw)
	dec.UseNumber()
	var out bytes.Buffer
	if err := writeJSONValue(dec, &out, 0, expand); err != nil {
		t.Fatalf("golden json: %v", err)
	}
	out.WriteByte('\n')
	return out.Bytes()
}

func writeJSONValue(dec *json.Decoder, buf *bytes.Buffer, depth, expand int) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	switch v := tok.(type) {
	case json.Delim:
		closer := byte('}')
		if v == '[' {
			closer = ']'
		}
		buf.WriteByte(byte(v))
		if !dec.More() {
			buf.WriteByte(closer)
			_, err := dec.Token()
			return err
		}
		multiline := depth < expand
		for first := true; dec.More(); first = false {
			if !first {
				buf.WriteByte(',')
				if !multiline {
					buf.WriteByte(' ')
				}
			}
			if multiline {
				buf.WriteByte('\n')
				buf.WriteString(strings.Repeat("  ", depth+1))
			}
			if v == '{' {
				key, err := dec.Token()
				if err != nil {
					return err
				}
				writeJSONString(buf, key.(string))
				buf.WriteString(": ")
			}
			if err := writeJSONValue(dec, buf, depth+1, expand); err != nil {
				return err
			}
		}
		if _, err := dec.Token(); err != nil {
			return err
		}
		if multiline {
			buf.WriteByte('\n')
			buf.WriteString(strings.Repeat("  ", depth))
		}
		buf.WriteByte(closer)
	case string:
		writeJSONString(buf, v)
	case json.Number:
		buf.WriteString(v.String())
	case bool:
		if v {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case nil:
		buf.WriteString("null")
	}
	return nil
}

func writeJSONString(buf *bytes.Buffer, s string) {
	var tmp bytes.Buffer
	enc := json.NewEncoder(&tmp)
	enc.SetEscapeHTML(false)
	enc.Encode(s)
	buf.Write(bytes.TrimRight(tmp.Bytes(), "\n"))
}
