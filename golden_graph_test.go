package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// goldenNode and goldenLink are the GetGraphData fields the UI and the
// reports use.
type goldenNode struct {
	ID          string `json:"id"`
	Group       string `json:"group"`
	Type        string `json:"type"`
	Label       string `json:"label"`
	SysName     string `json:"sysName,omitempty"`
	Hostname    string `json:"hostname,omitempty"`
	IP          string `json:"ip,omitempty"`
	Unreachable bool   `json:"unreachable,omitempty"`
}

type goldenLink struct {
	Source      string `json:"source"`
	Target      string `json:"target"`
	Label       string `json:"label"`
	SourceLabel string `json:"sourceLabel,omitempty"`
	TargetLabel string `json:"targetLabel,omitempty"`
	Unreachable bool   `json:"unreachable,omitempty"`
}

type graphSummary struct {
	Nodes       int            `json:"nodes"`
	Links       int            `json:"links"`
	Edges       int            `json:"edges"`
	Groups      map[string]int `json:"groups"`
	Unreachable int            `json:"unreachable_nodes"`
}

type graphGolden struct {
	Summary    graphSummary      `json:"summary"`
	Nodes      []goldenNode      `json:"nodes"`
	Links      []goldenLink      `json:"links"`
	SwitchInfo map[string]string `json:"switch_info"`
	NodeStatus map[string]string `json:"node_status"`
}

// graphRecord converts a graph into its golden form: GetGraphData nodes and
// links (sorted) plus the raw SwitchInfo labels and node status.
func graphRecord(g *DJGraph) graphGolden {
	data := g.GetGraphData()
	rec := graphGolden{
		Summary: graphSummary{
			Nodes:  len(data.Nodes),
			Links:  len(data.Links),
			Edges:  countEdges(g),
			Groups: map[string]int{},
		},
		SwitchInfo: maps.Clone(g.SwitchInfo),
		NodeStatus: maps.Clone(g.NodeStatus),
	}
	for _, n := range data.Nodes {
		rec.Summary.Groups[n.Group]++
		if n.Unreachable {
			rec.Summary.Unreachable++
		}
		rec.Nodes = append(rec.Nodes, goldenNode{
			ID: n.ID, Group: n.Group, Type: n.NodeType, Label: n.Label,
			SysName: n.SysName, Hostname: n.Hostname, IP: n.IP, Unreachable: n.Unreachable,
		})
	}
	for _, l := range data.Links {
		rec.Links = append(rec.Links, goldenLink{
			Source: l.Source, Target: l.Target, Label: l.Label,
			SourceLabel: l.SourceLabel, TargetLabel: l.TargetLabel, Unreachable: l.Unreachable,
		})
	}
	slices.SortFunc(rec.Nodes, func(a, b goldenNode) int { return strings.Compare(a.ID, b.ID) })
	slices.SortFunc(rec.Links, func(a, b goldenLink) int {
		if c := strings.Compare(a.Source, b.Source); c != 0 {
			return c
		}
		return strings.Compare(a.Target, b.Target)
	})
	return rec
}

// TestGoldenGraph pins the graph built from the fixture by the production
// build function (buildGraphFromSnapshot, as used by rebuildGraph), with
// globalMACtoIP seeded from the cache fixture and no confirmed ESXi hosts.
// The graph is built twice: both builds must be identical (change A).
func TestGoldenGraph(t *testing.T) {
	first := goldenJSON(t, graphRecord(buildFixtureGraph(t)), 2)
	second := goldenJSON(t, graphRecord(buildFixtureGraph(t)), 2)
	if !bytes.Equal(first, second) {
		t.Fatalf("two builds of the same snapshot differ (map-order dependence):\n%s", lineDiff(first, second, 20))
	}
	checkGolden(t, "graph.json", first)
}

// esxiConfirmedMACs are fixture MACs marked as HTTP-confirmed ESXi hosts in
// TestGoldenGraphESXi. Each one covers a different ESXi-dependent rule.
var esxiConfirmedMACs = []string{
	"08:35:71:ec:46:12", // direct [ENDPOINT] with IP and DNS name
	"56:8b:ca:d3:33:cd", // [WiFi] endpoint
	"00:0e:c8:9f:f5:c0", // [LLDP-EP] endpoint
	"90:1b:0e:f8:44:46", // [BMC] endpoint
	"5c:ed:8c:ba:a4:7c", // server NIC already tagged [HYPERVISOR]
	"4c:ae:a3:27:7e:ca", // switch chassis (no [SWITCH] tag is ever written)
	"00:0c:29:20:d6:60", // [VM] under a hyp- node
	"5c:62:8b:b8:b3:11", // hub member on Shadow-IT port 172.20.230.11/11
	"c8:d9:d2:8c:99:40", // not in the graph; on Shadow-IT port 172.20.230.14/17
}

type nodeView struct {
	Group   string `json:"group"`
	SysName string `json:"sysName"`
}

type nodeChange struct {
	ID     string    `json:"id"`
	Before *nodeView `json:"before,omitempty"`
	After  *nodeView `json:"after,omitempty"`
}

type esxiGolden struct {
	Confirmed    []string       `json:"confirmed_macs"`
	NodeChanges  []nodeChange   `json:"node_changes"`
	LinksAdded   []goldenLink   `json:"links_added"`
	LinksRemoved []goldenLink   `json:"links_removed"`
	Analyzer     map[string]any `json:"analyzer"`
	Experiment   map[string]any `json:"experiment"`
}

// TestGoldenGraphESXi marks a few fixture MACs as confirmed ESXi hosts and
// pins what changes against the same build without them: graph labels and
// groups, the analyzer's Shadow-IT alerts and the experiment counts; and the
// audit report's Shadow-IT and hypervisor sections for the ESXi graph.
func TestGoldenGraphESXi(t *testing.T) {
	baseGraph := buildFixtureGraph(t)
	base := graphRecord(baseGraph)
	baseReport, _ := analyzeFixture(t, baseGraph)
	baseMetrics := experimentMetrics(t, baseGraph)

	useFixture(t)
	for _, mac := range esxiConfirmedMACs {
		ConfirmedESXiMACs.Store(mac, true)
	}
	esxiGraph := buildGraphFromSnapshot(snapshotCollectedData())
	esxi := graphRecord(esxiGraph)
	esxiReport, _ := analyzeFixture(t, esxiGraph)
	esxiMetrics := experimentMetrics(t, esxiGraph)

	rec := esxiGolden{Confirmed: esxiConfirmedMACs}
	before := map[string]goldenNode{}
	for _, n := range base.Nodes {
		before[n.ID] = n
	}
	after := map[string]goldenNode{}
	for _, n := range esxi.Nodes {
		after[n.ID] = n
	}
	ids := slices.Sorted(maps.Keys(before))
	for id := range after {
		if _, ok := before[id]; !ok {
			ids = append(ids, id)
		}
	}
	slices.Sort(ids)
	for _, id := range ids {
		b, inB := before[id]
		a, inA := after[id]
		if inB && inA && b.Group == a.Group && b.SysName == a.SysName {
			continue
		}
		ch := nodeChange{ID: id}
		if inB {
			ch.Before = &nodeView{Group: b.Group, SysName: b.SysName}
		}
		if inA {
			ch.After = &nodeView{Group: a.Group, SysName: a.SysName}
		}
		rec.NodeChanges = append(rec.NodeChanges, ch)
	}
	rec.LinksAdded, rec.LinksRemoved = linkDiff(base.Links, esxi.Links)

	rec.Analyzer = map[string]any{
		"health_before":     baseReport.HealthScore,
		"health_after":      esxiReport.HealthScore,
		"shadow_it_before":  baseReport.Summary["shadow_it_issues"],
		"shadow_it_after":   esxiReport.Summary["shadow_it_issues"],
		"shadow_it_removed": issueDiff(baseReport, esxiReport),
		"shadow_it_added":   issueDiff(esxiReport, baseReport),
	}
	rec.Experiment = map[string]any{}
	for _, k := range []string{"shadow_it_raw", "shadow_it_filtered", "vm_ports_filtered", "vm_macs", "unique_macs"} {
		rec.Experiment[k+"_before"] = baseMetrics[k]
		rec.Experiment[k+"_after"] = esxiMetrics[k]
	}
	checkGolden(t, "graph_esxi.json", goldenJSON(t, rec, 2))

	// The audit report's Shadow-IT and hypervisor sections (7 and 8) for the
	// ESXi graph, with the ESXi MACs still confirmed. The same sections of
	// the plain graph are in audit_default.md.
	SetGlobalGraph(esxiGraph)
	audit := canonicalAuditMD(generateAuditMD([]string{"switch", "hub"}))
	checkGolden(t, "audit_esxi_sections.md", []byte(auditSections(t, audit, "## 7.", "## 9.")))
}

func linkDiff(before, after []goldenLink) (added, removed []goldenLink) {
	key := func(l goldenLink) string { return l.Source + "\x00" + l.Target + "\x00" + l.Label }
	inBefore := map[string]bool{}
	for _, l := range before {
		inBefore[key(l)] = true
	}
	inAfter := map[string]bool{}
	for _, l := range after {
		inAfter[key(l)] = true
		if !inBefore[key(l)] {
			added = append(added, l)
		}
	}
	for _, l := range before {
		if !inAfter[key(l)] {
			removed = append(removed, l)
		}
	}
	return added, removed
}

// issueDiff lists the shadow_it issue ids that are in a but not in b.
func issueDiff(a, b Report) []string {
	inB := map[string]bool{}
	for _, s := range b.Suggestions {
		inB[s.IssueID] = true
	}
	var out []string
	for _, s := range a.Suggestions {
		if s.Type == "shadow_it" && !inB[s.IssueID] {
			out = append(out, s.IssueID)
		}
	}
	slices.Sort(out)
	return out
}

// lldpTarget is how buildGraphEdges sees one LLDP neighbor.
type lldpTarget struct {
	Device         string `json:"device"`
	LocalPort      int    `json:"local_port"`
	LocalPortName  string `json:"local_port_name"`
	NullPort       bool   `json:"null_port,omitempty"`
	ChassisSubtype int    `json:"chassis_subtype"`
	ChassisID      string `json:"chassis_id"`
	PortSubtype    int    `json:"port_subtype"`
	PortID         string `json:"port_id"`
	SysName        string `json:"sys_name,omitempty"`
	MgmtIP         string `json:"mgmt_ip,omitempty"`
	NormChassis    string `json:"norm_chassis"`
	NormPort       string `json:"norm_port"`
	Target         string `json:"target"`
	Display        string `json:"display,omitempty"`
	Invalid        bool   `json:"invalid,omitempty"`
}

// lldpTargetRows lists the LLDP neighbors of the devices (IP order, stored
// neighbor order) with the ids production derives from them (chassis and
// port subtype tables), and the MACs each device treats as known from LLDP
// (lldpKnownMACs, sorted: the targets of accepted neighbors).
func lldpTargetRows(devices map[string]*DeviceData) ([]lldpTarget, map[string][]string) {
	var rows []lldpTarget
	known := map[string][]string{}
	for _, d := range sortedDevices(devices) {
		for _, n := range d.Neighbors {
			target, display := resolveLLDPTarget(n)
			portName := getLocalPortName(d, n.LocalPortNum)
			rows = append(rows, lldpTarget{
				Device:         d.IP,
				LocalPort:      n.LocalPortNum,
				LocalPortName:  portName,
				NullPort:       isNullInterface(portName),
				ChassisSubtype: n.RemChassisIdSubtype,
				ChassisID:      n.RemChassisId,
				PortSubtype:    n.RemPortIdSubtype,
				PortID:         n.RemPortId,
				SysName:        n.RemSysName,
				MgmtIP:         n.RemMgmtIP,
				NormChassis:    lldpChassisID(n),
				NormPort:       lldpPortID(n),
				Target:         target,
				Display:        display,
				Invalid:        !graphUsableTargetID(target),
			})
		}
		if macs := lldpKnownMACs(d); len(macs) > 0 {
			known[d.IP] = slices.Sorted(maps.Keys(macs))
		}
	}
	return rows, known
}

// TestGoldenLLDPTargets pins, for every LLDP neighbor in the fixture and in
// the synthetic scenario network (in stored order), the normalized chassis
// and port ids resolveLLDPTarget works with (chassis and port subtype
// tables), the node id and display name it chooses, whether
// graphUsableTargetID drops the target and whether the local port is a NULL
// interface; and per device the MACs buildGraphEdges treats as known from
// LLDP (lldpKnownMACs: the targets of accepted neighbors).
func TestGoldenLLDPTargets(t *testing.T) {
	resetState(t)
	rows, known := lldpTargetRows(fixtureDevices(t))
	scenarioRows, scenarioKnown := lldpTargetRows(scenarioNetwork())
	checkGolden(t, "lldp_targets.json", goldenJSON(t, map[string]any{
		"neighbors":           rows,
		"known_macs":          known,
		"scenario_neighbors":  scenarioRows,
		"scenario_known_macs": scenarioKnown,
	}, 2))
}

// TestRebuildGraphPublishesCompleteGraph checks change B: rebuildGraph (used
// by the reactive scan path and by every rescan) publishes the graph only
// after detectHypervisors and enrichGraphWithIPs have run. Concurrent
// /api/graph readers must only ever see the old graph or the finished one;
// run with -race to also check that nothing mutates a published graph.
func TestRebuildGraphPublishesCompleteGraph(t *testing.T) {
	want := goldenJSON(t, graphRecord(buildFixtureGraph(t)), 2)

	useFixture(t)
	graphDebugFile = filepath.Join(t.TempDir(), "graphs_data.txt")
	old := NewDJGraph()
	old.AddNode("old-graph")
	SetGlobalGraph(old)

	stop := make(chan struct{})
	var wg sync.WaitGroup
	var mu sync.Mutex
	seen := map[int]int{} // node count → times seen
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				rr := httptest.NewRecorder()
				graphHandler(rr, httptest.NewRequest(http.MethodGet, "/api/graph", nil))
				var data GraphData
				if err := json.Unmarshal(rr.Body.Bytes(), &data); err != nil {
					t.Errorf("decode /api/graph: %v", err)
					return
				}
				mu.Lock()
				seen[len(data.Nodes)]++
				mu.Unlock()
			}
		}()
	}

	published := rebuildGraph()
	full := len(published.Nodes)
	// Keep reading until the finished graph has been served at least once.
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(5 * time.Millisecond) {
		mu.Lock()
		served := seen[full]
		mu.Unlock()
		if served > 0 {
			break
		}
	}
	close(stop)
	wg.Wait()

	if seen[full] == 0 {
		t.Error("the finished graph was never served by /api/graph")
	}
	if GetGlobalGraph() != published {
		t.Fatal("rebuildGraph did not publish the graph it returned")
	}
	if got := goldenJSON(t, graphRecord(published), 2); !bytes.Equal(got, want) {
		t.Fatalf("published graph differs from buildGraphFromSnapshot:\n%s", lineDiff(want, got, 20))
	}
	for n := range seen {
		if n != 1 && n != full {
			t.Errorf("/api/graph served a graph with %d nodes (old graph: 1, finished graph: %d)", n, full)
		}
	}
}

// reactiveDevices are four small switches for the reactive-scan tests. Each
// has a direct endpoint with a known IP (its build does a reverse lookup)
// and a VM port, so a complete build has a hyp- node with a "VMs:" line.
func reactiveDevices() []*DeviceData {
	var devs []*DeviceData
	for i := 1; i <= 4; i++ {
		devs = append(devs, &DeviceData{
			IP:         fmt.Sprintf("10.0.8.%d", i),
			SysName:    fmt.Sprintf("sw-r%d", i),
			ChassisID:  fmt.Sprintf("4c:ae:a3:08:00:%02x", i),
			Interfaces: gigabitPorts(4, nil),
			MACTable: append(macEntries(1, fmt.Sprintf("00:1b:21:08:%02x:01", i)),
				macEntries(2, fmt.Sprintf("00:50:56:08:%02x:01", i), fmt.Sprintf("00:50:56:08:%02x:02", i))...),
		})
	}
	return devs
}

// reactiveMACtoIP gives every MAC of reactiveDevices an IP.
func reactiveMACtoIP() map[string]string {
	m := map[string]string{}
	for i := 1; i <= 4; i++ {
		m[fmt.Sprintf("00:1b:21:08:%02x:01", i)] = fmt.Sprintf("10.0.8.%d", 50+i)
		m[fmt.Sprintf("00:50:56:08:%02x:01", i)] = fmt.Sprintf("10.0.8.%d", 60+i)
		m[fmt.Sprintf("00:50:56:08:%02x:02", i)] = fmt.Sprintf("10.0.8.%d", 70+i)
	}
	return m
}

// useReactiveNetwork resets the state for a reactive-scan test: empty
// collectedData, the MAC-IP map of reactiveDevices, a fake SNMP agent for
// each of the four switches and a temporary graphs_data.txt.
func useReactiveNetwork(t *testing.T) {
	t.Helper()
	resetState(t)
	graphDebugFile = filepath.Join(t.TempDir(), "graphs_data.txt")
	globalMACtoIPMutex.Lock()
	globalMACtoIP = reactiveMACtoIP()
	globalMACtoIPMutex.Unlock()
	for i := 1; i <= 4; i++ {
		fakeSNMP.set(fmt.Sprintf("10.0.8.%d", i), reactiveAgent(i))
	}
}

// reactiveAgent answers CollectData for switch i of reactiveDevices: its
// chassis id, four ports, and the FDB (the endpoint on port 1, two VMware
// MACs on port 2). Every other walk fails, as on a switch without LLDP.
func reactiveAgent(i int) map[string][]string {
	walks := map[string][]string{
		oidChassis: {fmt.Sprintf("%s = Hex-STRING: 4C AE A3 08 00 %02X ", oidChassis, i)},
		oidFDBPort: {
			fmt.Sprintf("%s.0.27.33.8.%d.1 = INTEGER: 1", oidFDBPort, i),
			fmt.Sprintf("%s.0.80.86.8.%d.1 = INTEGER: 2", oidFDBPort, i),
			fmt.Sprintf("%s.0.80.86.8.%d.2 = INTEGER: 2", oidFDBPort, i),
		},
	}
	for p := 1; p <= 4; p++ {
		walks[oidIfDescr] = append(walks[oidIfDescr], fmt.Sprintf("%s.%d = STRING: \"GigabitEthernet1/0/%d\"", oidIfDescr, p, p))
	}
	return walks
}

// collectReactiveDevices returns what CollectData delivers for the four
// reactive switches (collected with a plain SNMP object).
func collectReactiveDevices(t *testing.T) []*DeviceData {
	t.Helper()
	var devs []*DeviceData
	for _, d := range reactiveDevices() {
		var got *DeviceData
		NewSNMPObject(func(data *DeviceData) { got = data }, nil).CollectData(d.IP, d.SysName)
		if got == nil || len(got.MACTable) != 3 {
			t.Fatalf("fake agent for %s did not deliver its FDB: %+v", d.IP, got)
		}
		devs = append(devs, got)
	}
	return devs
}

// serveGraph returns the /api/graph response body.
func serveGraph() string {
	rr := httptest.NewRecorder()
	graphHandler(rr, httptest.NewRequest(http.MethodGet, "/api/graph", nil))
	return rr.Body.String()
}

// waitDone waits for ch to be closed, failing the test after 10 seconds.
func waitDone(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(10 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
	}
}

// TestReactiveScanPublishesNewestGraph checks the order of the reactive graph
// publishes (review finding B1). The SNMP object of the first scan
// (newReactiveSNMPObject) collects two switches at the same time and the
// first one's build is slow: its reverse lookup hangs until the second
// switch has been stored. The graph published last must hold both switches,
// as it did when the reactive build held the collectedData read lock.
func TestReactiveScanPublishesNewestGraph(t *testing.T) {
	useReactiveNetwork(t)
	scan := newReactiveSNMPObject()

	hold := holdReverseDNS("10.0.8.51") // the endpoint behind the first switch
	first, second := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(first)
		scan.CollectData("10.0.8.1", "sw-r1")
	}()
	waitDone(t, hold.entered, "the first build to look up 10.0.8.51")
	go func() {
		defer close(second)
		scan.CollectData("10.0.8.2", "sw-r2")
	}()
	// Wait until the second switch is stored (at most 2 s: a build that keeps
	// the collectedData read lock delays the store until it is done). TryRLock
	// keeps this loop from queueing behind the waiting writer.
	for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); time.Sleep(time.Millisecond) {
		if !collectedDataMutex.TryRLock() {
			continue
		}
		_, stored := collectedData["10.0.8.2"]
		collectedDataMutex.RUnlock()
		if stored {
			break
		}
	}
	// Give the second callback time to build and publish, if it is not
	// made to wait for the first build.
	select {
	case <-second:
	case <-time.After(300 * time.Millisecond):
	}
	hold.free()
	waitDone(t, first, "the first switch's collection")
	waitDone(t, second, "the second switch's collection")

	got := GetGlobalGraph()
	if !got.Nodes["4c:ae:a3:08:00:02"] {
		t.Fatal("the graph published last has no node for 10.0.8.2: an older snapshot was published after a newer one")
	}
	want := goldenJSON(t, graphRecord(buildGraphFromSnapshot(snapshotCollectedData())), 2)
	if rec := goldenJSON(t, graphRecord(got), 2); !bytes.Equal(rec, want) {
		t.Fatalf("the graph published last is not the complete build of both switches:\n%s", lineDiff(want, rec, 20))
	}
	if n := liveAnalyses.Load(); n != 2 {
		t.Errorf("%d background analyses started, want one per collected switch (2)", n)
	}
}

// TestReactiveScanServesOnlyCompleteGraphs collects four switches at once
// with the SNMP object of the first scan, as main() does with one goroutine
// per switch, while four readers poll /api/graph (run it with -race too).
// Every graph served must be the complete build, hypervisor nodes and IP
// lines included, of some set of the switches, and the graph published last
// must be the complete build of all four (review findings B1 and C1).
func TestReactiveScanServesOnlyCompleteGraphs(t *testing.T) {
	useReactiveNetwork(t)
	devs := collectReactiveDevices(t)

	// The /api/graph response of the complete build of every subset. The
	// empty subset is also the graph main() publishes at startup.
	complete := map[string]string{}
	allSwitches := ""
	for mask := 0; mask < 1<<len(devs); mask++ {
		subset := map[string]*DeviceData{}
		var names []string
		for i, d := range devs {
			if mask&(1<<i) != 0 {
				cp := *d
				subset[d.IP] = &cp
				names = append(names, d.SysName)
			}
		}
		collectedDataMutex.Lock()
		collectedData = subset
		collectedDataMutex.Unlock()
		SetGlobalGraph(buildGraphFromSnapshot(snapshotCollectedData()))
		name := "{" + strings.Join(names, ",") + "}"
		complete[serveGraph()] = name
		allSwitches = name
	}
	if len(complete) != 1<<len(devs) {
		t.Fatalf("the complete builds of different switch sets are not all different (%d of %d)", len(complete), 1<<len(devs))
	}
	collectedDataMutex.Lock()
	collectedData = map[string]*DeviceData{}
	collectedDataMutex.Unlock()
	SetGlobalGraph(NewDJGraph())

	stop := make(chan struct{})
	var readers sync.WaitGroup
	stopReaders := sync.OnceFunc(func() {
		close(stop)
		readers.Wait()
	})
	defer stopReaders()
	var mu sync.Mutex
	served := map[string]int{}
	for i := 0; i < 4; i++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				body := serveGraph()
				mu.Lock()
				served[body]++
				mu.Unlock()
			}
		}()
	}
	scan := newReactiveSNMPObject()
	var collections sync.WaitGroup
	for _, d := range devs {
		collections.Add(1)
		go func(ip, name string) {
			defer collections.Done()
			scan.CollectData(ip, name)
		}(d.IP, d.SysName)
	}
	allDone := make(chan struct{})
	go func() {
		collections.Wait()
		close(allDone)
	}()
	waitDone(t, allDone, "the reactive collections")
	final := serveGraph()
	stopReaders()

	if name, ok := complete[final]; !ok || name != allSwitches {
		t.Fatalf("the graph published last is %q, want the complete build of %s", name, allSwitches)
	}
	for body, n := range served {
		if _, ok := complete[body]; !ok {
			t.Errorf("/api/graph served %d time(s) a graph that is not the complete build of any set of the switches:\n%.600s", n, body)
		}
	}
	if n := liveAnalyses.Load(); n != int64(len(devs)) {
		t.Errorf("%d background analyses started, want one per collected switch (%d)", n, len(devs))
	}
}
