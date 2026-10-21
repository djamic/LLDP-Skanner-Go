package main

import (
	"bytes"
	"encoding/json"
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
// groups, the analyzer's Shadow-IT alerts and the experiment counts.
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
	KnownMAC       string `json:"known_mac"`
}

// TestGoldenLLDPTargets pins, for every LLDP neighbor in the fixture (in
// stored order), the normalized ids (chassis and port subtype tables), the
// node id and display name chosen by resolveLLDPTarget, whether
// graphUsableTargetID drops it, whether the local port is a NULL interface,
// and the knownMACs key (the target of an accepted neighbor).
func TestGoldenLLDPTargets(t *testing.T) {
	resetState(t)
	devices := fixtureDevices(t)
	var rows []lldpTarget
	for _, d := range sortedDevices(devices) {
		for _, n := range d.Neighbors {
			target, display := resolveLLDPTarget(n)
			portName := getLocalPortName(d, n.LocalPortNum)
			known := ""
			if graphUsableTargetID(target) && !isNullInterface(portName) {
				known = target
			}
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
				NormChassis:    normalizeID(n.RemChassisId, n.RemChassisIdSubtype),
				NormPort:       graphNormalizePortID(n.RemPortId, n.RemPortIdSubtype),
				Target:         target,
				Display:        display,
				Invalid:        !graphUsableTargetID(target),
				KnownMAC:       known,
			})
		}
	}
	checkGolden(t, "lldp_targets.json", goldenJSON(t, map[string]any{"neighbors": rows}, 2))
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
