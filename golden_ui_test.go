package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// uiSwitch is the switch of the hand-made UI graph.
const uiSwitch = "4c:ae:a3:09:80:01"

// uiCaseGraph is a small graph, in the /api/graph format, with the node kinds
// the UI findings are about: a hypervisor node whose label lists VM IPs, an
// endpoint label with two IP lines, printer, server and unknown nodes, a link
// whose node is on the target side, hubs whose ESXi member has or has not a
// DNS name, a hub whose first link in the data goes to a member (its switch
// id sorts after it), and an LLDP name with markup.
func uiCaseGraph() GraphData {
	g := NewDJGraph()
	addInfoNode(g, uiSwitch, "sw-ui\n10.0.9.80")
	hyp := "hyp-" + uiSwitch + "-ge1_0_2"
	addInfoNode(g, hyp, "[HYPERVISOR] VMware ESXi\n2 VMs on ge1/0/2\nVMs: 10.0.9.61, 10.0.9.71")
	g.AddEdge(uiSwitch, hyp, "ge1/0/2")
	addInfoNode(g, "00:50:56:09:80:01", "[VM] 🐧 Linux VMware\n10.0.9.61")
	addInfoNode(g, "00:50:56:09:80:02", "[VM] 🪟 Windows VMware\n10.0.9.71")
	g.AddEdge(hyp, "00:50:56:09:80:01", "vNIC")
	g.AddEdge(hyp, "00:50:56:09:80:02", "vNIC")
	addInfoNode(g, "00:1b:21:09:80:03", "[ENDPOINT] Intel\n10.0.9.41\n10.0.9.4")
	g.AddEdge(uiSwitch, "00:1b:21:09:80:03", "GE1/0/3|")
	addInfoNode(g, "00:26:ab:09:80:04", "[ENDPOINT] Epson\n10.0.9.84")
	g.AddEdge(uiSwitch, "00:26:ab:09:80:04", "GE1/0/4|")
	addInfoNode(g, "linux-node", "")
	g.AddEdge(uiSwitch, "linux-node", "GE1/0/5|eth0")
	addInfoNode(g, "10.0.9.89", "")
	g.AddEdge(uiSwitch, "10.0.9.89", "GE1/0/6|")
	addInfoNode(g, "4c:ae:a3:09:80:07", "[LLDP-EP] SNR\nsw-peer")
	g.AddEdge(uiSwitch, "4c:ae:a3:09:80:07", "GE1/0/7 1G|GE1/0/48")

	hub8, hub9 := "hub-"+uiSwitch+"-p8", "hub-"+uiSwitch+"-p9"
	addInfoNode(g, hub8, "[HUB] Unmanaged\n2 devices")
	g.AddEdge(uiSwitch, hub8, "GE1/0/8|Hub")
	addInfoNode(g, "00:1b:21:09:80:81", "[HYPERVISOR] VMware ESXi\n[ENDPOINT] Intel\n10.0.9.81\n[DNS] esx-a")
	addInfoNode(g, "00:1b:21:09:80:82", "[ENDPOINT] Intel\n10.0.9.82")
	g.AddEdge(hub8, "00:1b:21:09:80:81", "")
	g.AddEdge(hub8, "00:1b:21:09:80:82", "")
	addInfoNode(g, hub9, "[HUB] Unmanaged\n2 devices")
	g.AddEdge(uiSwitch, hub9, "GE1/0/9|Hub")
	addInfoNode(g, "00:1b:21:09:80:91", "[HYPERVISOR] VMware ESXi\n[ENDPOINT] Intel\n10.0.9.91")
	addInfoNode(g, "00:1b:21:09:80:92", "[ENDPOINT] Intel")
	g.AddEdge(hub9, "00:1b:21:09:80:91", "")
	g.AddEdge(hub9, "00:1b:21:09:80:92", "")

	const merged = "no:such:object:available:on:this:agent:at:this:oid"
	addInfoNode(g, merged, "sw-x\n10.0.9.90")
	hubX := "hub-" + merged + "-p3"
	addInfoNode(g, hubX, "[HUB] Unmanaged\n2 devices")
	g.AddEdge(merged, hubX, "GE1/0/3|Hub")
	addInfoNode(g, "00:1b:21:09:80:a1", "[ENDPOINT] Intel\n10.0.9.101")
	addInfoNode(g, "00:1b:21:09:80:a2", "[ENDPOINT] Intel")
	g.AddEdge(hubX, "00:1b:21:09:80:a1", "")
	g.AddEdge(hubX, "00:1b:21:09:80:a2", "")

	addInfoNode(g, "aa:bb:cc:09:86:01", "[LLDP-EP]\n<img src=x onerror=alert(1)> shadow")
	g.AddEdge(uiSwitch, "aa:bb:cc:09:86:01", "GE1/0/10|eth0")
	return g.GetGraphData()
}

// TestGoldenUIApp runs static/app.js, unmodified, in Node.js with a stub DOM
// (testdata/ui/app_probe.js) and pins what its helpers do with the fixture
// graph, uiCaseGraph and the rule network's graph (built by the production
// build, with a hub whose two VM NICs sit below a hyp- node): the group
// colours next to the filter legend, the group filter, "Show Connected
// Devices", the info panel, the IP that History and Connect use, and the
// Shadow-IT list. Skipped when Node.js is not installed.
func TestGoldenUIApp(t *testing.T) {
	node := nodeBinary(t)
	resetState(t)
	rule := buildGraphFromSnapshot(analyzerDeviceMap(analyzerRuleNetwork())).GetGraphData()
	fixture := buildFixtureGraph(t).GetGraphData()
	busiest, links := "", -1
	degree := map[string]int{}
	for _, l := range fixture.Links {
		degree[l.Source]++
		degree[l.Target]++
	}
	for _, n := range fixture.Nodes {
		if n.Group == "switch" && degree[n.ID] > links {
			busiest, links = n.ID, degree[n.ID]
		}
	}
	hyp := "hyp-" + uiSwitch + "-ge1_0_2"
	cases := map[string]any{
		"graphs": map[string]GraphData{"fixture": fixture, "ui": uiCaseGraph(), "rule": rule},
		"connected": []map[string]string{
			{"graph": "fixture", "node": busiest},
			{"graph": "ui", "node": uiSwitch},
		},
		"info_panel": []map[string]string{
			{"graph": "ui", "node": uiSwitch},
			{"graph": "ui", "node": "4c:ae:a3:09:80:07"},
			{"graph": "ui", "node": "00:50:56:09:80:01"},
			{"graph": "ui", "node": "hub-" + uiSwitch + "-p8"},
			{"graph": "ui", "node": "aa:bb:cc:09:86:01"},
		},
		"ip_choice": []map[string]string{
			{"graph": "ui", "node": hyp},
			{"graph": "ui", "node": "00:1b:21:09:80:03"},
			{"graph": "ui", "node": uiSwitch},
		},
		"shadow_it": []string{"fixture", "ui", "rule"},
	}
	data, err := json.Marshal(cases)
	if err != nil {
		t.Fatal(err)
	}
	casesPath := filepath.Join(t.TempDir(), "cases.json")
	if err := os.WriteFile(casesPath, data, 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(node, filepath.Join("testdata", "ui", "app_probe.js"),
		filepath.Join("static", "app.js"), filepath.Join("static", "index.html"), casesPath)
	cmd.Env = []string{}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("app_probe.js: %v\n%s", err, stderr.String())
	}
	dec := json.NewDecoder(bytes.NewReader(out))
	dec.UseNumber()
	var rec any
	if err := dec.Decode(&rec); err != nil {
		t.Fatalf("app_probe.js output: %v\n%.500s", err, out)
	}
	checkGolden(t, "ui_app.json", goldenJSON(t, rec, 3))
}

// TestGoldenUITree runs testdata/ui/tree_probe.js, the Node tests of the
// Tree tab: static/tree.js's builder on a synthetic graph and on the fixture
// graph (testdata/golden/graph.json), and the tab itself (static/app.js and
// static/tree.js, unmodified, with a stub DOM and a model of jsTree): among
// others the device search typed key by key and the info panel's list of
// connected devices. A failed check fails the test. It pins the checks and the fixture's tree with the default
// filters and with only 'vm' shown. graph.json is TestGoldenGraph's golden,
// which runs first, so one -update run rewrites both. Skipped when Node.js
// is not installed.
func TestGoldenUITree(t *testing.T) {
	node := nodeBinary(t)
	cmd := exec.Command(node, filepath.Join("testdata", "ui", "tree_probe.js"),
		filepath.Join("static", "tree.js"), filepath.Join("testdata", "golden", "graph.json"),
		filepath.Join("static", "index.html"), filepath.Join("static", "app.js"))
	cmd.Env = []string{}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("tree_probe.js: %v\n%s", err, stderr.String())
	}
	dec := json.NewDecoder(bytes.NewReader(out))
	dec.UseNumber()
	var rec any
	if err := dec.Decode(&rec); err != nil {
		t.Fatalf("tree_probe.js output: %v\n%.500s", err, out)
	}
	checkGolden(t, "ui_tree.json", goldenJSON(t, rec, 4))
}

// nodeBinary returns a Node.js 16+ binary, or skips the test.
func nodeBinary(t *testing.T) string {
	t.Helper()
	if path := nodePath(); path != "" {
		return path
	}
	t.Skip("Node.js 16 or newer is not installed, so static/app.js is not checked")
	return ""
}

// nodePath returns a Node.js 16+ binary, or "" when none is installed.
func nodePath() string {
	for _, name := range []string{"node", "nodejs"} {
		path, err := exec.LookPath(name)
		if err != nil {
			continue
		}
		version, err := exec.Command(path, "--version").Output()
		var major int
		if _, scanErr := fmt.Sscanf(strings.TrimSpace(string(version)), "v%d", &major); err == nil && scanErr == nil && major >= 16 {
			return path
		}
	}
	return ""
}

// uiShadowModalHubs runs static/app.js's Shadow-IT modal (showShadowIT) on
// data, as /api/graph serves it, and returns the node ids of its entries,
// sorted; ok is false when Node.js is not installed.
func uiShadowModalHubs(t *testing.T, data GraphData) (hubs []string, ok bool) {
	t.Helper()
	node := nodePath()
	if node == "" {
		return nil, false
	}
	cases := map[string]any{
		"graphs":    map[string]GraphData{"g": data},
		"connected": []any{}, "info_panel": []any{}, "ip_choice": []any{},
		"shadow_it": []string{"g"},
	}
	raw, err := json.Marshal(cases)
	if err != nil {
		t.Fatal(err)
	}
	casesPath := filepath.Join(t.TempDir(), "cases.json")
	if err := os.WriteFile(casesPath, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(node, filepath.Join("testdata", "ui", "app_probe.js"),
		filepath.Join("static", "app.js"), filepath.Join("static", "index.html"), casesPath)
	cmd.Env = []string{}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("app_probe.js: %v\n%s", err, stderr.String())
	}
	var rec struct {
		ShadowIT map[string]struct {
			NodeIDs []string `json:"node_ids"`
		} `json:"shadow_it"`
	}
	if err := json.Unmarshal(out, &rec); err != nil {
		t.Fatalf("app_probe.js output: %v\n%.500s", err, out)
	}
	hubs = slices.Clone(rec.ShadowIT["g"].NodeIDs)
	slices.Sort(hubs)
	return hubs, true
}

// TestNoBotTokenInSource fails when a Telegram bot token is written into the
// bot sources (finding F87). The bot reads its token from TELEGRAM_BOT_TOKEN
// or from bot/.bot_token, which git ignores and this test does not read.
func TestNoBotTokenInSource(t *testing.T) {
	token := regexp.MustCompile(`[0-9]{8,10}:[A-Za-z0-9_-]{35}`)
	var files []string
	for _, pattern := range []string{"*.py", "*.sh", "*.service"} {
		matches, err := filepath.Glob(filepath.Join("bot", pattern))
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, matches...)
	}
	if len(files) == 0 {
		t.Fatal("no bot sources found")
	}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if token.Match(data) {
			t.Errorf("%s contains what looks like a Telegram bot token; read it from TELEGRAM_BOT_TOKEN or bot/.bot_token instead", f)
		}
	}
}
