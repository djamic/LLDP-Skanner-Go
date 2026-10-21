package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// labelTokens are the label markers the graph build writes and the UI or the
// reports parse back by substring.
var labelTokens = []string{
	"[ENDPOINT]", "[LLDP-EP]", "[HUB]", "[WiFi]", "[BMC]", "[VM]", "[HYPERVISOR]",
	"[DNS]", "[MAC-REF]", "[T]", "VMs:", "vNIC", "|Hub", "Unmanaged", "VMware ESXi", "Server\n",
}

type tokenUse struct {
	Nodes        int  `json:"graph_nodes"`
	Edges        int  `json:"graph_edges"`
	AppJS        bool `json:"app_js"`
	AppJSLower   bool `json:"app_js_lowercase"`
	IndexHTML    bool `json:"index_html"`
	IndexHTMLLow bool `json:"index_html_lowercase"`
}

type groupUse struct {
	Nodes        int  `json:"graph_nodes"`
	UICheckbox   bool `json:"index_html_data_group"`
	AppJSLiteral bool `json:"app_js_literal"`
}

// TestGoldenLabelContract pins the label contract between the Go graph build
// and the UI: how often each label token occurs in the fixture graph and
// whether static/app.js and static/index.html refer to it, and for every
// group in the graph whether the UI has a filter checkbox for it.
func TestGoldenLabelContract(t *testing.T) {
	graph := buildFixtureGraph(t)
	readStatic := func(name string) string {
		data, err := os.ReadFile(filepath.Join("static", name))
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	appJS, indexHTML := readStatic("app.js"), readStatic("index.html")

	tokens := map[string]tokenUse{}
	for _, tok := range labelTokens {
		u := tokenUse{
			AppJS:        strings.Contains(appJS, tok),
			AppJSLower:   strings.Contains(appJS, strings.ToLower(tok)),
			IndexHTML:    strings.Contains(indexHTML, tok),
			IndexHTMLLow: strings.Contains(indexHTML, strings.ToLower(tok)),
		}
		for id := range graph.Nodes {
			if strings.Contains(graph.SwitchInfo[id], tok) {
				u.Nodes++
			}
		}
		for _, targets := range graph.Edges {
			for _, label := range targets {
				if strings.Contains(label, tok) {
					u.Edges++
				}
			}
		}
		tokens[tok] = u
	}

	groups := map[string]groupUse{}
	for _, n := range graph.GetGraphData().Nodes {
		g := groups[n.Group]
		g.Nodes++
		groups[n.Group] = g
	}
	for _, name := range []string{"switch", "router", "hub", "endpoint", "access_point", "vm", "hypervisor", "bmc", "camera", "phone", "iot", "wifi_random", "printer", "server", "unknown"} {
		g := groups[name]
		g.UICheckbox = strings.Contains(indexHTML, `data-group="`+name+`"`)
		g.AppJSLiteral = strings.Contains(appJS, "'"+name+"'") || strings.Contains(appJS, `"`+name+`"`)
		groups[name] = g
	}
	checkGolden(t, "label_contract.json", goldenJSON(t, map[string]any{"tokens": tokens, "groups": groups}, 2))
}
