package main

import (
	"slices"
	"strings"
	"testing"
)

// reportLiveESXiHosts are MACs the live scanner confirmed as ESXi hosts. In
// the fixture the first two are members of the hubs hub-…27:7e:ca-p3 and
// hub-…8d:ee:c9-p18, and the other three sit on the same switch port as a
// hyp- node.
var reportLiveESXiHosts = []string{
	"c4:34:6b:b8:41:94", "08:f1:ea:8d:26:4e",
	"98:f2:b3:22:5c:18", "d4:f5:ef:4d:b5:cf", "50:7c:6f:62:e2:4c",
}

// TestGoldenReportESXiSections pins audit sections 7 (Shadow IT) and 8
// (hypervisors) for the fixture with the confirmed ESXi hosts of
// TestGoldenGraphESXi and reportLiveESXiHosts, which the default audit
// golden (no confirmed hosts) does not reach.
func TestGoldenReportESXiSections(t *testing.T) {
	useFixture(t)
	for _, mac := range slices.Concat(esxiConfirmedMACs, reportLiveESXiHosts) {
		ConfirmedESXiMACs.Store(mac, true)
	}
	SetGlobalGraph(buildGraphFromSnapshot(snapshotCollectedData()))
	md := canonicalAuditMD(generateAuditMD([]string{"switch", "hub"}))
	start, end := strings.Index(md, "## 7."), strings.Index(md, "## 9.")
	if start < 0 || end < start {
		t.Fatalf("audit report has no sections 7 and 8")
	}
	checkGolden(t, "report_esxi_sections.md", []byte(md[start:end]))
}
