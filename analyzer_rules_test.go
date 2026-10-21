package main

import (
	"slices"
	"testing"
)

// Tests for the analyzer fixes.

func analyzerIssueIDs(suggestions []OptimizationSuggestion, typ string) []string {
	var out []string
	for _, s := range suggestions {
		if s.Type == typ {
			out = append(out, s.IssueID)
		}
	}
	return out
}

// TestAnalyzerLoopbackChassisGuard: a switch whose chassis id is empty (or
// null) cannot recognise itself, so it never reports a loopback (F17).
func TestAnalyzerLoopbackChassisGuard(t *testing.T) {
	resetState(t)
	cases := []struct {
		name, local, remote string
		macs                []MACEntry
		want                []string
	}{
		{name: "both chassis ids empty", local: "", remote: ""},
		{name: "local chassis id empty", local: "", remote: "4C AE A3 09 00 70"},
		{name: "remote chassis id empty", local: "4c:ae:a3:09:00:70", remote: ""},
		{name: "both chassis ids null", local: "00:00:00:00:00:00", remote: "00 00 00 00 00 00"},
		{name: "empty chassis id and an empty FDB MAC", local: "", remote: "", macs: macEntries(4, "")},
		{name: "own chassis as LLDP neighbor", local: "4c:ae:a3:09:00:70", remote: "4C AE A3 09 00 70", want: []string{"loop_lldp_10_0_9_70_3"}},
		{name: "own chassis MAC in the FDB", local: "4c:ae:a3:09:00:70", remote: "4C AE A3 09 00 71", macs: macEntries(4, "4c:ae:a3:09:00:70"), want: []string{"loop_mac_10_0_9_70_4"}},
	}
	for _, c := range cases {
		d := &DeviceData{
			IP: "10.0.9.70", ChassisID: c.local,
			Interfaces: gigabitPorts(4, nil),
			Neighbors:  []LLDPNeighbor{{LocalPortNum: 3, RemIndex: 1, RemChassisId: c.remote}},
			MACTable:   c.macs,
		}
		got := analyzerIssueIDs(NewAnalyzer(FullCaptureData{DevicesData: devicesData(d)}).analyzeLoopback(), "loopback")
		if !slices.Equal(got, c.want) {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}
