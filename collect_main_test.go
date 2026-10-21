package main

import (
	"maps"
	"slices"
	"testing"
)

// Tests for the collection callbacks that main() wires to the SNMP objects.

// collectTestAgent answers every walk of CollectData with a small table set.
// Each table can be left out to make that one walk fail.
func collectTestAgent(skip ...string) map[string][]string {
	walks := map[string][]string{
		oidChassis: {oidChassis + " = Hex-STRING: 4C AE A3 09 02 01 "},
		oidIfDescr: {
			oidIfDescr + ".1 = STRING: \"GigabitEthernet1/0/1\"",
			oidIfDescr + ".2 = STRING: \"GigabitEthernet1/0/2\"",
		},
		".1.3.6.1.2.1.2.2.1.8": {".1.3.6.1.2.1.2.2.1.8.1 = INTEGER: 1", ".1.3.6.1.2.1.2.2.1.8.2 = INTEGER: 1"},
		oidLLDPRem: {
			oidLLDPRem + ".4.0.2.1 = INTEGER: 4",
			oidLLDPRem + ".5.0.2.1 = Hex-STRING: 4C AE A3 09 02 02 ",
			oidLLDPRem + ".9.0.2.1 = STRING: \"sw-b\"",
		},
		oidFDBPort: {
			oidFDBPort + ".0.27.33.9.2.1 = INTEGER: 1",
			oidFDBPort + ".0.27.33.9.2.2 = INTEGER: 1",
			oidFDBPort + ".76.174.163.9.2.2 = INTEGER: 2",
		},
		collectBasePortIfIndexOID: {collectBasePortIfIndexOID + ".1 = INTEGER: 1", collectBasePortIfIndexOID + ".2 = INTEGER: 2"},
		oidARP:                    {oidARP + ".1.10.9.2.11 = Hex-STRING: 00 1B 21 09 02 01 "},
		oidPVID:                   {oidPVID + ".1 = INTEGER: 20", oidPVID + ".2 = INTEGER: 1"},
		oidSTPProto:               {oidSTPProto + ".0 = INTEGER: 3"},
		oidSTPRoot:                {oidSTPRoot + ".0 = Hex-STRING: 80 00 4C AE A3 09 02 02 "},
	}
	for _, oid := range skip {
		delete(walks, oid)
	}
	return walks
}

// collectStored returns the stored data of ip.
func collectStored(ip string) *DeviceData {
	collectedDataMutex.RLock()
	defer collectedDataMutex.RUnlock()
	return collectedData[ip]
}

// TestCollectPartialWalkKeepsTables checks F57: when some walks of a poll
// fail (but not all), the tables of those walks are kept from the previous
// poll instead of being replaced by nil, so the next snapshot has no LEAVE
// storm. A walk that succeeds with no rows does empty its table.
func TestCollectPartialWalkKeepsTables(t *testing.T) {
	resetState(t)
	const ip = "10.9.2.1"
	obj := newRescanSNMPObject()

	fakeSNMP.set(ip, collectTestAgent())
	obj.CollectData(ip, "sw-a")
	first := collectStored(ip)
	if first == nil || len(first.MACTable) != 3 || len(first.ARPTable) != 1 || len(first.Neighbors) != 1 ||
		len(first.PortVLANs) != 2 || !first.STPInfo.Enabled || len(first.Interfaces) != 2 || len(first.BridgePortIfIndex) != 2 {
		t.Fatalf("first poll not stored completely: %+v", first)
	}
	snap1 := CreateSnapshot([]*DeviceData{first}, nil, nil)

	// Second poll: every table walk times out except the chassis id.
	fakeSNMP.set(ip, collectTestAgent(oidIfDescr, oidLLDPRem, oidFDBPort, oidARP, oidPVID, oidSTPProto))
	obj.CollectData(ip, "sw-a")
	second := collectStored(ip)
	if second == first {
		t.Fatal("second poll was not stored")
	}
	if second.Unreachable {
		t.Error("partial success marked the switch unreachable")
	}
	if !slices.Equal(second.MACTable, first.MACTable) {
		t.Errorf("MACTable = %v, want the previous %v", second.MACTable, first.MACTable)
	}
	if !maps.Equal(second.BridgePortIfIndex, first.BridgePortIfIndex) {
		t.Errorf("BridgePortIfIndex = %v, want the previous %v", second.BridgePortIfIndex, first.BridgePortIfIndex)
	}
	if !slices.Equal(second.ARPTable, first.ARPTable) || len(second.Neighbors) != 1 ||
		!slices.EqualFunc(second.PortVLANs, first.PortVLANs, func(a, b PortVLAN) bool { return a.PortIndex == b.PortIndex && a.PVID == b.PVID }) ||
		second.STPInfo != first.STPInfo || len(second.Interfaces) != 2 {
		t.Errorf("failed walks did not keep their tables: %+v", second)
	}
	snap2 := CreateSnapshot([]*DeviceData{second}, nil, nil)
	if diff := CompareSnapshots(snap1, snap2); len(diff.LeftMACs) != 0 || len(diff.JoinedMACs) != 0 {
		t.Errorf("partial poll produced %d LEAVE and %d JOIN events", len(diff.LeftMACs), len(diff.JoinedMACs))
	}

	// Third poll: the FDB walk answers with no rows: the table is empty now.
	agent := collectTestAgent()
	agent[oidFDBPort] = nil
	fakeSNMP.set(ip, agent)
	obj.CollectData(ip, "sw-a")
	if third := collectStored(ip); len(third.MACTable) != 0 || third.MACTable == nil {
		t.Errorf("empty FDB walk: MACTable = %#v, want empty", third.MACTable)
	}
}

// TestCollectUnreachableKeepsData checks the OnFailure callback: when every
// walk fails the last data is kept and marked unreachable. The stored struct
// is replaced, so a reader holding the old pointer (snapshots and the
// analyzer read without the lock) never sees it change.
func TestCollectUnreachableKeepsData(t *testing.T) {
	resetState(t)
	const ip = "10.9.2.2"
	obj := newRescanSNMPObject()
	fakeSNMP.set(ip, collectTestAgent())
	obj.CollectData(ip, "sw-b")
	before := collectStored(ip)

	fakeSNMP.set(ip, map[string][]string{}) // every walk fails
	obj.CollectData(ip, "sw-b")
	after := collectStored(ip)
	if after == before {
		t.Fatal("OnFailure changed the stored struct in place")
	}
	if !after.Unreachable || before.Unreachable {
		t.Errorf("Unreachable: stored %v, old pointer %v; want true, false", after.Unreachable, before.Unreachable)
	}
	if !slices.Equal(after.MACTable, before.MACTable) || after.LastSeen != before.LastSeen {
		t.Error("OnFailure did not keep the last data")
	}

	// The next successful poll marks it reachable again.
	fakeSNMP.set(ip, collectTestAgent())
	obj.CollectData(ip, "sw-b")
	if collectStored(ip).Unreachable {
		t.Error("successful poll left the switch unreachable")
	}
}

// TestCollectRescanObjectStoresData checks F53: the SNMP object that rescans
// use when saved data was loaded (normal and monitor24h mode) stores what it
// collects. It used to be NewSNMPObject(nil, nil) in normal mode, which threw
// every rescan away.
func TestCollectRescanObjectStoresData(t *testing.T) {
	resetState(t)
	const ip = "10.9.2.3"
	collectedDataMutex.Lock()
	collectedData[ip] = &DeviceData{IP: ip, SysName: "sw-c", MACTable: macEntries(9, "00:1b:21:09:02:99")}
	collectedDataMutex.Unlock()

	obj := newRescanSNMPObject()
	if obj.OnSuccess == nil || obj.OnFailure == nil {
		t.Fatal("rescan SNMP object has nil callbacks")
	}
	fakeSNMP.set(ip, collectTestAgent())
	obj.CollectData(ip, "sw-c")
	got := collectStored(ip)
	if len(got.MACTable) != 3 || got.MACTable[0].MACAddress != "00:1b:21:09:02:01" {
		t.Errorf("rescan result not stored: MACTable = %v", got.MACTable)
	}
	if got.LastSeen.IsZero() {
		t.Error("LastSeen not set")
	}
}
