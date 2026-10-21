package main

import (
	"bufio"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/klauspost/oui"
)

// edgeValues are hand-written MAC-like inputs: alternative spellings, special
// addresses, virtual and server OUIs, SNMP exception text, hostnames and IPs
// that LLDP or SNMP can deliver where a MAC is expected.
var edgeValues = []string{
	"",
	" ",
	"4C:AE:A3:8E:42:11",
	"4c-ae-a3-8e-42-11",
	"4C AE A3 8E 42 11",
	"4C AE A3 8E 42 11 ",
	"Hex-STRING: 4C AE A3 8E 42 11",
	"STRING: \"4c:ae:a3:8e:42:11\"",
	"\"4c:ae:a3:8e:42:11\"",
	"\"f8-f0-82-7a-d9-69\"",
	"f4-b5-20-19-12-5e",
	"5894.8000.f7a3",
	"b083.fe11.2233",
	"4caea32784cb",
	"0:c:29:aa:bb:cd",
	"0:0:0:0:0:0",
	"00:00:00:00:00:00",
	"00 00 00 00 00 00",
	"00-00-00-00-00-00",
	"000000000000",
	"00:00:00:12:34:56",
	"00:00:5e:00:01:14",
	"00:00:0c:07:ac:01",
	"ff:ff:ff:ff:ff:ff",
	"FF:FF:FF:FF:FF:FF",
	"01:00:5e:00:00:fb",
	"01:80:c2:00:00:0e",
	"03:00:00:00:00:01",
	"33:33:00:00:00:01",
	"02:42:ac:11:00:02",
	"02:11:22:33:44:55",
	"2:11:22:33:44:55",
	"da:a1:19:00:00:01",
	"52:54:00:12:34:56",
	"52-54-00-12-34-56",
	"bc:24:11:aa:bb:cc",
	"00:05:69:11:22:33",
	"00:1c:14:11:22:33",
	"00:50:56:aa:bb:cc",
	"00-50-56-aa-bb-cc",
	"00:0c:29:aa:bb:cc",
	"00:15:5d:11:22:33",
	"00:16:3e:11:22:33",
	"08:00:27:11:22:33",
	"F8:DB:88:11:22:33",
	"f8-db-88-11-22-33",
	"B0-83-FE-11-22-33",
	"0c:c4:7a:11:22:33",
	"00:18:82:11:22:33",
	"5c:ed:8c:ba:a4:7c",
	"f8:f0:82:7a:d9:69",
	"4c:ae:a3:27:84:cb",
	"00:25:b5:11:22:33",
	"a0:42:3f:11:22:33",
	"FA EF EF EF AA 4F",
	"01 AC 10 01 0F",
	"01 AC 10",
	"AC 10 01 0F",
	"\"pM{?WA\"",
	"pM{?WA",
	"\"P(J3:L\"",
	"No Such Object available on this agent at this OID",
	"No Such Instance currently exists at this OID",
	"no:such:object:available:on:this:agent:at:this:oid",
	"B-318/1",
	"E109-9",
	"A-332",
	"SW1",
	"DESKTOP-V380CHD",
	"\"DESKTOP-V380CHD\"",
	"FERUZA",
	"\"FERUZA\"",
	"lanxyz",
	"\"eth0\"",
	"\"uplink\"",
	"\"GigabitEthernet1/0/47\"",
	"a-b-c-d-e-f",
	"0.0.0.0",
	"0:0:0:0",
	"10.0.0.1",
	"172.16.1.15",
	"173.16.1.15",
	"172.20.1.254",
	"fe80::1",
	"aa:bb:cc:dd:ee",
	"aa:bb:cc:dd:ee:ff:00",
}

// edgeSubtypes are the LLDP subtypes normalizeID is evaluated with for the
// hand-written values (0: local chassis and unknown; 2/6: interface names;
// 3: port MAC; 4: chassis MAC; 5: network address; 7: locally assigned).
var edgeSubtypes = []int{0, 2, 3, 4, 5, 7}

// bmcNames are sample LLDP/DNS names for isBMC(x, name).
var bmcNames = []string{
	"", "core-sw-huawei", "srv01-idrac", "R720-DRAC", "ILOCZJ33411C3", "PC-ILONA",
	"esx01-ilo.tuit.local", "mgmt-bmc", "node1_bmc", "XCC-7X06", "server-imm",
	"cimc-ucs01", "irmc-rx300", "asmb-node", "ibmc-2288h", "ipmi-gw",
	"management-controller", "B-318/1", "DESKTOP-V380CHD",
}

// readListFile reads a frozen input list (one value per line, # comments).
func readListFile(t *testing.T, name string) []string {
	t.Helper()
	f, err := os.Open(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "#") {
			continue
		}
		if line == "<empty>" {
			line = ""
		}
		out = append(out, line)
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func boolBMC(ok bool, kind string) string {
	if ok {
		return "true:" + kind
	}
	return "false"
}

// TestGoldenMACPredicates evaluates every MAC predicate on every distinct
// MAC-like value of the fixture (FDB, ARP, LLDP chassis and port ids with
// their subtypes, local chassis ids, cache keys), one MAC per frozen OUI and
// the hand-written edge values. Results equal to the common default are
// omitted (see "omitted_defaults") so the file stays small.
func TestGoldenMACPredicates(t *testing.T) {
	resetState(t)
	devices := fixtureDevices(t)
	cache := fixtureCache(t)

	type entry struct {
		sources  map[string]bool
		subtypes map[int]bool
	}
	corpus := map[string]*entry{}
	add := func(v, source string, subtypes ...int) {
		e := corpus[v]
		if e == nil {
			e = &entry{sources: map[string]bool{}, subtypes: map[int]bool{}}
			corpus[v] = e
		}
		e.sources[source] = true
		for _, s := range subtypes {
			e.subtypes[s] = true
		}
	}
	for _, d := range devices {
		add(d.ChassisID, "local_chassis", 0)
		for _, m := range d.MACTable {
			add(m.MACAddress, "fdb")
		}
		for _, a := range d.ARPTable {
			add(a.MACAddress, "arp")
		}
		for _, n := range d.Neighbors {
			add(n.RemChassisId, fmt.Sprintf("lldp_chassis/%d", n.RemChassisIdSubtype), n.RemChassisIdSubtype)
			add(n.RemPortId, fmt.Sprintf("lldp_port/%d", n.RemPortIdSubtype), n.RemPortIdSubtype)
		}
	}
	for mac := range cache {
		add(mac, "cache")
	}
	for _, o := range readListFile(t, "predicate_ouis.txt") {
		add(o+":11:22:33", "oui_list")
	}
	for _, v := range edgeValues {
		add(v, "edge", edgeSubtypes...)
	}

	// isBMC(x, name) is shown per value only where it differs from the
	// name-only result isBMC("", name).
	baseline := map[string]string{}
	for _, name := range bmcNames {
		baseline[name] = boolBMC(isBMC("", name))
	}
	noNeighbors := &DeviceData{}

	values := map[string]map[string]any{}
	for v, e := range corpus {
		r := map[string]any{"src": strings.Join(slices.Sorted(maps.Keys(e.sources)), ",")}
		if n := normalizeMAC(v); n != v {
			r["normalizeMAC"] = n
		}
		lv := lookupVendor(v)
		if lv != "Unknown" {
			r["lookupVendor"] = lv
		}
		wantGet := lv
		if lv == "Unknown" {
			wantGet = ""
		}
		if gv := getMACVendor(v); gv != wantGet {
			r["getMACVendor"] = gv
		}
		if c := categorizeVendor(lv); c != "endpoint" {
			r["category"] = c
		}
		if isHypervisorMAC(v) {
			r["hypervisorMAC"] = true
		}
		if ok, vendor := isServerNIC(v); ok {
			r["serverNIC"] = vendor
		}
		if ok, kind := isBMC(v, ""); ok {
			r["bmc"] = kind
		}
		withNames := map[string]string{}
		for _, name := range bmcNames {
			if got := boolBMC(isBMC(v, name)); got != baseline[name] {
				withNames[name] = got
			}
		}
		if len(withNames) > 0 {
			r["bmcWithNames"] = withNames
		}
		if osLabel := detectOSFromMAC(v, map[string]string{}, noNeighbors); osLabel != "❓ Unknown VM" {
			r["detectOS"] = osLabel
		}
		if isSpecialMAC(v) {
			r["special"] = true
		}
		if isRandomMAC(v) {
			r["random"] = true
		}
		if isInvalidID(v) {
			r["invalid"] = true
		}
		if len(e.subtypes) > 0 {
			ids := map[string]string{}
			for _, s := range slices.Sorted(maps.Keys(e.subtypes)) {
				ids[strconv.Itoa(s)] = normalizeID(v, s)
			}
			r["normalizeID"] = ids
		}
		values[v] = r
	}

	categories := map[string]string{}
	for _, name := range readListFile(t, "vendor_names.txt") {
		categories[name] = categorizeVendor(name)
	}

	ouiInfo := map[string]any{"loaded": ouiDBOk}
	if raw, ok := ouiDB.(oui.RawGetter); ok {
		db := raw.RawDB()
		ouiInfo["entries"] = len(db)
		var sample []string
		for prefix, e := range db {
			sample = append(sample, fmt.Sprintf("%02x:%02x:%02x %s", prefix[0], prefix[1], prefix[2], e.Manufacturer))
		}
		slices.Sort(sample)
		if len(sample) > 10 {
			sample = sample[:10]
		}
		ouiInfo["first_entries"] = sample
	}

	rec := map[string]any{
		"oui_database": ouiInfo,
		"omitted_defaults": map[string]string{
			"normalizeMAC":  "equal to the value",
			"lookupVendor":  "Unknown",
			"getMACVendor":  "lookupVendor, with Unknown as \"\"",
			"category":      "endpoint (categorizeVendor of lookupVendor)",
			"hypervisorMAC": "false",
			"serverNIC":     "not a server NIC",
			"bmc":           "isBMC(value, \"\") is false",
			"bmcWithNames":  "isBMC(value, name) equals bmc_name_baseline for every name",
			"detectOS":      "❓ Unknown VM (no ping, empty macToIP, no neighbors)",
			"special":       "false",
			"random":        "false",
			"invalid":       "false",
			"normalizeID":   "only for LLDP values, local chassis ids (subtype 0) and edge values",
		},
		"bmc_name_baseline": baseline,
		"vendor_categories": categories,
		"value_count":       len(values),
		"values":            values,
	}
	checkGolden(t, "mac_predicates.json", goldenJSON(t, rec, 2))
}
