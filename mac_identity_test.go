package main

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"
)

// ouiTestIEEENames reads the organization name of every record of the shipped
// oui.txt, keyed "aa:bb:cc". It parses the file itself, so these tests do not
// depend on the loader they check.
func ouiTestIEEENames(t *testing.T) map[string]string {
	t.Helper()
	f, err := os.Open("oui.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	re := regexp.MustCompile(`^([0-9A-Fa-f]{2})-([0-9A-Fa-f]{2})-([0-9A-Fa-f]{2})\s+\(hex\)\s*(.*)$`)
	names := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if m := re.FindStringSubmatch(sc.Text()); m != nil {
			names[strings.ToLower(m[1]+":"+m[2]+":"+m[3])] = strings.TrimSpace(m[4])
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return names
}

// ouiTestSameCompany lists, for every curated vendor name, the lowercase
// fragments of an IEEE organization name that mean "the same company".
var ouiTestSameCompany = map[string][]string{
	"SNR": {"nagtech"}, "HPE": {"hewlett"}, "H3C": {"h3c"}, "HP": {"hewlett", "hp inc"},
	"HP Aruba": {"hewlett", "aruba"}, "Aruba": {"hewlett", "aruba"}, "Ubiquiti": {"ubiquiti"},
	"Cisco": {"cisco"}, "Dell": {"dell"}, "MikroTik": {"routerboard", "mikrotik"},
	"Huawei": {"huawei"}, "ZTE": {"zte"}, "TP-Link": {"tp-link"}, "D-Link": {"d-link"},
	"Eltex": {"eltex"}, "BizLink": {"bizlink"}, "Fortinet": {"fortinet"},
	"VMware": {"vmware"}, "Hyper-V": {"microsoft"}, "VirtualBox": {"pcs systemtechnik", "oracle"},
	"Xen": {"xensource"}, "Proxmox": {"proxmox"}, "QEMU/KVM": nil,
	"Dahua": {"dahua"}, "Hikvision": {"hikvision"}, "Lengda": {"lengda"},
	"Realtek": {"realtek"}, "EliteGroup": {"elitegroup"}, "Gigabyte": {"giga-byte"},
	"Intel": {"intel"}, "ASUS": {"asustek"}, "Biostar": {"biostar"}, "Supermicro": {"super micro"},
	"Tyan": {"tyan"}, "MSI": {"micro-star"}, "Wistron": {"wistron"}, "Compal": {"compal"},
	"Shiyuan": {"shiyuan"}, "Quanta": {"quanta"}, "LCFC": {"lcfc"}, "AzureWave": {"azurewave"},
	"Lianrui": {"lianrui"}, "Inventec": {"inventec"}, "Hon Hai": {"hon hai"}, "Fugui": {"fugui"},
	"Inspire Tech": {"inspire tech"}, "Murata": {"murata"},
	"Apple": {"apple"}, "Samsung": {"samsung"}, "Xiaomi": {"xiaomi"}, "OPPO": {"oppo"}, "vivo": {"vivo"},
	"Epson": {"epson"}, "Canon": {"canon"}, "Brother": {"brother"},
	"ESP (Espressif)": {"espressif"}, "IANA (VRRP)": {"iana"},
}

// ouiTestUnlisted are curated OUIs that oui.txt does not list at all. IEEE
// does not contradict them, so they keep their curated name.
var ouiTestUnlisted = map[string]bool{"00:cf:e0": true, "88:44:36": true, "5c:69:60": true}

// ouiTestNamelessIEEE are curated OUIs whose IEEE record has an empty name.
var ouiTestNamelessIEEE = map[string]bool{"52:54:00": true}

// TestOUICuratedVendorsAgreeWithIEEE is the evidence for the curated vendor
// names (Q2, Q3): every name must be the company IEEE registered the OUI to.
// No placeholder names, no "Private" registrations.
func TestOUICuratedVendorsAgreeWithIEEE(t *testing.T) {
	ieee := ouiTestIEEENames(t)
	if len(ieee) < 39000 {
		t.Fatalf("oui.txt has %d records, want about 39,000", len(ieee))
	}
	for prefix, vendor := range extendedVendorDB {
		org, listed := ieee[prefix]
		words, known := ouiTestSameCompany[vendor]
		switch {
		case !known:
			t.Errorf("%s %q: curated name without an IEEE alias in ouiTestSameCompany", prefix, vendor)
		case !listed:
			if !ouiTestUnlisted[prefix] {
				t.Errorf("%s %q: not in oui.txt", prefix, vendor)
			}
		case org == "":
			if !ouiTestNamelessIEEE[prefix] {
				t.Errorf("%s %q: oui.txt has no name for it", prefix, vendor)
			}
		case !ouiTestContainsAny(strings.ToLower(org), words):
			t.Errorf("%s: curated %q, but IEEE registers it to %q", prefix, vendor, org)
		}
	}
}

func ouiTestContainsAny(s string, words []string) bool {
	for _, w := range words {
		if strings.Contains(s, w) {
			return true
		}
	}
	return false
}

// TestOUIVendorRenames pins the owner decisions on vendor text (Q2, Q3).
func TestOUIVendorRenames(t *testing.T) {
	for _, c := range []struct{ mac, want string }{
		{"4c:ae:a3:27:84:cb", "HPE"}, // Q2: HPE Comware switches, was "SNR"
		{"00:0f:e2:11:22:33", "H3C"}, // Q2: was "SNR"
		{"f8:f0:82:7a:d9:69", "SNR"}, // NAGTECH builds the SNR switches
		{"78:45:58:11:22:33", "Ubiquiti"},
		{"bc:9b:5e:11:22:33", "Hikvision"},
		{"98:ee:cb:11:22:33", "Wistron"},
		{"00:e2:69:53:ec:10", "Unknown"}, // placeholder "Unknown (OUI 00:e2:69)" dropped
		{"64:6e:ea:11:22:33", "Unknown"}, // placeholder "Unknown (OUI 64:6e:ea)" dropped
		{"48:f3:17:07:58:7f", "Unknown"}, // IEEE "Private": "Shenzhen Reecam" dropped
		{"52:54:00:12:34:56", "QEMU/KVM"},
	} {
		if got := lookupVendor(c.mac); got != c.want {
			t.Errorf("lookupVendor(%q) = %q, want %q", c.mac, got, c.want)
		}
	}
}

// TestCategorizeVendor: curated names have an explicit category; IEEE names
// go through whole-word rules that leave multi-category vendors at
// "endpoint" and never give "vm" (F6).
func TestCategorizeVendor(t *testing.T) {
	for _, c := range []struct{ vendor, want string }{
		// curated names
		{"SNR", "network"}, {"HPE", "network"}, {"H3C", "network"}, {"Eltex", "network"},
		{"Fortinet", "network"}, {"Ubiquiti", "access_point"}, {"Hikvision", "camera"},
		{"Huawei", "endpoint"}, {"ZTE", "endpoint"}, {"Wistron", "endpoint"},
		{"Apple", "phone"}, {"Samsung", "phone"}, {"Epson", "printer"},
		{"ESP (Espressif)", "iot"}, {"VMware", "vm"}, {"QEMU/KVM", "vm"}, {"Hyper-V", "vm"},
		// IEEE organization names
		{"VIVOTEK INC.", "camera"}, {"Vivotek, Inc.", "camera"},
		{"Zhejiang Dahua Technology Co., Ltd.", "camera"}, {"Axis Communications AB", "camera"},
		{"Ace Axis Limited", "endpoint"},
		{"Ubiquiti Inc", "access_point"}, {"Cisco Meraki", "access_point"},
		{"Aruba, a Hewlett Packard Enterprise Company", "access_point"},
		{"Seiko Epson Corporation", "printer"}, {"Brother industries, LTD.", "printer"},
		{"Brother, Brother & Sons ApS", "endpoint"},
		{"KYOCERA Document Solutions Inc.", "printer"}, {"KYOCERA Corporation", "endpoint"},
		{"GUANGDONG OPPO MOBILE TELECOMMUNICATIONS CORP.,LTD", "phone"}, {"OPPO Digital, Inc.", "endpoint"},
		{"vivo Mobile Communication Co., Ltd.", "phone"}, {"HMD Global Oy", "phone"},
		{"Espressif Inc.", "iot"}, {"Shenzhen Lianrui Electronics Co.,Ltd", "endpoint"},
		{"Hewlett Packard Enterprise", "network"}, {"Hewlett Packard", "network"}, {"HP Inc.", "network"},
		{"Cisco Systems, Inc", "network"}, {"Routerboard.com", "network"}, {"NAGTECH LLC", "network"},
		{"Hangzhou H3C Technologies Co., Limited", "network"}, {"Dell Inc.", "network"},
		{"Juniper Networks", "network"}, {"Juniper Systems", "endpoint"},
		{"Italdata Ingegneria dell'Idea S.p.A.", "endpoint"},
		{"HUAWEI TECHNOLOGIES CO.,LTD", "endpoint"}, {"Apple, Inc.", "endpoint"},
		{"Samsung Electronics Co.,Ltd", "endpoint"}, {"Microsoft Corporation", "endpoint"},
		{"Xiaomi Communications Co Ltd", "endpoint"},
		{"VMware, Inc.", "endpoint"}, {"Xensource, Inc.", "endpoint"}, {"Crexendo", "endpoint"},
		{"Proxmox Server Solutions GmbH", "endpoint"}, {"PCS Systemtechnik GmbH", "endpoint"},
		{"", "endpoint"}, {"Unknown", "endpoint"},
	} {
		if got := categorizeVendor(c.vendor); got != c.want {
			t.Errorf("categorizeVendor(%q) = %q, want %q", c.vendor, got, c.want)
		}
	}
}

// TestOUICuratedCategories: every curated vendor name has a category, and
// "vm" belongs exactly to the virtual-NIC OUIs.
func TestOUICuratedCategories(t *testing.T) {
	valid := map[string]bool{"camera": true, "access_point": true, "printer": true, "phone": true,
		"iot": true, "vm": true, "network": true, "endpoint": true}
	virtual := map[string]bool{}
	for _, p := range hypervisorMACPrefixes {
		virtual[p] = true
	}
	for prefix, vendor := range extendedVendorDB {
		cat, ok := ouiVendorCategory[vendor]
		if !ok || !valid[cat] {
			t.Errorf("%s %q: category %q", prefix, vendor, cat)
		}
		if (cat == "vm") != virtual[prefix] {
			t.Errorf("%s %q: category %q, virtual NIC %v", prefix, vendor, cat, virtual[prefix])
		}
	}
}

// ouiTestServerMakers lists, for every server-NIC label, the fragments of
// the IEEE organization name it may stand for. 34:40:b5 is registered to IBM
// and labelled Lenovo, which took over IBM's x86 servers (Q6 keeps it).
var ouiTestServerMakers = map[string][]string{
	"Dell": {"dell"}, "Dell PowerEdge": {"dell"}, "HPE": {"hewlett"}, "HPE ProLiant": {"hewlett"},
	"SuperMicro": {"super micro"}, "Tyan": {"tyan"}, "Lenovo": {"lenovo", "ibm"},
	"Cisco UCS": {"cisco"}, "Fujitsu": {"fujitsu"}, "IBM": {"ibm"},
}

// TestServerNICsAreServerMakers: every OUI isServerNIC accepts belongs to the
// server maker of its label, so no PC or switch maker is a "server" (Q6, Q7).
func TestServerNICsAreServerMakers(t *testing.T) {
	n := 0
	for prefix, org := range ouiTestIEEENames(t) {
		ok, label := isServerNIC(prefix + ":00:00:01")
		if !ok {
			continue
		}
		n++
		if !ouiTestContainsAny(strings.ToLower(org), ouiTestServerMakers[label]) {
			t.Errorf("%s: server NIC %q, but IEEE registers it to %q", prefix, label, org)
		}
	}
	if n != 34 {
		t.Errorf("%d server-NIC OUIs, want 34", n)
	}
}

// TestServerNICDecisions pins the owner decisions on the server-NIC table.
func TestServerNICDecisions(t *testing.T) {
	for _, c := range []struct {
		mac   string
		ok    bool
		label string
	}{
		{"f8:f0:82:7a:d9:69", false, ""}, // Q7: NAGTECH builds SNR switches
		{"e8:6a:64:11:22:33", false, ""}, // Q6: LCFC (Lenovo PC ODM)
		{"54:ee:75:11:22:33", false, ""}, // Q6: Wistron
		{"08:94:ef:11:22:33", false, ""}, // Q6: Wistron
		{"7c:d3:0a:11:22:33", false, ""}, // Q6: Inventec
		{"00:1b:24:11:22:33", false, ""}, // Q6: Quanta
		{"74:56:3c:bb:d0:16", false, ""}, // Q6: GIGA-BYTE
		{"a0:36:9f:11:22:33", false, ""}, // Q6: Intel
		{"00:23:ae:11:22:33", false, ""}, // Q6: Dell PCs, was "Lenovo"
		{"a0:42:3f:11:22:33", true, "Tyan"},
		{"34:40:b5:11:22:33", true, "Lenovo"},
		{"5c:ed:8c:ba:a4:7c", true, "HPE ProLiant"},
		{"0c:c4:7a:11:22:33", true, "SuperMicro"},
		{"F8:DB:88:11:22:33", true, "Dell"},
	} {
		ok, label := isServerNIC(c.mac)
		if ok != c.ok || label != c.label {
			t.Errorf("isServerNIC(%q) = %v, %q; want %v, %q", c.mac, ok, label, c.ok, c.label)
		}
	}
}

// TestIsBMC: a BMC is recognised only by a keyword in its LLDP or DNS name;
// the OUI only names the maker of a generic "BMC"/"IPMI" (Q5; F32, F33).
func TestIsBMC(t *testing.T) {
	for _, c := range []struct{ mac, name, want string }{
		{"", "", ""},
		{"00:18:82:11:22:33", "", ""}, // Huawei NICs share the iBMC OUI
		{"0c:c4:7a:11:22:33", "", ""}, // Supermicro onboard NICs
		{"f8:db:88:11:22:33", "", ""},
		{"70:85:c2:11:22:33", "", ""}, // ASRock desktop boards
		{"00:18:82:11:22:33", "core-sw-huawei", ""},
		{"x", "ILOCZJ33411C3", "HPE iLO"}, // iLO default name: ILO + serial
		{"x", "ILOCZ240304GY.tuit.local", "HPE iLO"},
		{"x", "PC-ILONA", ""},
		{"x", "kamilo.tuit.uz", ""},
		{"x", "ilovepizza12", ""},
		{"x", "pc-immanuel", ""},
		{"x", "firmcorp-pc", ""},
		{"x", "mgmt-bmc", "BMC"},
		{"x", "bmc-node1", "BMC"},
		{"x", "node1_bmc", "BMC"},
		{"x", "rack2.bmc01", "BMC"},
		{"x", "esx01-ilo.tuit.local", "HPE iLO"},
		{"x", "ilo5-esx01", "HPE iLO"},
		{"x", "srv01-idrac", "Dell iDRAC"},
		{"x", "idrac-ABC1234", "Dell iDRAC"},
		{"x", "R720-DRAC", "Dell iDRAC"},
		{"x", "XCC-7X06-J30A1234", "Lenovo XCC"},
		{"x", "srv-xclarity", "Lenovo XCC"},
		{"x", "IMM-40f2e9abcdef", "Lenovo IMM"},
		{"x", "server-imm", "Lenovo IMM"},
		{"x", "iRMCF844A6", "Fujitsu iRMC"},
		{"x", "irmc-rx300", "Fujitsu iRMC"},
		{"x", "cimc-ucs01", "Cisco CIMC"},
		{"x", "ASMB9-iKVM", "ASUS ASMB"},
		{"x", "ibmc-2288h", "Huawei iBMC"},
		{"x", "ipmi-gw", "IPMI"},
		{"x", "management-controller", "BMC"},
		{"x", "DESKTOP-V380CHD", ""},
		{"x", "B-318/1", ""},
		{"0c:c4:7a:09:00:16", "node16-ipmi", "Supermicro IPMI"},
		{"f8:db:88:11:22:33", "rack1-bmc", "Dell iDRAC"},
		{"d0:50:99:11:22:33", "rack1-bmc", "ASRock IPMI"}, // was "Lenovo XCC"
		{"3c:a8:2a:11:22:33", "srv01-idrac", "Dell iDRAC"},
	} {
		ok, kind := isBMC(c.mac, c.name)
		if ok != (c.want != "") || kind != c.want {
			t.Errorf("isBMC(%q, %q) = %v, %q; want %q", c.mac, c.name, ok, kind, c.want)
		}
	}
}

// TestBMCKeywordsReachable: no keyword is shadowed by an earlier one.
func TestBMCKeywordsReachable(t *testing.T) {
	for _, kw := range macBMCKeywords {
		if kw.match == "serial" {
			continue
		}
		if got := bmcTypeByName(kw.keyword); got != kw.kind {
			t.Errorf("bmcTypeByName(%q) = %q, want %q", kw.keyword, got, kw.kind)
		}
	}
}

// ouiTestBMCMakers lists, for every BMC type, the fragments of the IEEE
// organization name of an OUI that may carry it.
var ouiTestBMCMakers = map[string][]string{
	"Dell iDRAC": {"dell"}, "HPE iLO": {"hewlett"}, "IBM IMM": {"ibm"}, "Oracle ILOM": {"oracle"},
	"Supermicro IPMI": {"super micro"}, "Cisco CIMC": {"cisco"}, "Fujitsu iRMC": {"fujitsu"},
	"ASUS ASMB": {"asustek"}, "ASRock IPMI": {"asrock"}, "Avocent BMC": {"avocent"},
	"Huawei iBMC": {"huawei"},
}

// TestBMCOUIMakers: every BMC type an OUI names is the maker IEEE registers
// the OUI to (F33).
func TestBMCOUIMakers(t *testing.T) {
	n := 0
	for prefix, org := range ouiTestIEEENames(t) {
		kind := bmcTypeByOUI(prefix + ":00:00:01")
		if kind == "" {
			continue
		}
		n++
		if !ouiTestContainsAny(strings.ToLower(org), ouiTestBMCMakers[kind]) {
			t.Errorf("%s: BMC %q, but IEEE registers it to %q", prefix, kind, org)
		}
	}
	if n != 33 {
		t.Errorf("%d BMC OUIs, want 33", n)
	}
}

// TestVirtualNICOUIs: every virtual-NIC OUI is in every VM list: the
// virtual-NIC set, the vendor table (category vm) and the VM OS text (Q8).
func TestVirtualNICOUIs(t *testing.T) {
	noData := &DeviceData{}
	for _, c := range []struct{ mac, vendor, os string }{
		{"00:50:56:00:00:01", "VMware", "💻 VMware VM"},
		{"00:0c:29:00:00:01", "VMware", "💻 VMware VM"},
		{"00:05:69:00:00:01", "VMware", "💻 VMware VM"},
		{"00:1c:14:00:00:01", "VMware", "💻 VMware VM"},
		{"bc:24:11:00:00:01", "Proxmox", "💻 KVM/Proxmox VM"},
		{"52:54:00:00:00:01", "QEMU/KVM", "💻 KVM/Proxmox VM"},
		{"00:15:5d:00:00:01", "Hyper-V", "🪟 Hyper-V VM"},
		{"00:16:3e:00:00:01", "Xen", "💻 Xen VM"},
		{"08:00:27:00:00:01", "VirtualBox", "💻 VirtualBox VM"},
	} {
		if !isHypervisorMAC(c.mac) {
			t.Errorf("isHypervisorMAC(%q) = false", c.mac)
		}
		if got := getMACVendor(c.mac); got != c.vendor {
			t.Errorf("getMACVendor(%q) = %q, want %q", c.mac, got, c.vendor)
		}
		if got := categorizeVendor(getMACVendor(c.mac)); got != "vm" {
			t.Errorf("category of %q = %q, want vm", c.mac, got)
		}
		if got := detectOSFromMAC(c.mac, map[string]string{}, noData); got != c.os {
			t.Errorf("detectOSFromMAC(%q) = %q, want %q", c.mac, got, c.os)
		}
	}
	if got := detectOSFromMAC("aa:bb:cc:00:00:01", map[string]string{}, noData); got != "❓ Unknown VM" {
		t.Errorf("detectOSFromMAC(non-VM OUI) = %q", got)
	}
}

// TestDetectOSFromMACOrder: the TTL ping wins over the OUI; LLDP names play
// no part, since MACs known from LLDP never reach the VM branch (F37).
func TestDetectOSFromMACOrder(t *testing.T) {
	neighbors := &DeviceData{Neighbors: []LLDPNeighbor{{RemChassisId: "00:50:56:00:00:21", RemSysName: "ubuntu-web01"}}}
	if got := detectOSFromMAC("00:50:56:00:00:21", map[string]string{}, neighbors); got != "💻 VMware VM" {
		t.Errorf("with an LLDP name: %q, want the OUI text", got)
	}
	// fakePing: x.x.x.2 answers with TTL 128.
	if got := detectOSFromMAC("00:50:56:00:00:22", map[string]string{"00:50:56:00:00:22": "10.0.0.2"}, neighbors); got != "🪟 Windows" {
		t.Errorf("with a TTL 128 reply: %q, want Windows", got)
	}
}

// TestParseMAC: every MAC text form the collectors and LLDP produce parses;
// exception text, hostnames, IPs and partial addresses do not.
func TestParseMAC(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"4c:ae:a3:8e:42:11", "4c:ae:a3:8e:42:11"},
		{"4C:AE:A3:8E:42:11", "4c:ae:a3:8e:42:11"},
		{"0:c:29:aa:bb:cd", "00:0c:29:aa:bb:cd"}, // net-snmp unpadded
		{"0:0:0:0:0:0", "00:00:00:00:00:00"},
		{"4C AE A3 8E 42 11", "4c:ae:a3:8e:42:11"},
		{"4C AE A3 8E 42 11 ", "4c:ae:a3:8e:42:11"},
		{"4C  AE A3 8E 42 11", "4c:ae:a3:8e:42:11"},
		{"Hex-STRING: 4C AE A3 8E 42 11", "4c:ae:a3:8e:42:11"},
		{"STRING: \"4c:ae:a3:8e:42:11\"", "4c:ae:a3:8e:42:11"},
		{"\"4c:ae:a3:8e:42:11\"", "4c:ae:a3:8e:42:11"},
		{"\"f8-f0-82-7a-d9-69\"", "f8:f0:82:7a:d9:69"},
		{"f4-b5-20-19-12-5e", "f4:b5:20:19:12:5e"},
		{"5894.8000.f7a3", "58:94:80:00:f7:a3"}, // Cisco dotted
		{"B083.FE11.2233", "b0:83:fe:11:22:33"},
		{"4caea32784cb", "4c:ae:a3:27:84:cb"},
		{"No Such Instance currently exists at this OID", ""},
		{"no:such:object:available:on:this:agent:at:this:oid", ""},
		{"DESKTOP-V380CHD", ""},
		{"FERUZA", ""},
		{"\"pM{?WA\"", ""},
		{"01 AC 10 01 0F", ""},
		{"aa:bb:cc:dd:ee", ""},
		{"aa:bb:cc:dd:ee:ff:00", ""},
		{"4c:ae:a3-8e:42:11", ""},
		{"a-b-c-d-e-f", ""},
		{"004:ae:a3:8e:42:11", ""},
		{"gg:ae:a3:8e:42:11", ""},
		{"fe80::1", ""},
		{"2001:db8::1", ""},
		{"172.20.1.1", ""},
		{"10.0.0", ""},
		{"B-318/1", ""},
		{"", ""},
		{"  ", ""},
	} {
		m, ok := parseMAC(c.in)
		got := ""
		if ok {
			got = m.String()
		}
		if got != c.want {
			t.Errorf("parseMAC(%q) = %q, %v; want %q", c.in, got, ok, c.want)
		}
	}
}

// TestMACAddrBits pins the bit predicates of a parsed address.
func TestMACAddrBits(t *testing.T) {
	for _, c := range []struct {
		mac                                                string
		null, broadcast, multicast, local, random, zeroOUI bool
	}{
		{"00:00:00:00:00:00", true, false, false, false, false, true},
		{"ff:ff:ff:ff:ff:ff", false, true, true, true, false, false},
		{"01:00:5e:00:00:fb", false, false, true, false, false, false},
		{"33:33:00:00:00:01", false, false, true, true, false, false},
		{"03:00:00:00:00:01", false, false, true, true, false, false},
		{"52:54:00:12:34:56", false, false, false, true, true, false},
		{"02:42:ac:11:00:02", false, false, false, true, true, false},
		{"da:a1:19:00:00:01", false, false, false, true, true, false},
		{"00:00:00:12:34:56", false, false, false, false, false, true},
		{"4c:ae:a3:8e:42:11", false, false, false, false, false, false},
	} {
		m, ok := parseMAC(c.mac)
		if !ok {
			t.Fatalf("parseMAC(%q) failed", c.mac)
		}
		got := [6]bool{m.IsNull(), m.IsBroadcast(), m.IsMulticast(), m.IsLocal(), m.IsRandom(), m.IsZeroOUI()}
		want := [6]bool{c.null, c.broadcast, c.multicast, c.local, c.random, c.zeroOUI}
		if got != want {
			t.Errorf("%s: null/broadcast/multicast/local/random/zeroOUI = %v, want %v", c.mac, got, want)
		}
		if m.OUI() != c.mac[:8] {
			t.Errorf("%s: OUI() = %q", c.mac, m.OUI())
		}
	}
}

// TestRandomMACNotVirtualNIC: a known virtual-NIC OUI is a VM, never a
// random MAC, even with the local bit set (52:54:00 QEMU/KVM) (Q4). Only
// parsed MACs can be random.
func TestRandomMACNotVirtualNIC(t *testing.T) {
	for _, c := range []struct {
		mac  string
		want bool
	}{
		{"52:54:00:12:34:56", false},
		{"52-54-00-12-34-56", false},
		{"02:42:ac:11:00:02", true}, // Docker bridge: no hypervisor OUI
		{"da:a1:19:00:00:01", true},
		{"2:11:22:33:44:55", true}, // unpadded net-snmp form
		{"03:00:00:00:00:01", false},
		{"fe80::1", false},
		{"\"2\"", false},
		{"B-318/1", false},
	} {
		if got := isRandomMAC(c.mac); got != c.want {
			t.Errorf("isRandomMAC(%q) = %v, want %v", c.mac, got, c.want)
		}
	}
}

// TestSpecialMAC: one filter policy for MACs, by the bits of the parsed
// address: null, broadcast, multicast and the zero OUI (Q11). Hostnames and
// IPs are never special (F38).
func TestSpecialMAC(t *testing.T) {
	for _, c := range []struct {
		mac  string
		want bool
	}{
		{"00:00:00:00:00:00", true},
		{"ff:ff:ff:ff:ff:ff", true},
		{"01:00:5e:00:00:16", true},
		{"01-80-c2-00-00-0e", true},
		{"33:33:00:00:00:01", true},
		{"03:00:00:00:00:01", true},
		{"15:04:05:11:22:33", true},
		{"00:00:00:12:34:56", true}, // zero OUI (F39: graph and snapshots agree)
		{"4c:ae:a3:8e:42:11", false},
		{"52:54:00:12:34:56", false},
		{"02:42:ac:11:00:02", false},
		{"B-318/1", false},
		{"E109-9", false},
		{"173.16.1.15", false},
		{"2001:db8::1", false},
		{"", false},
	} {
		if got := isSpecialMAC(c.mac); got != c.want {
			t.Errorf("isSpecialMAC(%q) = %v, want %v", c.mac, got, c.want)
		}
	}
}

// TestInvalidID: a MAC id is invalid when it is special; a hostname, IP or
// port id only when it is empty, all zeros, or a broken MAC (F38, F39; Q11).
func TestInvalidID(t *testing.T) {
	for _, c := range []struct {
		id   string
		want bool
	}{
		{"", true}, {" ", true}, {"0", true},
		{"0.0.0.0", true}, {"0:0:0:0", true}, {"::", true},
		{"00:00:00:00:00:00", true}, {"0:0:0:0:0:0", true}, {"00 00 00 00 00 00", true},
		{"00-00-00-00-00-00", true}, {"000000000000", true},
		{"00:00:00:12:34:56", true},
		{"ff:ff:ff:ff:ff:ff", true}, {"FF:FF:FF:FF:FF:FF", true},
		{"01:00:5e:00:00:fb", true}, {"33:33:00:00:00:01", true}, {"03:00:00:00:00:01", true},
		{"01:ac:10:01:0f", true}, // network-address chassis id read as hex
		{"aa:bb:cc:dd:ee", true}, {"00:00:00:01", true}, {"01 AC 10 01 0F", true},
		{"B-318/1", false}, {"E109-9", false}, {"A-332", false}, {"SW1", false}, {"A1", false},
		{"173.16.1.15", false}, {"172.16.1.15", false},
		{"2001:db8::1", false}, {"fe80::1", false}, {"1:2:3:4:5:6:7:8", false},
		{"DESKTOP-V380CHD", false}, {"AB-12", false},
		{"no:such:object:available:on:this:agent:at:this:oid", false},
		{"4c:ae:a3:8e:42:11", false}, {"4caea32784cb", false},
		{"02:42:ac:11:00:02", false}, {"52:54:00:12:34:56", false},
	} {
		if got := isInvalidID(c.id); got != c.want {
			t.Errorf("isInvalidID(%q) = %v, want %v", c.id, got, c.want)
		}
	}
}

// ouiTestForms writes one MAC in every text form parseMAC reads.
func ouiTestForms(canonical string) []string {
	m, ok := parseMAC(canonical)
	if !ok {
		panic(canonical)
	}
	h := strings.ReplaceAll(m.String(), ":", "")
	up := strings.ToUpper(m.String())
	unpadded := strings.NewReplacer(":0", ":").Replace(":" + m.String())[1:] // net-snmp "0:50:56:a:b:c"
	return []string{
		m.String(), up, strings.ReplaceAll(m.String(), ":", "-"), strings.ReplaceAll(up, ":", " "),
		"Hex-STRING: " + strings.ReplaceAll(up, ":", " "), `"` + m.String() + `"`,
		h[0:4] + "." + h[4:8] + "." + h[8:12], h, unpadded,
	}
}

// TestOUIKeyForms: every OUI table answers the same for every text form of a
// MAC, and nothing for text that is no MAC (one key rule: the OUI of the
// parsed address).
func TestOUIKeyForms(t *testing.T) {
	for _, mac := range []string{"00:50:56:0a:0b:0c", "f8:db:88:01:02:03", "4c:ae:a3:27:84:cb", "52:54:00:12:34:56", "00:15:5d:00:00:01"} {
		ok0, server0 := isServerNIC(mac)
		want := fmt.Sprint(lookupVendor(mac), isHypervisorMAC(mac), ok0, server0, bmcTypeByOUI(mac),
			detectOSFromMAC(mac, map[string]string{}, &DeviceData{}))
		for _, form := range ouiTestForms(mac) {
			ok, server := isServerNIC(form)
			got := fmt.Sprint(lookupVendor(form), isHypervisorMAC(form), ok, server, bmcTypeByOUI(form),
				detectOSFromMAC(form, map[string]string{}, &DeviceData{}))
			if got != want {
				t.Errorf("%q: %s, but %q gives %s", form, got, mac, want)
			}
		}
	}
	for _, text := range []string{"f8:db:88", "00:50:56:aa", "00:50:56:aa:bb:cc:dd", "52:54:00 VM"} {
		if ok, _ := isServerNIC(text); ok || isHypervisorMAC(text) || bmcTypeByOUI(text) != "" || lookupVendor(text) != "Unknown" {
			t.Errorf("%q is no MAC but an OUI table answered", text)
		}
	}
}
