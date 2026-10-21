package main

import (
	"bufio"
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
