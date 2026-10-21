package main

import "strings"

// ============================================================
// MAC identity — BMC detection
// ============================================================

// macBMCKeywords name the BMC kind in an LLDP or DNS name; the first match
// wins. The name is lowercased and cut into words at every character that is
// not a letter or digit. match says where the keyword may stand:
//
//	"word"   a whole word, or the word plus digits ("ilo5", "bmc01")
//	"prefix" the start of a word ("irmcf844a6")
//	"serial" the start of a word followed by an HPE serial number
//	         ("ILOCZJ33411C3", the iLO default name)
//	"any"    anywhere in the name ("srv01idrac")
var macBMCKeywords = []struct {
	keyword, match, kind string
}{
	{"idrac", "any", "Dell iDRAC"},
	{"drac", "word", "Dell iDRAC"},
	{"ilo", "word", "HPE iLO"},
	{"ilo", "serial", "HPE iLO"},
	{"xclarity", "any", "Lenovo XCC"},
	{"xcc", "word", "Lenovo XCC"},
	{"imm", "word", "Lenovo IMM"},
	{"cimc", "prefix", "Cisco CIMC"},
	{"irmc", "prefix", "Fujitsu iRMC"},
	{"asmb", "prefix", "ASUS ASMB"},
	{"ibmc", "prefix", "Huawei iBMC"},
	{"ipmi", "any", "IPMI"},
	{"bmc", "word", "BMC"},
	{"management-controller", "any", "BMC"},
}

// bmcTypeByName returns the BMC kind an LLDP or DNS name names, or "".
func bmcTypeByName(name string) string {
	lower := strings.ToLower(name)
	words := strings.FieldsFunc(lower, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9')
	})
	for _, kw := range macBMCKeywords {
		if macBMCKeywordIn(kw.keyword, kw.match, lower, words) {
			return kw.kind
		}
	}
	return ""
}

func macBMCKeywordIn(keyword, match, lower string, words []string) bool {
	if match == "any" {
		return strings.Contains(lower, keyword)
	}
	for _, w := range words {
		rest, ok := strings.CutPrefix(w, keyword)
		if !ok {
			continue
		}
		switch {
		case match == "prefix",
			match == "word" && strings.Trim(rest, "0123456789") == "",
			match == "serial" && macIsHPESerial(rest):
			return true
		}
	}
	return false
}

// macIsHPESerial reports whether the letters and digits s look like an HPE
// serial number: ten of them, at least three digits ("czj33411c3").
func macIsHPESerial(s string) bool {
	digits := 0
	for i := 0; i < len(s); i++ {
		if s[i] >= '0' && s[i] <= '9' {
			digits++
		}
	}
	return len(s) == 10 && digits >= 3
}

// macBMCOUIs name the BMC maker of an OUI. Server makers use the same OUIs
// for ordinary NICs, so an OUI never makes a BMC on its own (Q5); it only
// names the maker once a name keyword said "BMC".
var macBMCOUIs = map[string]string{
	// Dell iDRAC (Remote Access Controller)
	"14:fe:b5": "Dell iDRAC",
	"18:66:da": "Dell iDRAC",
	"b0:83:fe": "Dell iDRAC",
	"f8:db:88": "Dell iDRAC",
	"f0:1f:af": "Dell iDRAC",
	"b8:ca:3a": "Dell iDRAC",
	"d0:94:66": "Dell iDRAC",
	"54:bf:64": "Dell iDRAC",
	"b8:ac:6f": "Dell iDRAC",

	// HPE iLO (Integrated Lights-Out)
	"98:e7:f4": "HPE iLO",
	"b4:99:ba": "HPE iLO",
	"94:18:82": "HPE iLO",
	"9c:8e:99": "HPE iLO",
	"58:20:b1": "HPE iLO",
	"3c:a8:2a": "HPE iLO",
	"10:60:4b": "HPE iLO",
	"d8:d3:85": "HPE iLO",

	// IBM IMM / BMC (Integrated Management Module)
	"00:21:5e": "IBM IMM",
	"00:1a:64": "IBM IMM",
	"6c:ae:8b": "IBM IMM",
	"40:f2:e9": "IBM IMM",

	// Oracle ILOM
	"00:00:17": "Oracle ILOM",

	// Supermicro IPMI / BMC
	"0c:c4:7a": "Supermicro IPMI",

	// Cisco CIMC (Unified Computing System)
	"54:7f:ee": "Cisco CIMC",
	"cc:46:d6": "Cisco CIMC",
	"70:df:2f": "Cisco CIMC",

	// Fujitsu iRMC (integrated Remote Management Controller)
	"90:1b:0e": "Fujitsu iRMC",
	"00:19:99": "Fujitsu iRMC",

	// ASRock / ASUS ASMB (Server Management Board)
	"a8:5e:45": "ASUS ASMB",
	"70:85:c2": "ASRock IPMI",
	"d0:50:99": "ASRock IPMI",

	// Avocent (BMC firmware for several server makers), Huawei iBMC
	"00:e0:86": "Avocent BMC",
	"00:18:82": "Huawei iBMC",
}

// bmcTypeByOUI returns the BMC maker the MAC's OUI names, or "".
func bmcTypeByOUI(mac string) string {
	mac = normalizeMAC(mac)
	if len(mac) < 8 {
		return ""
	}
	return macBMCOUIs[mac[:8]]
}
