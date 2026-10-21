package main

import (
	"encoding/hex"
	"strings"
)

// ============================================================
// MAC identity — parsed addresses
// ============================================================

// macAddr is a parsed 48-bit MAC address.
type macAddr [6]byte

// parseMAC reads every MAC text form the collectors and LLDP produce:
//
//	"4c:ae:a3:8e:42:11"  colons, any case; net-snmp also drops leading
//	                     zeros ("0:c:29:aa:bb:cd")
//	"4C AE A3 8E 42 11"  Hex-STRING bytes, optionally after a "Hex-STRING:"
//	                     or "STRING:" prefix and in quotes
//	"4c-ae-a3-8e-42-11"  dashes
//	"5894.8000.f7a3"     Cisco dotted
//	"4caea38e4211"       bare hex
//
// Everything else is no MAC: SNMP exception text, hostnames, IPs, partial or
// overlong addresses, mixed separators.
func parseMAC(s string) (macAddr, bool) {
	s = strings.TrimSpace(s)
	if rest, ok := strings.CutPrefix(s, "Hex-STRING:"); ok {
		s = rest
	} else if rest, ok := strings.CutPrefix(s, "STRING:"); ok {
		s = rest
	}
	s = strings.TrimSpace(strings.Trim(strings.TrimSpace(s), `"`))

	var digits string
	switch {
	case strings.Count(s, ":") == 5:
		digits = macJoinGroups(strings.Split(s, ":"), 1)
	case strings.Count(s, "-") == 5:
		digits = macJoinGroups(strings.Split(s, "-"), 2)
	case strings.Count(s, ".") == 2:
		if g := strings.Split(s, "."); len(g[0]) == 4 && len(g[1]) == 4 && len(g[2]) == 4 {
			digits = g[0] + g[1] + g[2]
		}
	case strings.ContainsAny(s, " \t"):
		digits = macJoinGroups(strings.Fields(s), 2)
	default:
		digits = s
	}
	var m macAddr
	if len(digits) != 12 {
		return m, false
	}
	if _, err := hex.Decode(m[:], []byte(digits)); err != nil {
		return macAddr{}, false
	}
	return m, true
}

// macJoinGroups joins six groups of minDigits to 2 characters into twelve,
// padding single digits with a zero; any other shape gives "".
func macJoinGroups(groups []string, minDigits int) string {
	if len(groups) != 6 {
		return ""
	}
	var b strings.Builder
	for _, g := range groups {
		if len(g) < minDigits || len(g) > 2 {
			return ""
		}
		if len(g) == 1 {
			b.WriteByte('0')
		}
		b.WriteString(g)
	}
	return b.String()
}

// String gives the canonical text "aa:bb:cc:dd:ee:ff".
func (m macAddr) String() string {
	const digits = "0123456789abcdef"
	b := make([]byte, 0, 17)
	for i, octet := range m {
		if i > 0 {
			b = append(b, ':')
		}
		b = append(b, digits[octet>>4], digits[octet&0x0f])
	}
	return string(b)
}

// OUI gives the first three octets as "aa:bb:cc", the key of the OUI tables.
func (m macAddr) OUI() string { return m.String()[:8] }

// IsNull: 00:00:00:00:00:00.
func (m macAddr) IsNull() bool { return m == macAddr{} }

// IsBroadcast: ff:ff:ff:ff:ff:ff.
func (m macAddr) IsBroadcast() bool { return m == macAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff} }

// IsMulticast: the I/G bit (group address; broadcast included).
func (m macAddr) IsMulticast() bool { return m[0]&0x01 != 0 }

// IsLocal: the U/L bit (locally administered).
func (m macAddr) IsLocal() bool { return m[0]&0x02 != 0 }

// IsRandom: a locally administered unicast address, such as a phone's
// private Wi-Fi address.
func (m macAddr) IsRandom() bool { return m.IsLocal() && !m.IsMulticast() }

// IsZeroOUI: the OUI 00:00:00, which only appears on garbage entries.
func (m macAddr) IsZeroOUI() bool { return m[0] == 0 && m[1] == 0 && m[2] == 0 }

// IsSpecial: no station address. Null, broadcast, multicast and zero-OUI
// MACs are filtered everywhere (Q11).
func (m macAddr) IsSpecial() bool {
	return m.IsNull() || m.IsBroadcast() || m.IsMulticast() || m.IsZeroOUI()
}

// macIsBrokenMAC reports text made of 1-2 digit hex groups separated by
// colons or spaces that is not a whole MAC, such as "01:ac:10:01:0f" (a
// network-address chassis id read as hex) or "aa:bb:cc:dd:ee".
func macIsBrokenMAC(s string) bool {
	groups := strings.FieldsFunc(s, func(r rune) bool { return r == ':' || r == ' ' })
	if len(groups) < 2 || strings.Contains(s, "::") {
		return false
	}
	for _, g := range groups {
		if len(g) > 2 || strings.Trim(strings.ToLower(g), "0123456789abcdef") != "" {
			return false
		}
	}
	return true
}

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
