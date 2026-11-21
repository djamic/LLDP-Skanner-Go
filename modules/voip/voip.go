// Package voip is a standalone, extensible IP phone (VoIP) detection and
// inspection module. It separates VoIP identification and metadata parsing
// from the main topology builder so new phone vendors, model rules, or active
// HTTP/SIP probes can be registered without modifying scanner core logic.
package voip

import (
	"encoding/hex"
	"net"
	"slices"
	"strings"
	"sync"

	"lldp_scanner/modules/kit"
)

// LLDP system capability bits (kit.LLDPCap*).
const (
	CapBridge = kit.LLDPCapBridge // 0x20: also the 2-port PC bridge inside desk phones
	CapWLANAP = kit.LLDPCapWLANAP // 0x10: wireless access point
	CapRouter = kit.LLDPCapRouter // 0x08: router
	CapPhone  = kit.LLDPCapPhone  // 0x04: telephone
)

// ChassisSubtypeNetworkAddr is LLDP chassis ID subtype 5 (IANA AddressFamily + IP).
const ChassisSubtypeNetworkAddr = 5

// Evidence holds passive telemetry observed for one network endpoint (from
// LLDP, FDB/OUI lookup, and ARP/management IP tables). Any subset may be set.
type Evidence struct {
	MAC            string
	Vendor         string
	SysName        string
	SysDesc        string
	PortDesc       string
	Capabilities   uint8
	ChassisSubtype int
	ChassisID      string
	MgmtIP         string
}

// Profile describes a detected VoIP device and the structured attributes
// extracted from its telemetry.
type Profile struct {
	Brand    string `json:"brand"`
	Model    string `json:"model,omitempty"`
	Firmware string `json:"firmware,omitempty"`
	IP       string `json:"ip,omitempty"`
	Port     string `json:"port,omitempty"`
	PCBridge bool   `json:"pcBridge,omitempty"`
	Source   string `json:"source,omitempty"`
}

// Rule defines one pluggable vendor or protocol detector.
//
//   - DedicatedVendors lists whole-word OUI organization phrases for makers
//     whose endpoints are exclusively phones/VoIP (e.g. "yealink",
//     "grandstream", "fanvil"). Multi-product makers (Panasonic, Cisco, Huawei)
//     must leave DedicatedVendors empty and match via Match using LLDP model
//     prefixes or CapPhone.
//   - Exclude matches non-phone products of the rule's own vendor (for
//     example, Grandstream GWN76xx Wi-Fi APs, GWN78xx switches, UCM PBXs or
//     GDS door systems): the rule does not match them, and no fallback makes
//     them phones. It vetoes that vendor's rule only, never another's.
//   - Match inspects Evidence and returns (model, firmware, true) when the
//     endpoint is an IP phone of this brand.
type Rule struct {
	ID               string
	Brand            string
	Priority         int
	DedicatedVendors []string
	Exclude          func(ev Evidence) bool
	Match            func(ev Evidence) (model, firmware string, ok bool)
}

var (
	rulesMu sync.RWMutex
	rules   []Rule
)

// RegisterRule adds or replaces a VoIP detection rule (safe for init() and runtime extension).
func RegisterRule(r Rule) {
	rulesMu.Lock()
	defer rulesMu.Unlock()
	if i := slices.IndexFunc(rules, func(existing Rule) bool { return existing.ID == r.ID }); i >= 0 {
		rules[i] = r
	} else {
		rules = append(rules, r)
	}
	slices.SortFunc(rules, func(a, b Rule) int {
		if a.Priority != b.Priority {
			return b.Priority - a.Priority // higher priority first
		}
		return strings.Compare(a.ID, b.ID)
	})
}

// Rules returns a snapshot of all registered VoIP detection rules in evaluation order.
func Rules() []Rule {
	rulesMu.RLock()
	defer rulesMu.RUnlock()
	return slices.Clone(rules)
}

// UnregisterRule removes a registered VoIP rule by ID (useful in tests or dynamic overrides).
func UnregisterRule(id string) {
	rulesMu.Lock()
	defer rulesMu.Unlock()
	rules = slices.DeleteFunc(rules, func(r Rule) bool { return r.ID == id })
}

// IsDedicatedVoIPVendor reports whether an OUI vendor string belongs to a
// dedicated VoIP manufacturer (safe for MAC/FDB-only categorization without LLDP).
func IsDedicatedVoIPVendor(vendor string) bool {
	_, ok := BrandForDedicatedVendor(vendor)
	return ok
}

// BrandForDedicatedVendor returns the canonical VoIP brand for a dedicated
// VoIP OUI vendor name, or ("", false) for unknown or multi-category vendors.
func BrandForDedicatedVendor(vendor string) (string, bool) {
	v := strings.ToLower(strings.TrimSpace(vendor))
	if v == "" || v == "unknown" {
		return "", false
	}
	rulesMu.RLock()
	defer rulesMu.RUnlock()
	for _, r := range rules {
		for _, w := range r.DedicatedVendors {
			if kit.HasWord(v, w) {
				return r.Brand, true
			}
		}
	}
	return "", false
}

// Detect evaluates Evidence against all registered VoIP rules and IEEE 802.1AB
// telephone capability flags. Routers and wireless access points are never
// classified as phones.
func Detect(ev Evidence) (Profile, bool) {
	// Never classify a router or wireless AP as an IP phone.
	if ev.Capabilities&CapRouter != 0 || ev.Capabilities&CapWLANAP != 0 {
		return Profile{}, false
	}

	rulesMu.RLock()
	snapshot := slices.Clone(rules)
	rulesMu.RUnlock()

	excluded := false
	for _, r := range snapshot {
		if r.Exclude != nil && r.Exclude(ev) {
			excluded = true // this vendor's non-phone product: its rule does not match
			continue
		}
		if r.Match != nil {
			if model, fw, ok := r.Match(ev); ok {
				return buildProfile(ev, r.Brand, model, fw, r.ID), true
			}
		}
	}
	if excluded {
		return Profile{}, false
	}

	// Fallback 1: Dedicated VoIP OUI vendor (e.g. FDB-only Yealink/Grandstream node)
	if brand, ok := BrandForDedicatedVendor(ev.Vendor); ok {
		return buildProfile(ev, brand, "", "", "oui:"+strings.ToLower(brand)), true
	}

	// Fallback 2: Generic IEEE 802.1AB Telephone capability bit (0x04)
	if ev.Capabilities&CapPhone != 0 {
		brand := cleanVendorBrand(ev.Vendor)
		if brand == "" {
			brand = "VoIP Phone"
		}
		model := strings.TrimSpace(ev.SysName)
		fw := strings.TrimSpace(firstLine(ev.SysDesc))
		if strings.EqualFold(fw, brand) || strings.EqualFold(fw, ev.Vendor) {
			fw = ""
		}
		return buildProfile(ev, brand, model, fw, "lldp-cap:phone"), true
	}

	return Profile{}, false
}

// Excluded reports whether ev is a non-phone product of a VoIP vendor by a
// rule's Exclude (a Grandstream UCM PBX, GDS door system, GWN access point
// or switch; an Avaya Ethernet Routing Switch): the scanner then does not
// take the vendor's OUI for a phone either.
func Excluded(ev Evidence) bool {
	rulesMu.RLock()
	defer rulesMu.RUnlock()
	return slices.ContainsFunc(rules, func(r Rule) bool { return r.Exclude != nil && r.Exclude(ev) })
}

func buildProfile(ev Evidence, brand, model, firmware, source string) Profile {
	ip := strings.TrimSpace(ev.MgmtIP)
	if ip == "" {
		ip = DecodeChassisIPv4(ev.ChassisSubtype, ev.ChassisID)
	}
	port := cleanPortDesc(ev.PortDesc)
	return Profile{
		Brand:    brand,
		Model:    strings.TrimSpace(model),
		Firmware: strings.TrimSpace(firmware),
		IP:       ip,
		Port:     port,
		PCBridge: ev.Capabilities&CapBridge != 0,
		Source:   source,
	}
}

// DecodeChassisIPv4 extracts a valid host IPv4 address from an LLDP
// networkAddress chassis ID (subtype 5: 0x01 IANA IPv4 family + 4 octets,
// e.g. "01 C0 00 02 0F" -> "192.0.2.15"). Incomplete or network/broadcast
// addresses (such as truncated "01 C0 00" or "192.0.2.0") return "".
func DecodeChassisIPv4(subtype int, raw string) string {
	if subtype != ChassisSubtypeNetworkAddr {
		return ""
	}
	s := strings.Trim(strings.TrimSpace(raw), "\"")
	if s == "" {
		return ""
	}
	var ip net.IP
	if parsed := net.ParseIP(s); parsed != nil {
		ip = parsed.To4()
	} else if len(s) == 5 && s[0] == 1 {
		ip = net.IP([]byte(s[1:5])).To4()
	} else if len(s) == 4 {
		ip = net.IP([]byte(s)).To4()
	} else {
		fields := strings.FieldsFunc(s, func(r rune) bool { return r == ' ' || r == ':' || r == '-' })
		if len(fields) == 5 {
			var b [5]byte
			ok := true
			for i, f := range fields {
				dec, err := hex.DecodeString(f)
				if err != nil || len(dec) != 1 {
					ok = false
					break
				}
				b[i] = dec[0]
			}
			if ok && b[0] == 1 {
				ip = net.IP(b[1:5]).To4()
			}
		}
	}
	if len(ip) != 4 || ip.IsUnspecified() || ip.IsLoopback() || ip.IsMulticast() || ip[3] == 0 || ip[3] == 255 {
		return ""
	}
	return ip.String()
}

func firstLine(s string) string {
	line, _, _ := strings.Cut(strings.TrimSpace(s), "\n")
	return strings.TrimSpace(line)
}

func cleanPortDesc(s string) string {
	s = strings.Trim(strings.TrimSpace(s), "\"")
	if s == "" {
		return ""
	}
	return s
}

func cleanVendorBrand(vendor string) string {
	v := strings.TrimSpace(vendor)
	if v == "" || strings.EqualFold(v, "Unknown") {
		return ""
	}
	for _, sep := range []string{",", "(", " Co.", " Inc", " Corp", " Ltd", " LTD"} {
		if idx := strings.Index(v, sep); idx > 0 {
			v = strings.TrimSpace(v[:idx])
		}
	}
	return v
}
