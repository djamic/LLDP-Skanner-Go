package main

import (
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/klauspost/oui"
)

// ============================================================
// MAC identity — everything the scanner knows about a MAC address,
// without network I/O:
//   - parseMAC reads every text form of a MAC; macAddr answers the
//     address bits (null, broadcast, multicast, local, random, zero OUI).
//   - ouiRegistry is the one OUI table: per OUI the curated vendor and its
//     category, the virtual-NIC platform with its hypervisor type and VM
//     OS text, the server maker and the BMC maker.
//   - The IEEE database (oui.txt) names the vendors of all other OUIs.
//   - IdentifyMAC returns all of it for one address; lookupVendor, isBMC,
//     isServerNIC, isRandomMAC and the other helpers are thin wrappers.
//
// normalizeMAC is no parser: it is the text key of the MAC maps and node
// ids, and it also runs on hostnames and SNMP exception text.
// ============================================================

// ============================================================
// Parsed addresses
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

// parseMACOctets reads a 6-byte OCTET STRING that net-snmp printed as text
// (STRING: "pM{?WA") as the raw address bytes, after an optional "STRING:"
// prefix and the quotes. Any six characters pass, so use it only where the
// OID or the LLDP subtype says the value is a MAC (chassis subtype 4, port
// subtype 3, ARP physical address), and only after parseMAC failed.
func parseMACOctets(raw string) (macAddr, bool) {
	s := strings.TrimSpace(raw)
	if rest, ok := strings.CutPrefix(s, "STRING:"); ok {
		s = strings.TrimLeft(rest, " ")
	}
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		s = s[1 : len(s)-1]
	}
	var m macAddr
	if len(s) != len(m) {
		return m, false
	}
	copy(m[:], s)
	return m, true
}

// canonicalMAC gives "aa:bb:cc:dd:ee:ff" for any text parseMAC reads, or "".
func canonicalMAC(s string) string {
	m, ok := parseMAC(s)
	if !ok {
		return ""
	}
	return m.String()
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

// OUI gives the first three octets as "aa:bb:cc", the key of ouiRegistry.
func (m macAddr) OUI() string { return m.String()[:8] }

// ouiKey gives the OUI "aa:bb:cc" of a MAC in any form parseMAC reads, or ""
// for text that is no MAC. It is the one key of every OUI lookup.
func ouiKey(mac string) string {
	m, ok := parseMAC(mac)
	if !ok {
		return ""
	}
	return m.OUI()
}

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

// ============================================================
// normalizeMAC — canonical MAC address normalization
// Converts ANY MAC format to lowercase colon-separated:
//
//	"4C AE A3 27 84 CA" → "4c:ae:a3:27:84:ca"
//	"4c-ae-a3-27-84-ca" → "4c:ae:a3:27:84:ca"
//	"4C:AE:A3:27:84:CA" → "4c:ae:a3:27:84:ca"
//	"\"4c:ae:a3:27:84:ca\"" → "4c:ae:a3:27:84:ca"
//
// It does not check that the text is a MAC (parseMAC does): it is the key
// of the MAC maps and of node ids, and it also runs on other ids.
// ============================================================
func normalizeMAC(mac string) string {
	// Trim whitespace and quotes
	mac = strings.Trim(mac, "\" \t\r\n")
	if mac == "" {
		return ""
	}

	// Replace all separators with colons
	mac = strings.ReplaceAll(mac, "-", ":")
	mac = strings.ReplaceAll(mac, " ", ":")

	// Lowercase
	mac = strings.ToLower(mac)

	// Remove double colons from bad formatting
	for strings.Contains(mac, "::") {
		mac = strings.ReplaceAll(mac, "::", ":")
	}

	// Trim leading/trailing colons
	mac = strings.Trim(mac, ":")

	return mac
}

// hexStringToMAC converts any MAC format to canonical "4c:ae:a3:8e:42:11"
func hexStringToMAC(hex string) string {
	return normalizeMAC(hex)
}

// ============================================================
// OUI registry
// ============================================================

// ouiRole is everything one OUI stands for. Only non-empty fields apply.
type ouiRole struct {
	Vendor    string // curated short vendor name; without one the IEEE names the OUI
	Category  string // device category of Vendor
	VirtNIC   string // virtual-NIC platform: MACs of this OUI are VM NICs
	HypType   string // hypervisor type such a VM NIC belongs to
	VMOS      string // VM OS text when no TTL ping answers
	ServerNIC string // server maker, for "[HYPERVISOR] <maker> Server"
	BMC       string // BMC type, used only once a name keyword says BMC (Q5)
}

// ouiRegistry is the one OUI table: every role of an OUI on one line.
// Curated vendor names are the company oui.txt registers the OUI to
// (TestOUICuratedVendorsAgreeWithIEEE). Category "vm" goes with VirtNIC.
var ouiRegistry = map[string]ouiRole{
	// Switches of this network: SNR (NAGTECH) and H3C
	"f8:f0:82": {Vendor: "SNR", Category: "network"},
	"00:0f:e2": {Vendor: "H3C", Category: "network"},

	// HP / HPE / Aruba: switches, ProLiant NICs, iLO
	"00:26:55": {ServerNIC: "HPE"},
	"10:e7:c6": {ServerNIC: "HPE"},
	"1c:98:ec": {ServerNIC: "HPE"},
	"4c:ae:a3": {Vendor: "HPE", Category: "network"},
	"5c:ba:2c": {Vendor: "HPE", Category: "network"},
	"5c:ed:8c": {Vendor: "HPE", Category: "network", ServerNIC: "HPE ProLiant"},
	"94:18:82": {Vendor: "HPE", Category: "network", BMC: "HPE iLO"},
	"94:40:c9": {Vendor: "HPE", Category: "network"},
	"94:57:a5": {ServerNIC: "HPE"},
	"98:e7:f4": {Vendor: "HPE", Category: "network", BMC: "HPE iLO"},
	"b4:7a:f1": {Vendor: "HPE", Category: "network", ServerNIC: "HPE ProLiant"},
	"b4:99:ba": {Vendor: "HPE", Category: "network", BMC: "HPE iLO"},
	"e8:39:35": {ServerNIC: "HPE"},
	"ec:b1:d7": {ServerNIC: "HPE"},
	"00:1e:0b": {Vendor: "HP", Category: "network"},
	"18:a9:05": {Vendor: "HP", Category: "network"},
	"2c:41:38": {Vendor: "HP", Category: "network"},
	"3c:d9:2b": {Vendor: "HP", Category: "network"},
	"6c:02:e0": {Vendor: "HP", Category: "network"},
	"84:69:93": {Vendor: "HP", Category: "network"},
	"a0:d3:c1": {Vendor: "HP", Category: "network"},
	"00:4e:35": {Vendor: "HP Aruba", Category: "access_point"},
	"00:0b:86": {Vendor: "Aruba", Category: "access_point"},
	"20:4c:03": {Vendor: "Aruba", Category: "access_point"},
	"24:de:c6": {Vendor: "Aruba", Category: "access_point"},
	"6c:f3:7f": {Vendor: "Aruba", Category: "access_point"},
	"94:b4:0f": {Vendor: "Aruba", Category: "access_point"},
	"d8:c7:c8": {Vendor: "Aruba", Category: "access_point"},
	"3c:a8:2a": {ServerNIC: "HPE ProLiant", BMC: "HPE iLO"},
	"48:df:37": {ServerNIC: "HPE ProLiant"},
	"9c:b6:54": {ServerNIC: "HPE ProLiant"},
	"10:60:4b": {BMC: "HPE iLO"},
	"58:20:b1": {BMC: "HPE iLO"},
	"9c:8e:99": {BMC: "HPE iLO"},
	"d8:d3:85": {BMC: "HPE iLO"},

	// Cisco: switches, UCS NICs, CIMC
	"00:17:94": {Vendor: "Cisco", Category: "network"},
	"00:1a:2f": {Vendor: "Cisco", Category: "network"},
	"00:1a:a1": {Vendor: "Cisco", Category: "network"},
	"00:1b:2a": {Vendor: "Cisco", Category: "network"},
	"00:1c:57": {Vendor: "Cisco", Category: "network"},
	"00:25:45": {Vendor: "Cisco", Category: "network"},
	"30:f7:0d": {Vendor: "Cisco", Category: "network"},
	"68:86:a7": {Vendor: "Cisco", Category: "network"},
	"f4:cf:e2": {Vendor: "Cisco", Category: "network"},
	"f8:c2:88": {Vendor: "Cisco", Category: "network"},
	"00:25:b5": {ServerNIC: "Cisco UCS"},
	"00:2a:6a": {ServerNIC: "Cisco UCS"},
	"a8:9d:21": {ServerNIC: "Cisco UCS"},
	"54:7f:ee": {BMC: "Cisco CIMC"},
	"70:df:2f": {BMC: "Cisco CIMC"},
	"cc:46:d6": {BMC: "Cisco CIMC"},

	// Dell: PCs, PowerEdge NICs, iDRAC
	"00:14:22": {Vendor: "Dell", Category: "network", ServerNIC: "Dell"},
	"00:1a:a0": {ServerNIC: "Dell"},
	"00:21:9b": {ServerNIC: "Dell"},
	"00:26:b9": {ServerNIC: "Dell"},
	"00:4e:01": {Vendor: "Dell", Category: "network"},
	"14:fe:b5": {Vendor: "Dell", Category: "network", BMC: "Dell iDRAC"},
	"18:66:da": {Vendor: "Dell", Category: "network", BMC: "Dell iDRAC"},
	"18:db:f2": {ServerNIC: "Dell"},
	"34:17:eb": {ServerNIC: "Dell"},
	"8c:ec:4b": {Vendor: "Dell", Category: "network"},
	"a4:bb:6d": {Vendor: "Dell", Category: "network"},
	"b0:83:fe": {Vendor: "Dell", Category: "network", ServerNIC: "Dell", BMC: "Dell iDRAC"},
	"b4:45:06": {ServerNIC: "Dell"},
	"d4:ae:52": {ServerNIC: "Dell"},
	"f0:1f:af": {Vendor: "Dell", Category: "network", BMC: "Dell iDRAC"},
	"f8:bc:12": {Vendor: "Dell", Category: "network"},
	"f8:db:88": {Vendor: "Dell", Category: "network", ServerNIC: "Dell", BMC: "Dell iDRAC"},
	"4c:d9:8f": {ServerNIC: "Dell PowerEdge"},
	"54:bf:64": {BMC: "Dell iDRAC"},
	"b8:ac:6f": {BMC: "Dell iDRAC"},
	"b8:ca:3a": {BMC: "Dell iDRAC"},
	"d0:94:66": {BMC: "Dell iDRAC"},

	// Ubiquiti
	"18:e8:29": {Vendor: "Ubiquiti", Category: "access_point"},
	"24:5a:4c": {Vendor: "Ubiquiti", Category: "access_point"},
	"24:a4:3c": {Vendor: "Ubiquiti", Category: "access_point"},
	"44:d9:e7": {Vendor: "Ubiquiti", Category: "access_point"},
	"68:72:51": {Vendor: "Ubiquiti", Category: "access_point"},
	"70:a7:41": {Vendor: "Ubiquiti", Category: "access_point"},
	"74:83:c2": {Vendor: "Ubiquiti", Category: "access_point"},
	"78:45:58": {Vendor: "Ubiquiti", Category: "access_point"},
	"78:8a:20": {Vendor: "Ubiquiti", Category: "access_point"},
	"80:2a:a8": {Vendor: "Ubiquiti", Category: "access_point"},
	"9c:05:d6": {Vendor: "Ubiquiti", Category: "access_point"},
	"ac:8b:a9": {Vendor: "Ubiquiti", Category: "access_point"},
	"b4:fb:e4": {Vendor: "Ubiquiti", Category: "access_point"},
	"dc:9f:db": {Vendor: "Ubiquiti", Category: "access_point"},
	"e4:38:83": {Vendor: "Ubiquiti", Category: "access_point"},
	"f0:9f:c2": {Vendor: "Ubiquiti", Category: "access_point"},
	"f4:92:bf": {Vendor: "Ubiquiti", Category: "access_point"},
	"f4:e2:c6": {Vendor: "Ubiquiti", Category: "access_point"},

	// MikroTik
	"00:0c:42": {Vendor: "MikroTik", Category: "network"},
	"2c:c8:1b": {Vendor: "MikroTik", Category: "network"},
	"48:8f:5a": {Vendor: "MikroTik", Category: "network"},
	"4c:5e:0c": {Vendor: "MikroTik", Category: "network"},
	"6c:3b:6b": {Vendor: "MikroTik", Category: "network"},
	"74:4d:28": {Vendor: "MikroTik", Category: "network"},
	"b8:69:f4": {Vendor: "MikroTik", Category: "network"},
	"cc:2d:e0": {Vendor: "MikroTik", Category: "network"},
	"d4:01:c3": {Vendor: "MikroTik", Category: "network"},
	"dc:2c:6e": {Vendor: "MikroTik", Category: "network"},
	"e4:8d:8c": {Vendor: "MikroTik", Category: "network"},

	// Huawei
	"00:18:82": {Vendor: "Huawei", Category: "endpoint", BMC: "Huawei iBMC"},
	"00:25:68": {Vendor: "Huawei", Category: "endpoint"},
	"00:46:4b": {Vendor: "Huawei", Category: "endpoint"},
	"04:f9:38": {Vendor: "Huawei", Category: "endpoint"},
	"28:31:52": {Vendor: "Huawei", Category: "endpoint"},
	"34:29:12": {Vendor: "Huawei", Category: "endpoint"},
	"48:ad:08": {Vendor: "Huawei", Category: "endpoint"},
	"70:8c:b6": {Vendor: "Huawei", Category: "endpoint"},
	"7c:a2:3e": {Vendor: "Huawei", Category: "endpoint"},
	"88:28:b3": {Vendor: "Huawei", Category: "endpoint"},
	"9c:c1:72": {Vendor: "Huawei", Category: "endpoint"},
	"ac:cf:85": {Vendor: "Huawei", Category: "endpoint"},
	"c4:07:2f": {Vendor: "Huawei", Category: "endpoint"},
	"c8:d1:5e": {Vendor: "Huawei", Category: "endpoint"},
	"cc:a2:23": {Vendor: "Huawei", Category: "endpoint"},
	"dc:ee:06": {Vendor: "Huawei", Category: "endpoint"},

	// ZTE
	"00:19:c6": {Vendor: "ZTE", Category: "endpoint"},
	"30:f3:1d": {Vendor: "ZTE", Category: "endpoint"},

	// TP-Link
	"10:fe:ed": {Vendor: "TP-Link", Category: "network"},
	"14:cc:20": {Vendor: "TP-Link", Category: "network"},
	"18:d6:c7": {Vendor: "TP-Link", Category: "network"},
	"30:b5:c2": {Vendor: "TP-Link", Category: "network"},
	"50:3e:aa": {Vendor: "TP-Link", Category: "network"},
	"50:c7:bf": {Vendor: "TP-Link", Category: "network"},
	"54:af:97": {Vendor: "TP-Link", Category: "network"},
	"5c:e9:31": {Vendor: "TP-Link", Category: "network"},
	"60:e3:27": {Vendor: "TP-Link", Category: "network"},
	"64:70:02": {Vendor: "TP-Link", Category: "network"},
	"a4:2b:b0": {Vendor: "TP-Link", Category: "network"},
	"b0:95:75": {Vendor: "TP-Link", Category: "network"},
	"ec:08:6b": {Vendor: "TP-Link", Category: "network"},

	// D-Link
	"00:1c:f0": {Vendor: "D-Link", Category: "network"},
	"00:22:b0": {Vendor: "D-Link", Category: "network"},
	"1c:5f:2b": {Vendor: "D-Link", Category: "network"},
	"28:10:7b": {Vendor: "D-Link", Category: "network"},
	"34:08:04": {Vendor: "D-Link", Category: "network"},
	"84:c9:b2": {Vendor: "D-Link", Category: "network"},
	"c8:be:19": {Vendor: "D-Link", Category: "network"},

	// Other network makers
	"e0:d9:e3": {Vendor: "Eltex", Category: "network"},
	"84:39:8f": {Vendor: "Fortinet", Category: "network"},
	"00:00:5e": {Vendor: "IANA (VRRP)", Category: "endpoint"},

	// Virtual NICs: VMs (Q8: all VMware OUIs and Proxmox)
	"00:05:69": {Vendor: "VMware", Category: "vm", VirtNIC: "VMware", HypType: "VMware ESXi", VMOS: "💻 VMware VM"},
	"00:0c:29": {Vendor: "VMware", Category: "vm", VirtNIC: "VMware", HypType: "VMware ESXi", VMOS: "💻 VMware VM"},
	"00:1c:14": {Vendor: "VMware", Category: "vm", VirtNIC: "VMware", HypType: "VMware ESXi", VMOS: "💻 VMware VM"},
	"00:50:56": {Vendor: "VMware", Category: "vm", VirtNIC: "VMware", HypType: "VMware ESXi", VMOS: "💻 VMware VM"},
	"bc:24:11": {Vendor: "Proxmox", Category: "vm", VirtNIC: "Proxmox", HypType: "Proxmox VE", VMOS: "💻 KVM/Proxmox VM"},
	"52:54:00": {Vendor: "QEMU/KVM", Category: "vm", VirtNIC: "QEMU/KVM", HypType: "QEMU/KVM", VMOS: "💻 KVM/Proxmox VM"},
	"00:15:5d": {Vendor: "Hyper-V", Category: "vm", VirtNIC: "Hyper-V", HypType: "Hyper-V", VMOS: "🪟 Hyper-V VM"},
	"00:16:3e": {Vendor: "Xen", Category: "vm", VirtNIC: "Xen", HypType: "Xen", VMOS: "💻 Xen VM"},
	"08:00:27": {Vendor: "VirtualBox", Category: "vm", VirtNIC: "VirtualBox", HypType: "VirtualBox", VMOS: "💻 VirtualBox VM"},

	// Cameras
	"08:54:11": {Vendor: "Hikvision", Category: "camera"},
	"24:0f:9b": {Vendor: "Hikvision", Category: "camera"},
	"28:57:be": {Vendor: "Hikvision", Category: "camera"},
	"2c:a5:9c": {Vendor: "Hikvision", Category: "camera"},
	"40:ac:bf": {Vendor: "Hikvision", Category: "camera"},
	"44:47:cc": {Vendor: "Hikvision", Category: "camera"},
	"50:e5:38": {Vendor: "Hikvision", Category: "camera"},
	"54:c4:15": {Vendor: "Hikvision", Category: "camera"},
	"80:7c:62": {Vendor: "Hikvision", Category: "camera"},
	"80:be:af": {Vendor: "Hikvision", Category: "camera"},
	"a4:14:37": {Vendor: "Hikvision", Category: "camera"},
	"bc:9b:5e": {Vendor: "Hikvision", Category: "camera"},
	"bc:ad:28": {Vendor: "Hikvision", Category: "camera"},
	"c0:51:7e": {Vendor: "Hikvision", Category: "camera"},
	"c0:56:e3": {Vendor: "Hikvision", Category: "camera"},
	"e0:ca:3c": {Vendor: "Hikvision", Category: "camera"},
	"e8:a0:ed": {Vendor: "Hikvision", Category: "camera"},
	"f8:4d:fc": {Vendor: "Hikvision", Category: "camera"},
	"fc:9f:fd": {Vendor: "Hikvision", Category: "camera"},
	"3c:ef:8c": {Vendor: "Dahua", Category: "camera"},
	"90:02:a9": {Vendor: "Dahua", Category: "camera"},
	"a0:bd:1d": {Vendor: "Dahua", Category: "camera"},

	// Server makers: NICs and BMCs
	"00:25:90": {Vendor: "Supermicro", Category: "endpoint", ServerNIC: "SuperMicro"},
	"0c:c4:7a": {Vendor: "Supermicro", Category: "endpoint", ServerNIC: "SuperMicro", BMC: "Supermicro IPMI"},
	"3c:ec:ef": {ServerNIC: "SuperMicro"},
	"ac:1f:6b": {ServerNIC: "SuperMicro"},
	"00:e0:81": {Vendor: "Tyan", Category: "endpoint"},
	"a0:42:3f": {ServerNIC: "Tyan"},
	"34:40:b5": {ServerNIC: "Lenovo"},
	"90:1b:0e": {ServerNIC: "Fujitsu", BMC: "Fujitsu iRMC"},
	"00:19:99": {BMC: "Fujitsu iRMC"},
	"00:14:5e": {ServerNIC: "IBM"},
	"00:21:5e": {ServerNIC: "IBM", BMC: "IBM IMM"},
	"00:1a:64": {BMC: "IBM IMM"},
	"40:f2:e9": {BMC: "IBM IMM"},
	"6c:ae:8b": {BMC: "IBM IMM"},
	"00:00:17": {BMC: "Oracle ILOM"},
	"a8:5e:45": {BMC: "ASUS ASMB"},
	"70:85:c2": {BMC: "ASRock IPMI"},
	"d0:50:99": {BMC: "ASRock IPMI"},
	"00:e0:86": {BMC: "Avocent BMC"},

	// PC, laptop and NIC makers
	"00:cf:e0": {Vendor: "Intel", Category: "endpoint"},
	"14:85:7f": {Vendor: "Intel", Category: "endpoint"},
	"60:45:2e": {Vendor: "Intel", Category: "endpoint"},
	"7c:b2:7d": {Vendor: "Intel", Category: "endpoint"},
	"b4:96:91": {Vendor: "Intel", Category: "endpoint"},
	"00:e0:4c": {Vendor: "Realtek", Category: "endpoint"},
	"00:1f:c6": {Vendor: "ASUS", Category: "endpoint"},
	"04:92:26": {Vendor: "ASUS", Category: "endpoint"},
	"2c:56:dc": {Vendor: "ASUS", Category: "endpoint"},
	"d0:17:c2": {Vendor: "ASUS", Category: "endpoint"},
	"f0:2f:74": {Vendor: "ASUS", Category: "endpoint"},
	"f4:6d:04": {Vendor: "ASUS", Category: "endpoint"},
	"18:c0:4d": {Vendor: "Gigabyte", Category: "endpoint"},
	"1c:1b:0d": {Vendor: "Gigabyte", Category: "endpoint"},
	"e0:d5:5e": {Vendor: "Gigabyte", Category: "endpoint"},
	"94:c6:91": {Vendor: "EliteGroup", Category: "endpoint"},
	"c0:3f:d5": {Vendor: "EliteGroup", Category: "endpoint"},
	"f4:4d:30": {Vendor: "EliteGroup", Category: "endpoint"},
	"b8:97:5a": {Vendor: "Biostar", Category: "endpoint"},
	"00:d8:61": {Vendor: "MSI", Category: "endpoint"},
	"3c:97:0e": {Vendor: "Wistron", Category: "endpoint"},
	"98:ee:cb": {Vendor: "Wistron", Category: "endpoint"},
	"bc:ec:a0": {Vendor: "Compal", Category: "endpoint"},
	"e4:a8:df": {Vendor: "Compal", Category: "endpoint"},
	"b4:a9:fc": {Vendor: "Quanta", Category: "endpoint"},
	"90:2e:16": {Vendor: "LCFC", Category: "endpoint"},
	"00:23:81": {Vendor: "Lengda", Category: "endpoint"},
	"1c:2f:a2": {Vendor: "Shiyuan", Category: "endpoint"},
	"64:c9:01": {Vendor: "Inventec", Category: "endpoint"},
	"d4:6a:6a": {Vendor: "Hon Hai", Category: "endpoint"},
	"28:cd:c4": {Vendor: "Fugui", Category: "endpoint"},
	"ec:5c:68": {Vendor: "Fugui", Category: "endpoint"},
	"94:bb:43": {Vendor: "AzureWave", Category: "endpoint"},
	"b4:8c:9d": {Vendor: "AzureWave", Category: "endpoint"},
	"6c:b3:11": {Vendor: "Lianrui", Category: "endpoint"},
	"c4:ac:59": {Vendor: "Murata", Category: "endpoint"},
	"0c:37:96": {Vendor: "BizLink", Category: "endpoint"},
	"a0:3b:1b": {Vendor: "Inspire Tech", Category: "endpoint"},

	// Phones
	"00:03:93": {Vendor: "Apple", Category: "phone"},
	"00:0a:95": {Vendor: "Apple", Category: "phone"},
	"00:1c:b3": {Vendor: "Apple", Category: "phone"},
	"28:cf:e9": {Vendor: "Apple", Category: "phone"},
	"3c:22:fb": {Vendor: "Apple", Category: "phone"},
	"a4:5e:60": {Vendor: "Apple", Category: "phone"},
	"00:26:37": {Vendor: "Samsung", Category: "phone"},
	"00:f4:6f": {Vendor: "Samsung", Category: "phone"},
	"5c:0a:5b": {Vendor: "Samsung", Category: "phone"},
	"84:25:db": {Vendor: "Samsung", Category: "phone"},
	"8c:f5:a3": {Vendor: "Samsung", Category: "phone"},
	"94:01:c2": {Vendor: "Samsung", Category: "phone"},
	"ec:1f:72": {Vendor: "Samsung", Category: "phone"},
	"f4:09:d8": {Vendor: "Samsung", Category: "phone"},
	"28:6c:07": {Vendor: "Xiaomi", Category: "phone"},
	"38:a4:ed": {Vendor: "Xiaomi", Category: "phone"},
	"48:fd:a3": {Vendor: "Xiaomi", Category: "phone"},
	"58:44:98": {Vendor: "Xiaomi", Category: "phone"},
	"64:b4:73": {Vendor: "Xiaomi", Category: "phone"},
	"78:11:dc": {Vendor: "Xiaomi", Category: "phone"},
	"b0:e2:35": {Vendor: "Xiaomi", Category: "phone"},
	"f8:a4:5f": {Vendor: "Xiaomi", Category: "phone"},
	"88:44:36": {Vendor: "OPPO", Category: "phone"},
	"a4:3d:78": {Vendor: "OPPO", Category: "phone"},
	"5c:69:60": {Vendor: "vivo", Category: "phone"},

	// Printers
	"00:00:48": {Vendor: "Epson", Category: "printer"},
	"00:26:ab": {Vendor: "Epson", Category: "printer"},
	"64:eb:8c": {Vendor: "Epson", Category: "printer"},
	"00:1e:8f": {Vendor: "Canon", Category: "printer"},
	"00:1b:a9": {Vendor: "Brother", Category: "printer"},
	"30:05:5c": {Vendor: "Brother", Category: "printer"},

	// IoT
	"24:0a:c4": {Vendor: "ESP (Espressif)", Category: "iot"},
	"24:6f:28": {Vendor: "ESP (Espressif)", Category: "iot"},
	"60:01:94": {Vendor: "ESP (Espressif)", Category: "iot"},
	"a0:20:a6": {Vendor: "ESP (Espressif)", Category: "iot"},
	"a4:cf:12": {Vendor: "ESP (Espressif)", Category: "iot"},
	"b4:e6:2d": {Vendor: "ESP (Espressif)", Category: "iot"},
	"bc:dd:c2": {Vendor: "ESP (Espressif)", Category: "iot"},
	"cc:50:e3": {Vendor: "ESP (Espressif)", Category: "iot"},
}

// ouiVendorCategory is the category of every curated vendor name, so that
// categorizeVendor of a curated name gives the category of its OUIs (the
// graph categorizes lookupVendor's result).
var ouiVendorCategory = func() map[string]string {
	categories := map[string]string{}
	for _, role := range ouiRegistry {
		if role.Vendor != "" {
			categories[role.Vendor] = role.Category
		}
	}
	return categories
}()

// ============================================================
// IEEE OUI database
// ============================================================

var (
	ouiDB     oui.StaticDB // IEEE records from oui.txt; nil when none loaded
	ouiDBOnce sync.Once
	ouiDBOk   bool
)

// ouiOpenHTTP downloads the IEEE database when oui.txt cannot be opened.
// Tests replace it so nothing is downloaded.
var ouiOpenHTTP = ouiDownload

// ouiIEEEURL is where the IEEE publishes oui.txt.
const ouiIEEEURL = "http://standards-oui.ieee.org/oui.txt"

// initOUIDatabase tries to load the IEEE OUI database
func initOUIDatabase() {
	ouiDBOnce.Do(func() {
		// Try local file first
		db, err := loadOUIFile("oui.txt")
		if err == nil {
			ouiDB = db
			ouiDBOk = true
			fmt.Printf("✅ OUI database loaded: %d entries\n", len(db.RawDB()))
			return
		}
		fmt.Printf("⚠️ OUI file not loaded: %v\n", err)

		// Try downloading from IEEE
		fmt.Println("⏳ Downloading IEEE OUI database...")
		db, err = ouiOpenHTTP(ouiIEEEURL)
		if err == nil && db != nil {
			ouiDB = db
			ouiDBOk = true
			fmt.Printf("✅ OUI database downloaded: %d entries\n", len(db.RawDB()))
			return
		}

		fmt.Printf("⚠️ OUI database not available: %v\n", err)
		fmt.Printf("   Using the curated OUI registry only (%d OUIs)\n", len(ouiRegistry))
		ouiDBOk = false
	})
}

// loadOUIFile reads the IEEE database from an oui.txt file.
func loadOUIFile(path string) (oui.StaticDB, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	db, err := ouiParse(f)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return db, nil
}

// ouiDownload is the production ouiOpenHTTP: it fetches oui.txt from the IEEE.
func ouiDownload(url string) (oui.StaticDB, error) {
	return ouiFetch(&http.Client{Timeout: 2 * time.Minute}, url)
}

// ouiFetch downloads oui.txt with client. Anything but a 200 answer whose
// body holds OUI records is an error (an error page used to "load" as an
// empty database, F2).
func ouiFetch(client *http.Client, url string) (oui.StaticDB, error) {
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: HTTP status %d", url, resp.StatusCode)
	}
	db, err := ouiParse(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", url, err)
	}
	return db, nil
}

// ouiParse reads an IEEE oui.txt in either layout: the compact one shipped
// here ("00-00-0C   (hex)\t\tCisco Systems, Inc" then a "(base 16)" line,
// nothing else) and the one the IEEE publishes (a header, then address
// lines and a blank line after every record). Only the "(hex)" lines count;
// the name is kept even when empty. The library's own parser stops after the
// first record of the compact layout (F1). A text without a single record is
// an error.
func ouiParse(r io.Reader) (oui.StaticDB, error) {
	// oui.StaticDB has unexported methods, so only the library can make one:
	// an empty one from an empty input. RawDB returns its map.
	db, err := oui.OpenStatic(strings.NewReader(""))
	if err != nil {
		return nil, err
	}
	raw := db.RawDB()
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		head, name, ok := strings.Cut(sc.Text(), "(hex)")
		head = strings.TrimSpace(head)
		if !ok || len(head) != 8 || head[2] != '-' || head[5] != '-' {
			continue
		}
		var prefix [3]byte
		if _, err := hex.Decode(prefix[:], []byte(head[0:2]+head[3:5]+head[6:8])); err != nil {
			continue
		}
		raw[prefix] = oui.Entry{Prefix: oui.HardwareAddr(prefix), Manufacturer: strings.TrimSpace(name),
			Local: prefix[0]&0x02 != 0, Multicast: prefix[0]&0x01 != 0}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(raw) == 0 {
		return nil, errors.New("no OUI records")
	}
	return db, nil
}

// ouiIEEEName returns the IEEE organization of the MAC's OUI, or "" when no
// database is loaded or the record names no vendor: an empty name (F5),
// "Private", or an "IEEE Registration Authority" block that the IEEE split
// into MA-M/MA-S assignments, whose owners oui.txt does not list. A locally
// administered (random) address has no IEEE vendor either: the few records
// with that bit are company IDs, not the maker of a random address.
func ouiIEEEName(m macAddr) string {
	if ouiDB == nil || m.IsLocal() {
		return ""
	}
	e, ok := ouiDB.RawDB()[[3]byte{m[0], m[1], m[2]}]
	if !ok {
		return ""
	}
	name := strings.TrimSpace(e.Manufacturer)
	switch strings.ToLower(name) {
	case "private", "ieee registration authority":
		return ""
	}
	return name
}

// ============================================================
// Vendor and category
// ============================================================

// macVendorOf is the vendor of an address: the curated name, else the IEEE
// organization (Q1), else "". Special MACs (null, broadcast, multicast,
// zero OUI) have none.
func macVendorOf(m macAddr) string {
	if m.IsSpecial() {
		return ""
	}
	if vendor := ouiRegistry[m.OUI()].Vendor; vendor != "" {
		return vendor
	}
	return ouiIEEEName(m)
}

// lookupVendor resolves MAC address to vendor name: the curated name, else
// the IEEE organization, else "Unknown" (also for text that is no MAC).
func lookupVendor(mac string) string {
	if m, ok := parseMAC(mac); ok {
		if vendor := macVendorOf(m); vendor != "" {
			return vendor
		}
	}
	return "Unknown"
}

// getMACVendor returns vendor name for a MAC address based on OUI, "" when unknown.
func getMACVendor(mac string) string {
	vendor := lookupVendor(mac)
	if vendor == "Unknown" {
		return ""
	}
	return vendor
}

// ouiCategoryWords are the rules categorizeVendor applies to vendor names
// that are not curated (IEEE organization names); the first match wins. Each
// rule is a whole word or phrase of a vendor that makes one kind of device.
// Vendors that make several kinds (Huawei, Apple, Samsung, Microsoft, ...)
// have no rule and stay "endpoint", and no rule gives "vm": that comes only
// from a virtual-NIC OUI.
var ouiCategoryWords = []struct {
	category string
	words    []string
}{
	{"camera", []string{"hikvision", "dahua", "uniview", "axis communications", "hanwha vision", "hanwha techwin", "vivotek"}},
	{"access_point", []string{"ubiquiti", "aruba", "ruckus", "meraki"}},
	{"printer", []string{"epson", "canon", "brother industries", "kyocera document", "lexmark", "xerox", "ricoh", "konica"}},
	{"phone", []string{"oppo mobile", "vivo mobile", "oneplus", "realme", "hmd global"}},
	{"iot", []string{"espressif", "tuya"}},
	{"network", []string{"cisco", "juniper networks", "routerboard", "mikrotik", "d-link", "tp-link", "nagtech",
		"h3c", "hewlett packard", "hp inc", "procurve", "dell", "fortinet", "eltex"}},
}

// categorizeVendor maps a vendor name to a device category: the curated
// category for curated names, else the first ouiCategoryWords rule that
// matches, else "endpoint".
func categorizeVendor(vendor string) string {
	if category, ok := ouiVendorCategory[vendor]; ok {
		return category
	}
	v := strings.ToLower(vendor)
	for _, rule := range ouiCategoryWords {
		for _, w := range rule.words {
			if ouiHasWord(v, w) {
				return rule.category
			}
		}
	}
	return "endpoint"
}

// ouiHasWord reports whether s contains w as a whole word: the bytes around
// the match are not letters, digits or apostrophes ("dell'idea" is no "dell").
func ouiHasWord(s, w string) bool {
	for i := 0; ; {
		j := strings.Index(s[i:], w)
		if j < 0 {
			return false
		}
		j += i
		end := j + len(w)
		if (j == 0 || !ouiWordByte(s[j-1])) && (end == len(s) || !ouiWordByte(s[end])) {
			return true
		}
		i = j + 1
	}
}

func ouiWordByte(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || b == '\'' || b >= 0x80
}

// ============================================================
// IdentifyMAC
// ============================================================

// MACIdentity is everything the MAC layer knows about one address. (MACInfo,
// in snapshot_diff.go, is where a MAC was seen.)
type MACIdentity struct {
	Input     string  // the text given to IdentifyMAC
	MAC       macAddr // the parsed address; zero unless Valid
	Valid     bool    // Input is a MAC in a form parseMAC reads
	Canonical string  // "aa:bb:cc:dd:ee:ff"; "" unless Valid
	OUI       string  // "aa:bb:cc"; "" unless Valid

	// Address bits; all false unless Valid.
	Null, Broadcast, Multicast, Local, ZeroOUI bool

	Special bool // null, broadcast, multicast or zero OUI: filtered everywhere (Q11)
	Random  bool // locally administered unicast and no virtual NIC (Q4)

	Vendor    string // curated name, else the IEEE organization; "" when unknown
	Category  string // device category; "endpoint" when unknown
	VirtNIC   string // virtual-NIC platform: the address is a VM NIC
	HypType   string // hypervisor type of such a VM NIC
	VMOS      string // VM OS text of such a VM NIC
	ServerNIC string // server maker of the OUI
	BMCType   string // BMC maker of the OUI; a BMC also needs a name keyword (isBMC)
}

// IdentifyMAC parses s and returns its address bits, vendor, category and
// every OUI role. It never pings or resolves names.
func IdentifyMAC(s string) MACIdentity {
	id := MACIdentity{Input: s, Category: "endpoint"}
	m, ok := parseMAC(s)
	if !ok {
		return id
	}
	role := ouiRegistry[m.OUI()]
	id.MAC, id.Valid, id.Canonical, id.OUI = m, true, m.String(), m.OUI()
	id.Null, id.Broadcast, id.Multicast, id.Local, id.ZeroOUI = m.IsNull(), m.IsBroadcast(), m.IsMulticast(), m.IsLocal(), m.IsZeroOUI()
	id.Special = m.IsSpecial()
	id.Random = m.IsRandom() && role.VirtNIC == ""
	id.Vendor = macVendorOf(m)
	switch {
	case role.Vendor != "" && id.Vendor == role.Vendor:
		id.Category = role.Category
	case id.Vendor != "":
		id.Category = categorizeVendor(id.Vendor)
	}
	id.VirtNIC, id.HypType, id.VMOS = role.VirtNIC, role.HypType, role.VMOS
	id.ServerNIC, id.BMCType = role.ServerNIC, role.BMC
	return id
}

// ============================================================
// Virtual NICs and VMs
// ============================================================

// isHypervisorMAC checks if a MAC address belongs to a known hypervisor vendor
// (a virtual NIC: VMware, Proxmox/KVM, Hyper-V, Xen, VirtualBox).
func isHypervisorMAC(mac string) bool {
	return ouiRegistry[ouiKey(mac)].VirtNIC != ""
}

// isHypervisorPort checks if the majority of MACs on a port are from hypervisors
func isHypervisorPort(macs []string) bool {
	if len(macs) == 0 {
		return false
	}
	vmCount := 0
	for _, mac := range macs {
		if isHypervisorMAC(mac) {
			vmCount++
		}
	}
	// If more than 50% of MACs are hypervisor MACs, it's a VM server
	return float64(vmCount)/float64(len(macs)) > 0.5
}

// hypervisorTypeOf returns the hypervisor a VM NIC's OUI belongs to:
// "VMware ESXi" for every VMware OUI, "Proxmox VE", "QEMU/KVM", "Hyper-V",
// "Xen" or "VirtualBox".
func hypervisorTypeOf(mac string) (string, bool) {
	t := ouiRegistry[ouiKey(mac)].HypType
	return t, t != ""
}

// vmOSFromOUI returns the VM OS text of a VM NIC's OUI ("💻 VMware VM"), or "".
func vmOSFromOUI(mac string) string {
	return ouiRegistry[ouiKey(mac)].VMOS
}

// detectOSFromMAC guesses the OS of a VM: by a TTL ping when its IP is known,
// else by its virtual-NIC OUI. The *DeviceData argument is not used: the
// LLDP-name step it fed could never match, because MACs known from LLDP never
// reach the VM branch (F37).
func detectOSFromMAC(mac string, macToIP map[string]string, _ *DeviceData) string {
	// 1. TTL fingerprinting via quick ping (1 attempt, 1 second timeout)
	if ip, ok := macToIP[normalizeMAC(mac)]; ok && ip != "" {
		if osLabel := detectOSByTTL(ip); osLabel != "" {
			return osLabel
		}
	}
	// 2. Fallback: guess by MAC prefix
	if osLabel := vmOSFromOUI(mac); osLabel != "" {
		return osLabel
	}
	return "❓ Unknown VM"
}

// ============================================================
// Server NICs and BMCs
// ============================================================

// isServerNIC returns true if the MAC belongs to a known server vendor NIC
// (Dell PowerEdge, HPE ProLiant, SuperMicro, Tyan, Cisco UCS etc.). PC/laptop
// ODMs and the SNR switches are not server makers (Q6, Q7).
// Used to detect ESXi/KVM hypervisors that run on physical servers.
func isServerNIC(mac string) (bool, string) {
	vendor := ouiRegistry[ouiKey(mac)].ServerNIC
	return vendor != "", vendor
}

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

// bmcTypeByOUI returns the BMC maker the MAC's OUI names, or "". Server
// makers use the same OUIs for ordinary NICs, so an OUI never makes a BMC on
// its own (Q5).
func bmcTypeByOUI(mac string) string {
	return ouiRegistry[ouiKey(mac)].BMC
}

// isBMC detects server BMC/management interfaces (iDRAC, iLO, IPMI, XCC, iRMC, CIMC)
// by a keyword in the LLDP or DNS name (Q5). The OUI only names the maker of a
// BMC whose name just says "BMC" or "IPMI": server makers use the same OUIs
// for ordinary NICs, so a server NIC without such a name is no BMC.
// Returns (isBMC bool, bmcType string e.g. "Dell iDRAC").
func isBMC(mac, name string) (bool, string) {
	kind := bmcTypeByName(name)
	if kind == "" {
		return false, ""
	}
	if kind == "BMC" || kind == "IPMI" {
		if maker := bmcTypeByOUI(mac); maker != "" {
			kind = maker
		}
	}
	return true, kind
}

// ============================================================
// Filters
// ============================================================

// isRandomMAC checks if a MAC address uses locally administered address (random/private):
// the U/L bit is set and the I/G bit is not, e.g. da:a1:19:... (a phone's private
// Wi-Fi address). A known virtual-NIC OUI is a VM, not random, even with the
// U/L bit set (52:54:00 QEMU/KVM) (Q4). Text that is no MAC is never random.
func isRandomMAC(mac string) bool {
	m, ok := parseMAC(mac)
	return ok && m.IsRandom() && ouiRegistry[m.OUI()].VirtNIC == ""
}

// isSpecialMAC checks if MAC is broadcast, null, multicast or zero-OUI (should be
// filtered everywhere, Q11). It reads the bits of the parsed address, so text that
// is no MAC (a hostname, an IP) is never special (F38).
func isSpecialMAC(mac string) bool {
	m, ok := parseMAC(mac)
	return ok && m.IsSpecial()
}

// isInvalidID checks if an ID is garbage/invalid (should be filtered).
// A MAC is invalid when isSpecialMAC says so (null, broadcast, multicast,
// zero OUI). Any other id (hostname, IP, port name) is invalid only when it is
// empty or all zeros ("0.0.0.0", "0:0:0:0", "::"), or when it is a broken MAC
// ("01:ac:10:01:0f"); short hostnames like "SW1" are valid (F38, F39; Q11).
func isInvalidID(id string) bool {
	if m, ok := parseMAC(id); ok {
		return m.IsSpecial()
	}
	id = strings.TrimSpace(id)
	if strings.Trim(id, "0:.- ") == "" {
		return true
	}
	if net.ParseIP(id) != nil {
		return false
	}
	return macIsBrokenMAC(id)
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
