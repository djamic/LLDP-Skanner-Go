package main

import (
	"fmt"
	"strings"
	"sync"

	"github.com/klauspost/oui"
)

// ============================================================
// OUI Vendor Lookup — IEEE database + local fallback
// ============================================================

var (
	ouiDB     oui.OuiDB
	ouiDBOnce sync.Once
	ouiDBOk   bool

	// Extended OUI database — covers top vendors in TUIT network
	// This supplements the library when IEEE download fails
	extendedVendorDB = map[string]string{
		// ===== Network Equipment =====
		"4c:ae:a3": "SNR",
		"f8:f0:82": "SNR",
		"00:0f:e2": "SNR",
		"e4:38:83": "Ubiquiti",
		"f0:9f:c2": "Ubiquiti",
		"80:2a:a8": "Ubiquiti",
		"dc:9f:db": "Ubiquiti",
		"74:83:c2": "Ubiquiti",
		"24:5a:4c": "Ubiquiti",
		"f4:92:bf": "Ubiquiti",
		"18:e8:29": "Ubiquiti",
		"ac:8b:a9": "Ubiquiti",
		"78:8a:20": "Ubiquiti",
		"68:72:51": "Ubiquiti",
		"b4:fb:e4": "Ubiquiti",
		"44:d9:e7": "Ubiquiti",
		"24:a4:3c": "Ubiquiti",
		"70:a7:41": "Ubiquiti",

		// HP / HPE / Aruba
		"1c:1b:0d": "HP",
		"3c:d9:2b": "HP",
		"6c:02:e0": "HP",
		"98:e7:f4": "HPE",
		"b4:99:ba": "HPE",
		"94:18:82": "HPE",
		"18:a9:05": "HP",
		"a0:d3:c1": "HP",
		"00:1e:0b": "HP",
		"2c:41:38": "HP",
		"00:4e:35": "HP Aruba",
		"00:4e:01": "HP Aruba",
		"d8:c7:c8": "Aruba",
		"00:0b:86": "Aruba",
		"24:de:c6": "Aruba",
		"6c:f3:7f": "Aruba",
		"20:4c:03": "Aruba",
		"94:b4:0f": "Aruba",

		// Cisco
		"00:1b:2a": "Cisco",
		"00:1c:57": "Cisco",
		"00:25:45": "Cisco",
		"f8:c2:88": "Cisco",
		"68:86:a7": "Cisco",
		"00:17:94": "Cisco",
		"00:1a:a1": "Cisco",
		"30:f7:0d": "Cisco",
		"f4:cf:e2": "Cisco",

		// Dell
		"14:fe:b5": "Dell",
		"18:66:da": "Dell",
		"f8:db:88": "Dell",
		"f0:1f:af": "Dell",
		"b0:83:fe": "Dell",
		"00:14:22": "Dell",
		"f8:bc:12": "Dell",

		// MikroTik
		"00:0c:42": "MikroTik",
		"4c:5e:0c": "MikroTik",
		"48:8f:5a": "MikroTik",
		"b8:69:f4": "MikroTik",
		"cc:2d:e0": "MikroTik",
		"e4:8d:8c": "MikroTik",
		"d4:01:c3": "MikroTik",
		"2c:c8:1b": "MikroTik",
		"6c:3b:6b": "MikroTik",
		"74:4d:28": "MikroTik",
		"dc:2c:6e": "MikroTik",

		// Huawei
		"00:18:82": "Huawei",
		"00:25:68": "Huawei",
		"00:46:4b": "Huawei",
		"84:69:93": "Huawei",
		"e0:d9:e3": "Huawei",
		"48:ad:08": "Huawei",
		"ac:cf:85": "Huawei",
		"88:28:b3": "Huawei",
		"80:be:af": "Huawei",
		"78:45:58": "Huawei",
		"2c:a5:9c": "Huawei",
		"08:54:11": "Huawei",
		"bc:9b:5e": "Huawei",
		"e0:ca:3c": "Huawei",
		"50:e5:38": "Huawei",
		"80:7c:62": "Huawei",
		"04:f9:38": "Huawei",
		"7c:a2:3e": "Huawei",
		"c8:d1:5e": "Huawei",
		"28:31:52": "Huawei",
		"70:8c:b6": "Huawei",
		"f8:4d:fc": "Huawei",
		"c0:51:7e": "Huawei",
		"c4:07:2f": "Huawei",
		"34:29:12": "Huawei",
		"cc:a2:23": "Huawei",
		"9c:05:d6": "Huawei",
		"40:ac:bf": "Huawei",
		"fc:9f:fd": "Huawei",

		// ZTE
		"e8:a0:ed": "ZTE",
		"54:af:97": "ZTE",
		"0c:37:96": "ZTE",
		"14:85:7f": "ZTE",
		"60:45:2e": "ZTE",
		"30:f3:1d": "ZTE",
		"f4:e2:c6": "ZTE",
		"9c:c1:72": "ZTE",
		"00:19:c6": "ZTE",

		// TP-Link
		"50:c7:bf": "TP-Link",
		"60:e3:27": "TP-Link",
		"10:fe:ed": "TP-Link",
		"14:cc:20": "TP-Link",
		"18:d6:c7": "TP-Link",
		"30:b5:c2": "TP-Link",
		"50:3e:aa": "TP-Link",
		"5c:e9:31": "TP-Link",
		"a4:2b:b0": "TP-Link",
		"ec:08:6b": "TP-Link",
		"b0:95:75": "TP-Link",
		"64:70:02": "TP-Link",

		// D-Link
		"00:1c:f0": "D-Link",
		"00:22:b0": "D-Link",
		"28:10:7b": "D-Link",
		"1c:5f:2b": "D-Link",
		"c8:be:19": "D-Link",
		"84:c9:b2": "D-Link",
		"34:08:04": "D-Link",

		// ===== Virtual Machines =====
		"00:0c:29": "VMware",
		"00:50:56": "VMware",
		"00:15:5d": "Hyper-V",
		"08:00:27": "VirtualBox",
		"52:54:00": "QEMU/KVM",
		"00:16:3e": "Xen",

		// ===== Cameras / Surveillance =====
		"00:23:81": "Dahua",
		"3c:ef:8c": "Dahua",
		"a0:bd:1d": "Dahua",
		"90:02:a9": "Dahua",
		"54:c4:15": "Hikvision",
		"c0:56:e3": "Hikvision",
		"bc:ad:28": "Hikvision",
		"28:57:be": "Hikvision",
		"44:47:cc": "Hikvision",
		"c0:3f:d5": "Hikvision",
		"a4:14:37": "Hikvision",
		"98:ee:cb": "Shenzhen Videopark",

		// ===== PC / NIC Manufacturers =====
		"00:e0:4c": "Realtek",
		"94:c6:91": "EliteGroup",
		"f4:4d:30": "EliteGroup",
		"bc:ec:a0": "Gigabyte",
		"1c:2f:a2": "Gigabyte",
		"b4:a9:fc": "Gigabyte",
		"90:2e:16": "Gigabyte",
		"94:bb:43": "Intel",
		"a4:bb:6d": "Intel",
		"3c:22:fb": "Intel",
		"00:1f:c6": "Intel",
		"00:25:90": "Intel",
		"84:39:8f": "Intel",
		"e0:d5:5e": "Intel",
		"00:cf:e0": "Intel",
		"5c:ed:8c": "Intel",
		"6c:b3:11": "Intel",
		"b4:96:91": "Intel",
		"f4:6d:04": "Intel",
		"8c:ec:4b": "ASUS",
		"f0:2f:74": "ASUS",
		"04:92:26": "ASUS",
		"2c:56:dc": "ASUS",
		"b8:97:5a": "Biostar",
		"48:f3:17": "Shenzhen Reecam",
		"b4:7a:f1": "Supermicro",
		"0c:c4:7a": "Supermicro",
		"00:e0:81": "Tyan",
		"3c:97:0e": "MSI",
		"00:d8:61": "MSI",

		// ===== Mobile / Phone =====
		"00:03:93": "Apple",
		"00:0a:95": "Apple",
		"00:1c:b3": "Apple",
		"28:cf:e9": "Apple",
		"a4:5e:60": "Apple",
		"00:26:37": "Samsung",
		"5c:0a:5b": "Samsung",
		"84:25:db": "Samsung",
		"ec:1f:72": "Samsung",
		"8c:f5:a3": "Samsung",
		"94:01:c2": "Samsung",
		"00:f4:6f": "Samsung",
		"d0:17:c2": "Samsung",
		"f4:09:d8": "Samsung",
		"28:6c:07": "Xiaomi",
		"64:b4:73": "Xiaomi",
		"f8:a4:5f": "Xiaomi",
		"58:44:98": "Xiaomi",
		"78:11:dc": "Xiaomi",
		"38:a4:ed": "Xiaomi",
		"b0:e2:35": "Xiaomi",
		"7c:b2:7d": "OPPO",
		"48:fd:a3": "OPPO",
		"a4:3d:78": "OPPO",
		"88:44:36": "OPPO",
		"dc:ee:06": "OPPO",
		"a0:3b:1b": "vivo",
		"d4:6a:6a": "vivo",
		"5c:69:60": "vivo",
		"ec:5c:68": "vivo",

		// ===== Printers =====
		"00:00:48": "Epson",
		"00:26:ab": "Epson",
		"64:eb:8c": "Epson",
		"00:1e:8f": "Canon",
		"c4:ac:59": "Canon",
		"00:1b:a9": "Brother",
		"30:05:5c": "Brother",
		"00:1a:2f": "Kyocera",

		// ===== IoT / Smart Home =====
		"18:c0:4d": "GIGA-TMS",
		"28:cd:c4": "Phicomm",
		"e4:a8:df": "Phicomm",
		"5c:ba:2c": "Phicomm",
		"cc:50:e3": "ESP (Espressif)",
		"24:6f:28": "ESP (Espressif)",
		"a4:cf:12": "ESP (Espressif)",
		"bc:dd:c2": "ESP (Espressif)",
		"60:01:94": "ESP (Espressif)",
		"b4:e6:2d": "ESP (Espressif)",
		"24:0a:c4": "ESP (Espressif)",
		"a0:20:a6": "ESP (Espressif)",

		// ===== Other =====
		"64:c9:01": "ELSA",
		"b4:8c:9d": "AzureWave",
		"94:40:c9": "HMD Global (Nokia)",
		"24:0f:9b": "Technicolor",
		"00:e2:69": "Unknown (OUI 00:e2:69)",
		"64:6e:ea": "Unknown (OUI 64:6e:ea)",
		"00:00:5e": "IANA (VRRP)",
	}
)

// initOUIDatabase tries to load the IEEE OUI database
func initOUIDatabase() {
	ouiDBOnce.Do(func() {
		// Try local file first
		db, err := oui.OpenStaticFile("oui.txt")
		if err == nil {
			ouiDB = db
			ouiDBOk = true
			raw := db.RawDB()
			fmt.Printf("✅ OUI database loaded: %d entries\n", len(raw))
			return
		}

		// Try downloading from IEEE
		fmt.Println("⏳ Downloading IEEE OUI database...")
		db2, err := oui.OpenStaticHttp("http://standards-oui.ieee.org/oui.txt")
		if err == nil {
			ouiDB = db2
			ouiDBOk = true
			raw := db2.RawDB()
			fmt.Printf("✅ OUI database downloaded: %d entries\n", len(raw))
			return
		}

		fmt.Printf("⚠️ OUI database not available: %v\n", err)
		fmt.Printf("   Using extended local database (%d entries)\n", len(extendedVendorDB))
		ouiDBOk = false
	})
}

// ============================================================
// normalizeMAC — canonical MAC address normalization
// Converts ANY MAC format to lowercase colon-separated:
//   "4C AE A3 27 84 CA" → "4c:ae:a3:27:84:ca"
//   "4c-ae-a3-27-84-ca" → "4c:ae:a3:27:84:ca"
//   "4C:AE:A3:27:84:CA" → "4c:ae:a3:27:84:ca"
//   "\"4c:ae:a3:27:84:ca\"" → "4c:ae:a3:27:84:ca"
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

// lookupVendor resolves MAC address to vendor name
// Priority: 1) klauspost/oui (IEEE), 2) extendedVendorDB (local)
func lookupVendor(mac string) string {
	mac = normalizeMAC(mac)
	if len(mac) < 8 {
		return "Unknown"
	}

	prefix := mac[:8] // "aa:bb:cc"

	// 1. Try IEEE OUI database
	if ouiDBOk && ouiDB != nil {
		entry, err := ouiDB.Query(mac)
		if err == nil && entry != nil {
			return strings.TrimSpace(entry.Manufacturer)
		}
	}

	// 2. Try extended local database
	if vendor, ok := extendedVendorDB[prefix]; ok {
		return vendor
	}

	return "Unknown"
}

// categorizeVendor maps vendor name to a device category
func categorizeVendor(vendor string) string {
	v := strings.ToLower(vendor)

	// Cameras
	if strings.Contains(v, "hikvision") || strings.Contains(v, "dahua") ||
		strings.Contains(v, "videopark") || strings.Contains(v, "uniview") ||
		strings.Contains(v, "axis") || strings.Contains(v, "hanwha") {
		return "camera"
	}

	// Access Points
	if strings.Contains(v, "ubiquiti") || strings.Contains(v, "aruba") ||
		strings.Contains(v, "ruckus") || strings.Contains(v, "meraki") ||
		strings.Contains(v, "unifi") {
		return "access_point"
	}

	// Printers
	if strings.Contains(v, "epson") || strings.Contains(v, "canon") ||
		strings.Contains(v, "brother") || strings.Contains(v, "kyocera") ||
		strings.Contains(v, "lexmark") || strings.Contains(v, "xerox") ||
		strings.Contains(v, "ricoh") || strings.Contains(v, "konica") {
		return "printer"
	}

	// Phones/Mobile
	if strings.Contains(v, "samsung") || strings.Contains(v, "xiaomi") ||
		strings.Contains(v, "apple") || strings.Contains(v, "oppo") ||
		strings.Contains(v, "vivo") || strings.Contains(v, "huawei") ||
		strings.Contains(v, "nokia") || strings.Contains(v, "hmd global") ||
		strings.Contains(v, "oneplus") || strings.Contains(v, "realme") {
		return "phone"
	}

	// IoT
	if strings.Contains(v, "esp") || strings.Contains(v, "espressif") ||
		strings.Contains(v, "tuya") || strings.Contains(v, "shenzhen") ||
		strings.Contains(v, "giga-tms") {
		return "iot"
	}

	// VMs
	if strings.Contains(v, "vmware") || strings.Contains(v, "hyper-v") ||
		strings.Contains(v, "virtualbox") || strings.Contains(v, "qemu") ||
		strings.Contains(v, "kvm") || strings.Contains(v, "xen") {
		return "vm"
	}

	// Switches/Networking (not endpoint)
	if strings.Contains(v, "snr") || strings.Contains(v, "cisco") ||
		strings.Contains(v, "mikrotik") || strings.Contains(v, "hp") ||
		strings.Contains(v, "hpe") || strings.Contains(v, "dell") ||
		strings.Contains(v, "d-link") || strings.Contains(v, "tp-link") {
		return "network"
	}

	return "endpoint"
}
