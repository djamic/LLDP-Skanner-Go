package main

import (
	"slices"

	"lldp_scanner/modules/kit"
)

// sysTextWord is one word of sysTextWords.
type sysTextWord struct {
	word, vendor string
	switchOS     bool // a switch platform's word
}

// sysTextWords is what the words of a sysName or a sysDescr (a polled
// device's own, an LLDP neighbor's RemSysName and RemSysDesc) tell of the
// device: its vendor (the reports' vendor of a device without an OUI
// vendor, reportDeviceVendor; the Zabbix templates) and whether it runs a
// switch platform (graphIsSwitchNode: no ESXi host is made of a switch). A
// word matches as a whole word, case aside (kit.HasWord: "hp" is no part of
// "dhcp"); the first word, in this order, that a text holds names its
// vendor ("SNR HP" is SNR's). The MAC's vendor is mac_identity.go's, the
// phone makers' the voip module's.
var sysTextWords = []sysTextWord{
	{"snr", "SNR", true},
	{"mikrotik", "MikroTik", false},
	{"cisco", "Cisco", true},
	{"aruba", "Aruba", true}, // AOS-S and AOS-CX
	{"hpe", "HPE", false},
	{"hp", "HPE", false},
	{"ubiquiti", "Ubiquiti", false},
	{"ubnt", "Ubiquiti", false},
	{"huawei", "Huawei", true}, // VRP
	{"fortinet", "Fortinet", false},
	{"fortigate", "Fortinet", false},
	{"fortiswitch", "Fortinet", true},
	{"pixietech", "PiXiETECH", true},
	{"comware", "", true}, // HPE's and H3C's: no one vendor
}

// sysTextVendor is the vendor the first of texts that names one names
// (sysTextWords), "" when none does.
func sysTextVendor(texts ...string) string {
	for _, text := range texts {
		for _, w := range sysTextWords {
			if w.vendor != "" && kit.HasWord(text, w.word) {
				return w.vendor
			}
		}
	}
	return ""
}

// sysTextSwitchOS reports whether text names a switch platform.
func sysTextSwitchOS(text string) bool {
	return slices.ContainsFunc(sysTextWords, func(w sysTextWord) bool { return w.switchOS && kit.HasWord(text, w.word) })
}
