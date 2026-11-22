package main

import "testing"

// TestSysTextWords (D6): one table tells the vendor and the switch
// platform a sysName or sysDescr names: whole words, case aside.
func TestSysTextWords(t *testing.T) {
	for _, c := range []struct {
		text, vendor string
		switchOS     bool
	}{
		{"HPE Comware Platform Software, Version 7.1.070", "HPE", true},
		{"H3C Comware Platform Software", "", true}, // Comware: a switch, no one vendor
		{"Huawei Versatile Routing Platform Software", "Huawei", true},
		{"HUAWEI", "Huawei", true},
		{"PiXiETECH(tm) PXT-S2790G-24FX Software", "PiXiETECH", true},
		{"FortiSwitch-148F-FPOE v7.2.5", "Fortinet", true},
		{"FortiGate-600F", "Fortinet", false},
		{"Aruba JL659A 6300M 48SR5", "Aruba", true},
		{"SNR HP", "SNR", true}, // the first word, in the table's order
		{"A_padval_SNR", "SNR", true},
		{"dhcp relay agent", "", false},
		{"MikroTik RouterOS", "MikroTik", false},
		{"VMware ESXi 7.0.3", "", false},
	} {
		if got := sysTextVendor(c.text); got != c.vendor {
			t.Errorf("sysTextVendor(%q) = %q, want %q", c.text, got, c.vendor)
		}
		if got := sysTextSwitchOS(c.text); got != c.switchOS {
			t.Errorf("sysTextSwitchOS(%q) = %v, want %v", c.text, got, c.switchOS)
		}
	}
	if got := sysTextVendor("B-318/1", "HPE Comware Platform Software"); got != "HPE" {
		t.Errorf("a sysName that names none, then its sysDescr: %q", got)
	}
}
