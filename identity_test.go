package main

import "testing"

func TestIsRandomMAC(t *testing.T) {
	tests := []struct {
		mac      string
		expected bool
		desc     string
	}{
		// Random MACs (second hex char is 2, 6, A, or E)
		{"da:a1:19:00:00:01", true, "second char 'a' → random"},
		{"d2:a1:19:00:00:01", true, "second char '2' → random"},
		{"d6:a1:19:00:00:01", true, "second char '6' → random"},
		{"de:a1:19:00:00:01", true, "second char 'e' → random"},
		{"fa:b1:c2:d3:e4:f5", true, "second char 'a' → random"},
		{"f6:11:22:33:44:55", true, "second char '6' → random"},
		{"72:ab:cd:ef:01:23", true, "second char '2' → random"},

		// Real MACs (second hex char NOT 2, 6, A, E)
		{"00:1a:2b:3c:4d:5e", false, "second char '0' → real"},
		{"4c:ae:a3:8e:42:11", false, "second char 'c' → real (SNR switch)"},
		{"f8:f0:82:12:34:56", false, "second char '8' → real (SNR)"},
		{"00:0c:29:aa:bb:cc", false, "second char '0' → real (VMware)"},
		{"e4:38:83:11:22:33", false, "second char '4' → real (Ubiquiti)"},
		{"00:50:56:aa:bb:cc", false, "second char '0' → real (VMware)"},
		{"08:00:27:11:22:33", false, "second char '8' → real (VirtualBox)"},

		// Edge cases
		{"", false, "empty → not random"},
		{"a", false, "too short → not random"},
	}

	for _, tt := range tests {
		result := isRandomMAC(tt.mac)
		if result != tt.expected {
			t.Errorf("isRandomMAC(%q) = %v, want %v (%s)", tt.mac, result, tt.expected, tt.desc)
		}
	}
}

func TestResolveHostname(t *testing.T) {
	// Test with localhost (should resolve)
	hostname := resolveHostname("127.0.0.1")
	t.Logf("resolveHostname(127.0.0.1) = %q", hostname)
	// We can't assert exact value since it depends on system config,
	// but it should not panic

	// Test with invalid IP
	hostname = resolveHostname("999.999.999.999")
	if hostname != "" {
		t.Errorf("Expected empty for invalid IP, got %q", hostname)
	}
}
