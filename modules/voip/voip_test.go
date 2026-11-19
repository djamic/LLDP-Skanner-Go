package voip

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"lldp_scanner/modules"
)

// Test cases use RFC 5737 documentation/test subnets (192.0.2.0/24 = C0 00 02 xx,
// 198.51.100.0/24 = C6 33 64 xx, 203.0.113.0/24 = CB 00 71 xx) and synthetic
// host MAC suffixes (:00:00:xx) so tests are completely portable and environment-independent.
func TestDetectYealinkAndGrandstream(t *testing.T) {
	cases := []struct {
		name         string
		ev           Evidence
		wantOK       bool
		wantBrand    string
		wantModel    string
		wantFirmware string
		wantIP       string
		wantBridge   bool
	}{
		{
			name: "Grandstream GRP2613 LLDP",
			ev: Evidence{
				MAC:            "c0:74:ad:00:00:11",
				Vendor:         "Grandstream Networks, Inc.",
				SysName:        "GRP2613_c0:74:ad:00:00:11",
				SysDesc:        "GRP2613 1.0.7.33",
				PortDesc:       "\"eth0\"",
				Capabilities:   0x24,
				ChassisSubtype: 5,
				ChassisID:      "01 C0 00 02 11", // 192.0.2.17 (RFC 5737 TEST-NET-1)
			},
			wantOK:       true,
			wantBrand:    "Grandstream",
			wantModel:    "GRP2613",
			wantFirmware: "1.0.7.33",
			wantIP:       "192.0.2.17",
			wantBridge:   true,
		},
		{
			name: "Grandstream GXP1625 LLDP",
			ev: Evidence{
				MAC:            "c0:74:ad:00:00:12",
				Vendor:         "Grandstream Networks, Inc.",
				SysName:        "GXP1625_c0:74:ad:00:00:12",
				SysDesc:        "GXP1625 1.0.7.8",
				PortDesc:       "\"eth0\"",
				Capabilities:   0x24,
				ChassisSubtype: 5,
				ChassisID:      "01 C6 33 64 12", // 198.51.100.18 (RFC 5737 TEST-NET-2)
			},
			wantOK:       true,
			wantBrand:    "Grandstream",
			wantModel:    "GXP1625",
			wantFirmware: "1.0.7.8",
			wantIP:       "198.51.100.18",
			wantBridge:   true,
		},
		{
			name: "Grandstream FDB-only OUI",
			ev: Evidence{
				MAC:    "c0:74:ad:00:00:13",
				Vendor: "Grandstream Networks, Inc.",
				MgmtIP: "192.0.2.19",
			},
			wantOK:    true,
			wantBrand: "Grandstream",
			wantIP:    "192.0.2.19",
		},
		{
			name: "Grandstream GWN7660 Wi-Fi AP is NOT a phone",
			ev: Evidence{
				MAC:          "c0:74:ad:00:00:14",
				Vendor:       "Grandstream Networks, Inc.",
				SysName:      "GWN7660",
				SysDesc:      "GWN7660 1.0.25.30",
				Capabilities: CapBridge | CapWLANAP,
			},
			wantOK: false,
		},
		{
			name: "Grandstream GWN7802P switch is NOT a phone even without WLAN bit",
			ev: Evidence{
				MAC:     "c0:74:ad:00:00:15",
				Vendor:  "Grandstream Networks, Inc.",
				SysName: "GWN7802P",
				SysDesc: "Grandstream GWN7802P Switch",
			},
			wantOK: false,
		},
		{
			name: "Yealink SIP-T48U LLDP",
			ev: Evidence{
				MAC:            "c4:fc:22:00:00:21",
				Vendor:         "YEALINK(XIAMEN) NETWORK TECHNOLOGY CO.,LTD.",
				SysName:        "SIP-T48U",
				SysDesc:        "108.86.0.90",
				PortDesc:       "\"WAN PORT\"",
				Capabilities:   0x24,
				ChassisSubtype: 5,
				ChassisID:      "01 C0 00 02 21", // 192.0.2.33
			},
			wantOK:       true,
			wantBrand:    "Yealink",
			wantModel:    "SIP-T48U",
			wantFirmware: "108.86.0.90",
			wantIP:       "192.0.2.33",
			wantBridge:   true,
		},
		{
			name: "Yealink SIP-T30P LLDP",
			ev: Evidence{
				MAC:            "80:5e:c0:00:00:22",
				Vendor:         "YEALINK(XIAMEN) NETWORK TECHNOLOGY CO.,LTD.",
				SysName:        "SIP-T30P",
				SysDesc:        "124.85.0.35",
				PortDesc:       "\"WAN PORT\"",
				Capabilities:   0x24,
				ChassisSubtype: 5,
				ChassisID:      "01 C0 00 02 22", // 192.0.2.34
			},
			wantOK:       true,
			wantBrand:    "Yealink",
			wantModel:    "SIP-T30P",
			wantFirmware: "124.85.0.35",
			wantIP:       "192.0.2.34",
			wantBridge:   true,
		},
		{
			name: "Yealink FDB-only OUI",
			ev: Evidence{
				MAC:    "c4:fc:22:00:00:23",
				Vendor: "YEALINK(XIAMEN) NETWORK TECHNOLOGY CO.,LTD.",
			},
			wantOK:    true,
			wantBrand: "Yealink",
		},
		{
			name: "Avaya AVX phone LLDP",
			ev: Evidence{
				MAC:          "c8:1f:ea:00:00:31",
				Vendor:       "Avaya Inc",
				SysName:      "AVXC00031",
				Capabilities: 0x20,
				MgmtIP:       "198.51.100.31",
			},
			wantOK:     true,
			wantBrand:  "Avaya",
			wantModel:  "AVXC00031",
			wantIP:     "198.51.100.31",
			wantBridge: true,
		},
		{
			name: "Panasonic KX-HDV230RU LLDP",
			ev: Evidence{
				MAC:            "4c:36:4e:00:00:41",
				Vendor:         "Panasonic Communications Co., Ltd.",
				SysName:        "KX-HDV230RU",
				SysDesc:        "Panasonic",
				PortDesc:       "\"LAN PORT\"",
				Capabilities:   0x04,
				ChassisSubtype: 5,
				ChassisID:      "01 CB 00 71 41", // 203.0.113.65 (RFC 5737 TEST-NET-3)
			},
			wantOK:       true,
			wantBrand:    "Panasonic",
			wantModel:    "KX-HDV230RU",
			wantFirmware: "",
			wantIP:       "203.0.113.65",
			wantBridge:   false,
		},
		{
			name: "Panasonic laptop without CapPhone or KX-* stays non-phone",
			ev: Evidence{
				MAC:    "4c:36:4e:00:00:42",
				Vendor: "Panasonic Corporation",
			},
			wantOK: false,
		},
		{
			name: "Fanvil H81 LLDP",
			ev: Evidence{
				MAC:          "68:69:2e:00:00:51",
				Vendor:       "Unknown",
				SysName:      "H81",
				SysDesc:      "2.0.4-93-g25fa5ef build 3455",
				PortDesc:     "\"WAN Port 10M/100M\"",
				Capabilities: 0x24,
				MgmtIP:       "192.0.2.51",
			},
			wantOK:       true,
			wantBrand:    "Fanvil",
			wantModel:    "H81",
			wantFirmware: "2.0.4-93-g25fa5ef build 3455",
			wantIP:       "192.0.2.51",
			wantBridge:   true,
		},
		{
			name: "Cisco switch without CapPhone stays non-phone",
			ev: Evidence{
				MAC:          "58:94:80:00:00:61",
				Vendor:       "Cisco Systems, Inc",
				SysName:      "SW-CORE",
				SysDesc:      "Cisco IOS Software",
				Capabilities: CapBridge | CapRouter,
			},
			wantOK: false,
		},
		{
			name: "Cisco CP-8841 IP Phone is detected",
			ev: Evidence{
				MAC:          "00:1b:54:00:00:62",
				Vendor:       "Cisco Systems, Inc",
				SysName:      "SEP001B54000062",
				SysDesc:      "Cisco IP Phone CP-8841, V12",
				Capabilities: CapBridge | CapPhone,
			},
			wantOK:       true,
			wantBrand:    "Cisco",
			wantModel:    "CP-8841",
			wantFirmware: "V12",
			wantBridge:   true,
		},
	}

	for _, tc := range cases {
		p, ok := Detect(tc.ev)
		if ok != tc.wantOK {
			t.Errorf("%s: Detect ok=%v, want %v (profile=%+v)", tc.name, ok, tc.wantOK, p)
			continue
		}
		if !ok {
			continue
		}
		if p.Brand != tc.wantBrand || p.Model != tc.wantModel || p.Firmware != tc.wantFirmware || p.IP != tc.wantIP || p.PCBridge != tc.wantBridge {
			t.Errorf("%s: got %+v, want brand=%q model=%q fw=%q ip=%q bridge=%v",
				tc.name, p, tc.wantBrand, tc.wantModel, tc.wantFirmware, tc.wantIP, tc.wantBridge)
		}
	}
}

func TestDecodeChassisIPv4EdgeCases(t *testing.T) {
	if got := DecodeChassisIPv4(5, "01 C0 00"); got != "" {
		t.Errorf("truncated chassis IP = %q, want empty", got)
	}
	if got := DecodeChassisIPv4(5, "01 C0 00 02 00"); got != "" {
		t.Errorf(".0 network address = %q, want empty", got)
	}
	if got := DecodeChassisIPv4(5, "01 C0 00 02 0F"); got != "192.0.2.15" {
		t.Errorf("valid chassis IP = %q, want 192.0.2.15", got)
	}
}

func TestCustomRuleExtensibility(t *testing.T) {
	t.Cleanup(func() { UnregisterRule("custom-test-voip") })
	RegisterRule(Rule{
		ID:               "custom-test-voip",
		Brand:            "CustomSIP",
		Priority:         110,
		DedicatedVendors: []string{"customsip telecom"},
		Match: func(ev Evidence) (string, string, bool) {
			if strings.HasPrefix(ev.SysName, "CSIP-") {
				return ev.SysName, "v9.1", true
			}
			return "", "", false
		},
	})
	p, ok := Detect(Evidence{SysName: "CSIP-9000", Capabilities: CapPhone})
	if !ok || p.Brand != "CustomSIP" || p.Model != "CSIP-9000" || p.Firmware != "v9.1" {
		t.Fatalf("custom rule failed: ok=%v profile=%+v", ok, p)
	}
	if !IsDedicatedVoIPVendor("CustomSIP Telecom LLC") {
		t.Fatal("expected IsDedicatedVoIPVendor to recognize custom rule vendor")
	}
}

func TestGrandstreamAndYealinkHTTPModules(t *testing.T) {
	gsSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "mini_httpd/1.30 26Oct2018")
		switch r.URL.Path {
		case "/":
			w.Write([]byte(`<html><script src="webapp/webapp.nocache.js"></script></html>`))
		case "/cgi-bin/dologin":
			r.ParseForm()
			if r.FormValue("password") != "secret" {
				w.Write([]byte(`{"response":"error","body":{}}`))
				return
			}
			w.Write([]byte(`{"response":"success","body":{"sid":"sid123"}}`))
		case "/cgi-bin/api-get_phone_status":
			w.Write([]byte(`{"response":"success","body":{"product_model":"GXP1625","prog_version":"1.0.7.8"}}`))
		}
	}))
	defer gsSrv.Close()
	gsHost, _, _ := net.SplitHostPort(gsSrv.Listener.Addr().String())

	gs := GrandstreamModule{BaseURL: gsSrv.URL}
	if !gs.CheckWebUI(context.Background(), gsHost) {
		t.Fatal("GrandstreamModule.CheckWebUI = false, want true")
	}
	if _, err := gs.Run(context.Background(), modules.Request{IP: gsHost, Action: "detect", Login: modules.Login{Username: "admin", Password: "wrong"}}); !errors.Is(err, modules.ErrLoginRejected) {
		t.Fatalf("wrong password err = %v, want ErrLoginRejected", err)
	}
	res, err := gs.Run(context.Background(), modules.Request{IP: gsHost, Action: "detect", Login: modules.Login{Username: "admin", Password: "secret"}})
	if err != nil || !strings.Contains(res.Summary, "Grandstream") || len(res.Facts) < 4 {
		t.Fatalf("Grandstream Run = (%+v, %v)", res, err)
	}

	ylSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Write([]byte(`<html><title>Yealink</title><form action="/servlet?m=mod_listener&p=login"></form></html>`))
		case "/servlet":
			r.ParseForm()
			if r.FormValue("pwd") != "ylpass" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.Write([]byte(`ok`))
		}
	}))
	defer ylSrv.Close()
	ylHost, _, _ := net.SplitHostPort(ylSrv.Listener.Addr().String())

	yl := YealinkModule{BaseURL: ylSrv.URL}
	if !yl.CheckWebUI(context.Background(), ylHost) {
		t.Fatal("YealinkModule.CheckWebUI = false, want true")
	}
	if _, err := yl.Run(context.Background(), modules.Request{IP: ylHost, Action: "detect", Login: modules.Login{Username: "admin", Password: "ylpass"}}); err != nil {
		t.Fatalf("Yealink Run err = %v", err)
	}
}
