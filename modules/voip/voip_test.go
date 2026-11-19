package voip

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"lldp_scanner/modules"
)

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
			name: "Grandstream GRP2613 live LLDP",
			ev: Evidence{
				MAC:            "c0:74:ad:96:03:25",
				Vendor:         "Grandstream Networks, Inc.",
				SysName:        "GRP2613_c0:74:ad:96:03:25",
				SysDesc:        "GRP2613 1.0.7.33",
				PortDesc:       "\"eth0\"",
				Capabilities:   0x24,
				ChassisSubtype: 5,
				ChassisID:      "01 C0 A8 B1 AB",
			},
			wantOK:       true,
			wantBrand:    "Grandstream",
			wantModel:    "GRP2613",
			wantFirmware: "1.0.7.33",
			wantIP:       "192.168.177.171",
			wantBridge:   true,
		},
		{
			name: "Grandstream GXP1625 live LLDP",
			ev: Evidence{
				MAC:            "c0:74:ad:40:61:c6",
				Vendor:         "Grandstream Networks, Inc.",
				SysName:        "GXP1625_c0:74:ad:40:61:c6",
				SysDesc:        "GXP1625 1.0.7.8",
				PortDesc:       "\"eth0\"",
				Capabilities:   0x24,
				ChassisSubtype: 5,
				ChassisID:      "01 0A 43 0A 5C",
			},
			wantOK:       true,
			wantBrand:    "Grandstream",
			wantModel:    "GXP1625",
			wantFirmware: "1.0.7.8",
			wantIP:       "10.67.10.92",
			wantBridge:   true,
		},
		{
			name: "Grandstream FDB-only OUI",
			ev: Evidence{
				MAC:    "c0:74:ad:ae:9b:91",
				Vendor: "Grandstream Networks, Inc.",
				MgmtIP: "192.168.176.179",
			},
			wantOK:    true,
			wantBrand: "Grandstream",
			wantIP:    "192.168.176.179",
		},
		{
			name: "Grandstream GWN7660 Wi-Fi AP is NOT a phone",
			ev: Evidence{
				MAC:          "c0:74:ad:11:22:33",
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
				MAC:     "c0:74:ad:aa:bb:cc",
				Vendor:  "Grandstream Networks, Inc.",
				SysName: "GWN7802P",
				SysDesc: "Grandstream GWN7802P Switch",
			},
			wantOK: false,
		},
		{
			name: "Yealink SIP-T48U live LLDP",
			ev: Evidence{
				MAC:            "c4:fc:22:21:0b:90",
				Vendor:         "YEALINK(XIAMEN) NETWORK TECHNOLOGY CO.,LTD.",
				SysName:        "SIP-T48U",
				SysDesc:        "108.86.0.90",
				PortDesc:       "\"WAN PORT\"",
				Capabilities:   0x24,
				ChassisSubtype: 5,
				ChassisID:      "01 C0 A8 B1 1D",
			},
			wantOK:       true,
			wantBrand:    "Yealink",
			wantModel:    "SIP-T48U",
			wantFirmware: "108.86.0.90",
			wantIP:       "192.168.177.29",
			wantBridge:   true,
		},
		{
			name: "Yealink SIP-T30P live LLDP",
			ev: Evidence{
				MAC:            "80:5e:c0:eb:e1:80",
				Vendor:         "YEALINK(XIAMEN) NETWORK TECHNOLOGY CO.,LTD.",
				SysName:        "SIP-T30P",
				SysDesc:        "124.85.0.35",
				PortDesc:       "\"WAN PORT\"",
				Capabilities:   0x24,
				ChassisSubtype: 5,
				ChassisID:      "01 C0 A8 B0 0F",
			},
			wantOK:       true,
			wantBrand:    "Yealink",
			wantModel:    "SIP-T30P",
			wantFirmware: "124.85.0.35",
			wantIP:       "192.168.176.15",
			wantBridge:   true,
		},
		{
			name: "Yealink FDB-only OUI",
			ev: Evidence{
				MAC:    "c4:fc:22:c8:ce:40",
				Vendor: "YEALINK(XIAMEN) NETWORK TECHNOLOGY CO.,LTD.",
			},
			wantOK:    true,
			wantBrand: "Yealink",
		},
		{
			name: "Avaya AVXC28D65 live LLDP",
			ev: Evidence{
				MAC:          "c8:1f:ea:c2:8d:65",
				Vendor:       "Avaya Inc",
				SysName:      "AVXC28D65",
				Capabilities: 0x20,
				MgmtIP:       "10.67.10.67",
			},
			wantOK:     true,
			wantBrand:  "Avaya",
			wantModel:  "AVXC28D65",
			wantIP:     "10.67.10.67",
			wantBridge: true,
		},
		{
			name: "Panasonic KX-HDV230RU live LLDP",
			ev: Evidence{
				MAC:            "4c:36:4e:7b:1b:45",
				Vendor:         "Panasonic Communications Co., Ltd.",
				SysName:        "KX-HDV230RU",
				SysDesc:        "Panasonic",
				PortDesc:       "\"LAN PORT\"",
				Capabilities:   0x04,
				ChassisSubtype: 5,
				ChassisID:      "01 C0 A8 B2 50",
			},
			wantOK:       true,
			wantBrand:    "Panasonic",
			wantModel:    "KX-HDV230RU",
			wantFirmware: "",
			wantIP:       "192.168.178.80",
			wantBridge:   false,
		},
		{
			name: "Panasonic laptop without CapPhone or KX-* stays non-phone",
			ev: Evidence{
				MAC:    "4c:36:4e:00:11:22",
				Vendor: "Panasonic Corporation",
			},
			wantOK: false,
		},
		{
			name: "Fanvil H81 live LLDP",
			ev: Evidence{
				MAC:          "68:69:2e:01:21:7f",
				Vendor:       "ZyXEL / Unknown",
				SysName:      "H81",
				SysDesc:      "2.0.4-93-g25fa5ef build 3455",
				PortDesc:     "\"WAN Port 10M/100M\"",
				Capabilities: 0x24,
				MgmtIP:       "192.168.176.148",
			},
			wantOK:       true,
			wantBrand:    "Fanvil",
			wantModel:    "H81",
			wantFirmware: "2.0.4-93-g25fa5ef build 3455",
			wantIP:       "192.168.176.148",
			wantBridge:   true,
		},
		{
			name: "Cisco switch without CapPhone stays non-phone",
			ev: Evidence{
				MAC:          "58:94:80:00:f7:a3",
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
				MAC:          "00:1b:54:11:22:33",
				Vendor:       "Cisco Systems, Inc",
				SysName:      "SEP001B54112233",
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
	if got := DecodeChassisIPv4(5, "01 AC 10"); got != "" {
		t.Errorf("truncated SNR chassis IP = %q, want empty", got)
	}
	if got := DecodeChassisIPv4(5, "01 AC 10 01 00"); got != "" {
		t.Errorf(".0 network address = %q, want empty", got)
	}
	if got := DecodeChassisIPv4(5, "01 AC 10 01 0F"); got != "172.16.1.15" {
		t.Errorf("valid chassis IP = %q, want 172.16.1.15", got)
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

	gs := GrandstreamModule{BaseURL: gsSrv.URL}
	if !gs.CheckWebUI(context.Background(), "127.0.0.1") {
		t.Fatal("GrandstreamModule.CheckWebUI = false, want true")
	}
	if _, err := gs.Run(context.Background(), modules.Request{IP: "127.0.0.1", Action: "detect", Login: modules.Login{Username: "admin", Password: "wrong"}}); !errors.Is(err, modules.ErrLoginRejected) {
		t.Fatalf("wrong password err = %v, want ErrLoginRejected", err)
	}
	res, err := gs.Run(context.Background(), modules.Request{IP: "127.0.0.1", Action: "detect", Login: modules.Login{Username: "admin", Password: "secret"}})
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

	yl := YealinkModule{BaseURL: ylSrv.URL}
	if !yl.CheckWebUI(context.Background(), "127.0.0.1") {
		t.Fatal("YealinkModule.CheckWebUI = false, want true")
	}
	if _, err := yl.Run(context.Background(), modules.Request{IP: "127.0.0.1", Action: "detect", Login: modules.Login{Username: "admin", Password: "ylpass"}}); err != nil {
		t.Fatalf("Yealink Run err = %v", err)
	}
}
