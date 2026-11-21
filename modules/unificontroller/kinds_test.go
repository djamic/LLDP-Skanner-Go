package unificontroller

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"lldp_scanner/modules"
)

// TestDeviceKind: a gateway is a gateway by its model, whatever its
// features say and whether the older API was read or not; the others by
// their features.
func TestDeviceKind(t *testing.T) {
	for _, c := range []struct {
		model, features, want string
	}{
		{"UDM Pro", `["switching"]`, modules.KindGateway},
		{"UDMPRO", `["switching","accessPoint"]`, modules.KindGateway},
		{"UDR", `["accessPoint","switching"]`, modules.KindGateway},
		{"UCG Ultra", `[]`, modules.KindGateway},
		{"UXG-Lite", `null`, modules.KindGateway},
		{"USG-3P", ``, modules.KindGateway},
		{"UX", `["accessPoint"]`, modules.KindGateway},
		{"USW Pro 24", `["switching"]`, modules.KindSwitch},
		{"US 8 60W", `["switching"]`, modules.KindSwitch},
		{"U6 Pro", `["accessPoint"]`, modules.KindAccessPoint},
		{"U6 LR", `{"accessPoint":{}}`, modules.KindAccessPoint},
		{"UAP-AC-M-Pro", `["accessPoint","switching"]`, modules.KindAccessPoint},
		{"", ``, ""},
	} {
		d := device{Model: c.model, Features: json.RawMessage(c.features)}
		got := d.kind()
		if got != c.want {
			t.Errorf("kind of %q %s = %q, want %q", c.model, c.features, got, c.want)
		}
		// the older API agrees on a gateway: classicKinds["udm"]
		if c.want == modules.KindGateway && classicKinds["udm"] != got {
			t.Errorf("%q: the older API's udm is %q", c.model, classicKinds["udm"])
		}
	}
}

// TestManagedState: the states the scanner reads (modules.State*).
func TestManagedState(t *testing.T) {
	for in, want := range map[string]string{
		"ONLINE": modules.StateOnline, "online": modules.StateOnline, "OFFLINE": modules.StateOffline,
		"CONNECTION_INTERRUPTED": modules.StateOffline, "ISOLATED": modules.StateOffline, "disconnected": modules.StateOffline,
		"ADOPTING": "ADOPTING", "pending_adoption": "PENDING_ADOPTION", "": "",
	} {
		if got := managedState(in); got != want {
			t.Errorf("managedState(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestProbeAsksInfoOnce: Probe's two checks of an address read one answer
// of its /info.
func TestProbeAsksInfoOnce(t *testing.T) {
	var infos atomic.Int32
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/":
			fmt.Fprint(w, `<html><head><title>Router admin</title></head></html>`)
		case strings.HasSuffix(r.URL.Path, "/info"):
			infos.Add(1)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":{"code":401,"message":"Unauthorized"}}`)
		default:
			http.NotFound(w, r)
		}
	})
	srv := serve(t, h)
	useBases(t, srv.URL+prefix)
	useStatusURLs(t, closedURL(t)+"/status")
	if (Module{}).Probe(context.Background(), "10.9.60.5") {
		t.Error("Probe = true for a web server that is no UniFi OS console")
	}
	if n := infos.Load(); n != 1 {
		t.Errorf("/info asked %d times, want once", n)
	}
}
