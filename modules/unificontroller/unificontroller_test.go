package unificontroller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"lldp_scanner/modules"
)

// Every name, address and key here is made up.

const (
	testKey = "test-key-0123456789"
	prefix  = "/proxy/network/integration/v1"
)

// fakeController is the Network Integration API of a UniFi Network
// application under prefix: it takes key, and gives at most pageSize items
// in one page, as the real API caps a page.
type fakeController struct {
	key      string
	info     string // the /info answer
	sites    []map[string]any
	devices  map[string][]map[string]any // by site ID
	clients  map[string][]map[string]any // by site ID
	pageSize int
	noTotal  bool // pages with no totalCount

	mu     sync.Mutex
	keys   []string       // the X-API-KEY of every request
	limits []string       // the limit of every list request
	pages  map[string]int // list requests by path
}

func newFake() *fakeController {
	wireless := func(device string) map[string]any {
		return map[string]any{"type": "WIRELESS", "uplinkDeviceId": device}
	}
	wired := func(device string) map[string]any { return map[string]any{"type": "WIRED", "uplinkDeviceId": device} }
	return &fakeController{
		key:  testKey,
		info: `{"applicationVersion":"9.0.114"}`,
		sites: []map[string]any{
			{"id": "s-main", "internalReference": "default", "name": "Main"},
			{"id": "s-lab", "internalReference": "lab1", "name": "Lab"},
		},
		devices: map[string][]map[string]any{
			"s-main": {
				{"id": "d-sw", "name": "Core USW", "model": "USW Pro 24", "macAddress": "aa:bb:cc:00:00:01", "ipAddress": "10.9.60.2",
					"state": "ONLINE", "firmwareVersion": "7.1.26", "features": []string{"switching"}},
				{"id": "d-ap2", "name": "AP-B", "model": "U6 Pro", "macAddress": "aa:bb:cc:00:00:03", "ipAddress": "10.9.60.12",
					"state": "OFFLINE", "uplink": map[string]any{"deviceId": "d-sw"}},
				{"id": "d-ap1", "name": "ap-a", "model": "U6 Lite", "macAddress": "aa:bb:cc:00:00:02", "ipAddress": "10.9.60.11",
					"state": "ONLINE", "firmwareVersion": "6.6.77", "uplink": map[string]any{"deviceId": "d-sw"}},
			},
			"s-lab": {
				{"id": "d-ap9", "name": "Lab AP", "model": "U6 LR", "macAddress": "aa:bb:cc:00:00:09", "ipAddress": "10.9.61.5",
					"state": "ONLINE", "uplink": map[string]any{"deviceId": "d-elsewhere"}},
			},
		},
		clients: map[string][]map[string]any{
			"s-main": {
				wireless("d-ap1"), wired("d-sw"), wireless("d-ap1"), wireless("d-ap2"),
				{"type": "VPN", "name": "remote"}, wired("d-sw"), wireless("d-ap1"),
			},
			"s-lab": {wireless("d-ap9"), wireless("d-ap9")},
		},
		pageSize: 3,
		pages:    map[string]int{},
	}
}

func (f *fakeController) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+prefix+"/info", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, f.info)
	})
	mux.HandleFunc("GET "+prefix+"/sites", func(w http.ResponseWriter, r *http.Request) { f.list(w, r, f.sites) })
	mux.HandleFunc("GET "+prefix+"/sites/{site}/devices", func(w http.ResponseWriter, r *http.Request) {
		f.list(w, r, f.devices[r.PathValue("site")])
	})
	mux.HandleFunc("GET "+prefix+"/sites/{site}/clients", func(w http.ResponseWriter, r *http.Request) {
		f.list(w, r, f.clients[r.PathValue("site")])
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.Header.Get("X-API-KEY")
		f.mu.Lock()
		f.keys = append(f.keys, key)
		f.mu.Unlock()
		if key != f.key {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprintf(w, `{"statusCode":401,"statusName":"UNAUTHORIZED","code":"api.authentication.missing-credentials",`+
				`"message":"Missing credentials","timestamp":"2026-01-01T00:00:00Z","requestPath":%q,"requestId":"0000"}`, r.URL.Path)
			return
		}
		mux.ServeHTTP(w, r)
	})
}

// list answers one page of items, as the API does.
func (f *fakeController) list(w http.ResponseWriter, r *http.Request, items []map[string]any) {
	f.mu.Lock()
	f.limits = append(f.limits, r.URL.Query().Get("limit"))
	f.pages[r.URL.Path]++
	f.mu.Unlock()
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	limit, err := strconv.Atoi(r.URL.Query().Get("limit"))
	if err != nil || limit <= 0 {
		limit = 25
	}
	limit = min(limit, f.pageSize)
	data := items[min(offset, len(items)):min(offset+limit, len(items))]
	page := map[string]any{"offset": offset, "limit": limit, "count": len(data), "data": data}
	if !f.noTotal {
		page["totalCount"] = len(items)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(page)
}

func (f *fakeController) requests() (keys, limits []string, pages map[string]int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	pagesCopy := map[string]int{}
	for k, v := range f.pages {
		pagesCopy[k] = v
	}
	return append([]string(nil), f.keys...), append([]string(nil), f.limits...), pagesCopy
}

func serve(t *testing.T, h http.Handler) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	return srv
}

// closedURL is an address where nothing listens.
func closedURL(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	return "https://" + addr
}

func useBases(t *testing.T, bases ...string) {
	old := apiBases
	apiBases = func(string) []string { return bases }
	t.Cleanup(func() { apiBases = old })
}

func useStatusURLs(t *testing.T, urls ...string) {
	old := statusURLs
	statusURLs = func(string) []string { return urls }
	t.Cleanup(func() { statusURLs = old })
}

func detectWith(key string) (modules.Result, error) {
	return Module{}.Run(context.Background(), modules.Request{IP: "10.9.60.5", Action: "detect", Login: modules.Login{Password: key}})
}

func fact(r modules.Result, label string) string {
	for _, f := range r.Facts {
		if f.Label == label {
			return f.Value
		}
	}
	return ""
}

func table(t *testing.T, r modules.Result, title string) modules.Table {
	t.Helper()
	for _, tb := range r.Tables {
		if strings.HasPrefix(tb.Title, title) {
			return tb
		}
	}
	t.Fatalf("no table %q in %+v", title, r.Tables)
	return modules.Table{}
}

func sameRows(t *testing.T, tb modules.Table, want [][]string) {
	t.Helper()
	if !reflect.DeepEqual(tb.Rows, want) {
		t.Errorf("%s rows:\n got %q\nwant %q", tb.Title, tb.Rows, want)
	}
}

// checkStandard checks the result of detect on newFake's data.
func checkStandard(t *testing.T, r modules.Result, base string) {
	t.Helper()
	if want := "UniFi Network 9.0.114: 2 sites, 4 devices (3 online), 9 clients"; r.Summary != want {
		t.Errorf("summary %q, want %q", r.Summary, want)
	}
	for label, want := range map[string]string{
		"Application version": "9.0.114",
		"API":                 base,
		"Sites":               "Lab, Main",
		"Device states":       "ONLINE 3, OFFLINE 1",
		"Clients":             "9 (2 wired, 6 wireless)",
		"Not read":            "",
	} {
		if got := fact(r, label); got != want {
			t.Errorf("fact %s = %q, want %q", label, got, want)
		}
	}
	devices := table(t, r, "Devices")
	if want := []string{"Site", "Name", "Model", "MAC", "IP", "State", "Firmware", "Uplink"}; !reflect.DeepEqual(devices.Columns, want) {
		t.Errorf("device columns %q", devices.Columns)
	}
	sameRows(t, devices, [][]string{
		{"Lab", "Lab AP", "U6 LR", "aa:bb:cc:00:00:09", "10.9.61.5", "ONLINE", "", "d-elsewhere"},
		{"Main", "ap-a", "U6 Lite", "aa:bb:cc:00:00:02", "10.9.60.11", "ONLINE", "6.6.77", "Core USW"},
		{"Main", "AP-B", "U6 Pro", "aa:bb:cc:00:00:03", "10.9.60.12", "OFFLINE", "", "Core USW"},
		{"Main", "Core USW", "USW Pro 24", "aa:bb:cc:00:00:01", "10.9.60.2", "ONLINE", "7.1.26", ""},
	})
	clients := table(t, r, "Clients by device")
	if clients.Title != "Clients by device" {
		t.Errorf("clients title %q", clients.Title)
	}
	sameRows(t, clients, [][]string{
		{"Lab", "Lab AP", "0", "2", "0"},
		{"Main", "(none)", "0", "0", "1"},
		{"Main", "ap-a", "0", "3", "0"},
		{"Main", "AP-B", "0", "1", "0"},
		{"Main", "Core USW", "2", "0", "0"},
	})
}

func TestDetectUniFiOS(t *testing.T) {
	f := newFake()
	srv := serve(t, f.handler())
	base := srv.URL + prefix
	useBases(t, base, closedURL(t)+prefix)
	r, err := detectWith(testKey)
	if err != nil {
		t.Fatal(err)
	}
	checkStandard(t, r, base)

	keys, limits, pages := f.requests()
	for _, k := range keys {
		if k != testKey {
			t.Errorf("a request carried X-API-KEY %q, want %q", k, testKey)
		}
	}
	if len(keys) == 0 {
		t.Error("no request reached the API")
	}
	for _, l := range limits {
		if l != "200" {
			t.Errorf("a list was asked with limit %q, want 200", l)
		}
	}
	// 7 clients of Main, 3 to a page: 3 pages
	if n := pages[prefix+"/sites/s-main/clients"]; n != 3 {
		t.Errorf("Main's clients read in %d pages, want 3", n)
	}
}

func TestDetectSelfHosted(t *testing.T) {
	f := newFake()
	selfHosted := serve(t, f.handler()) // the application on port 8443
	base := selfHosted.URL + prefix

	t.Run("another web server on 443", func(t *testing.T) {
		other := serve(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/" {
				fmt.Fprint(w, "<html>It works</html>")
				return
			}
			http.NotFound(w, r)
		}))
		useBases(t, other.URL+prefix, base)
		r, err := detectWith(testKey)
		if err != nil {
			t.Fatal(err)
		}
		checkStandard(t, r, base)
	})
	t.Run("a web page for every path on 443", func(t *testing.T) {
		other := serve(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, "<!doctype html><html><title>UniFi OS</title></html>")
		}))
		useBases(t, other.URL+prefix, base)
		r, err := detectWith(testKey)
		if err != nil {
			t.Fatal(err)
		}
		checkStandard(t, r, base)
	})
	t.Run("nothing on 443", func(t *testing.T) {
		useBases(t, closedURL(t)+prefix, base)
		r, err := detectWith(testKey)
		if err != nil {
			t.Fatal(err)
		}
		checkStandard(t, r, base)
	})
}

func TestNoAPI(t *testing.T) {
	other := serve(t, http.NotFoundHandler())
	useBases(t, other.URL+prefix, closedURL(t)+prefix)
	_, err := detectWith(testKey)
	if err == nil || errors.Is(err, modules.ErrLoginRejected) {
		t.Fatalf("err = %v, want a no-API error that is no refused login", err)
	}
	if strings.Contains(err.Error(), testKey) {
		t.Errorf("the error carries the key: %v", err)
	}
}

func TestKeyRefused(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			f := newFake()
			h := f.handler()
			if status == http.StatusForbidden {
				h = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusForbidden)
					fmt.Fprint(w, `{"statusCode":403,"statusName":"FORBIDDEN","message":"Forbidden"}`)
				})
			}
			srv := serve(t, h)
			next := newFake()
			nextSrv := serve(t, next.handler())
			useBases(t, srv.URL+prefix, nextSrv.URL+prefix)
			_, err := detectWith("wrong-key-42")
			if !errors.Is(err, modules.ErrLoginRejected) {
				t.Fatalf("err = %v, want one that wraps ErrLoginRejected", err)
			}
			if strings.Contains(err.Error(), "wrong-key-42") {
				t.Errorf("the error carries the key: %v", err)
			}
			if keys, _, _ := next.requests(); len(keys) != 0 {
				t.Errorf("the next base was tried after a refused key: %d requests", len(keys))
			}
		})
	}
	t.Run("no key", func(t *testing.T) {
		f := newFake()
		srv := serve(t, f.handler())
		useBases(t, srv.URL+prefix)
		if _, err := detectWith("  "); !errors.Is(err, modules.ErrLoginRejected) {
			t.Fatalf("err = %v, want one that wraps ErrLoginRejected", err)
		}
		if keys, _, _ := f.requests(); len(keys) != 0 {
			t.Errorf("%d requests with no key", len(keys))
		}
	})
}

func TestRedirectNotFollowed(t *testing.T) {
	var mu sync.Mutex
	var leaked []string
	elsewhere := serve(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		leaked = append(leaked, r.Header.Get("X-API-KEY"))
		mu.Unlock()
		fmt.Fprint(w, `{"applicationVersion":"1.0"}`)
	}))
	redirecting := serve(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.URL+r.URL.Path, http.StatusFound)
	}))
	f := newFake()
	srv := serve(t, f.handler())
	useBases(t, redirecting.URL+prefix, srv.URL+prefix)
	r, err := detectWith(testKey)
	if err != nil {
		t.Fatal(err)
	}
	checkStandard(t, r, srv.URL+prefix)
	mu.Lock()
	defer mu.Unlock()
	if len(leaked) != 0 {
		t.Errorf("a redirect was followed: %d requests elsewhere, keys %q", len(leaked), leaked)
	}
}

func TestPagination(t *testing.T) {
	manyClients := func(n int) []map[string]any {
		out := make([]map[string]any, n)
		for i := range out {
			kind := "WIRELESS"
			if i%5 == 0 {
				kind = "WIRED"
			}
			out[i] = map[string]any{"type": kind, "uplinkDeviceId": "d-ap1"}
		}
		return out
	}
	oneSite := func(f *fakeController, clients int) {
		f.sites = f.sites[:1]
		f.devices = map[string][]map[string]any{"s-main": {{"id": "d-ap1", "name": "ap-a", "state": "ONLINE"}}}
		f.clients = map[string][]map[string]any{"s-main": manyClients(clients)}
	}

	t.Run("pages of 200", func(t *testing.T) {
		f := newFake()
		f.pageSize = 200
		oneSite(f, 450)
		srv := serve(t, f.handler())
		useBases(t, srv.URL+prefix)
		r, err := detectWith(testKey)
		if err != nil {
			t.Fatal(err)
		}
		if want := "UniFi Network 9.0.114: 1 site, 1 device (1 online), 450 clients"; r.Summary != want {
			t.Errorf("summary %q, want %q", r.Summary, want)
		}
		sameRows(t, table(t, r, "Clients by device"), [][]string{{"Main", "ap-a", "90", "360", "0"}})
		if _, _, pages := f.requests(); pages[prefix+"/sites/s-main/clients"] != 3 {
			t.Errorf("clients read in %d pages, want 3", pages[prefix+"/sites/s-main/clients"])
		}
	})
	t.Run("no totalCount", func(t *testing.T) {
		for _, n := range []int{7, 6} { // the last page short, or full and then an empty one
			f := newFake()
			f.noTotal = true
			oneSite(f, n)
			srv := serve(t, f.handler())
			useBases(t, srv.URL+prefix)
			r, err := detectWith(testKey)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.HasSuffix(r.Summary, fmt.Sprintf(", %d clients", n)) {
				t.Errorf("%d clients: summary %q", n, r.Summary)
			}
		}
	})
	t.Run("capped", func(t *testing.T) {
		f := newFake()
		f.pageSize = 200
		oneSite(f, maxItems+100)
		srv := serve(t, f.handler())
		useBases(t, srv.URL+prefix)
		r, err := detectWith(testKey)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasSuffix(r.Summary, fmt.Sprintf(", %d clients", maxItems+100)) {
			t.Errorf("summary %q, want the API's total", r.Summary)
		}
		clients := table(t, r, "Clients by device")
		if want := fmt.Sprintf("Clients by device (the first %d of %d clients)", maxItems, maxItems+100); clients.Title != want {
			t.Errorf("title %q, want %q", clients.Title, want)
		}
		if _, _, pages := f.requests(); pages[prefix+"/sites/s-main/clients"] != maxItems/200 {
			t.Errorf("clients read in %d pages, want %d", pages[prefix+"/sites/s-main/clients"], maxItems/200)
		}
	})
}

func TestMissingFields(t *testing.T) {
	f := newFake()
	f.info = `{}`
	f.sites = []map[string]any{{"id": "s-1"}}
	f.devices = map[string][]map[string]any{"s-1": {
		{"id": "d-1"},
		{"id": "d-2", "macAddress": "aa:bb:cc:00:00:22", "state": "ONLINE", "uplink": map[string]any{}},
		{"id": "d-3", "name": "Mesh AP", "state": "ONLINE", "uplink": nil, "uplinkDeviceId": "d-2"},
	}}
	f.clients = map[string][]map[string]any{"s-1": {{"uplinkDeviceId": "d-1"}, {}}}
	srv := serve(t, f.handler())
	useBases(t, srv.URL+prefix)
	r, err := detectWith(testKey)
	if err != nil {
		t.Fatal(err)
	}
	if want := "UniFi Network: 1 site, 3 devices (2 online), 2 clients"; r.Summary != want {
		t.Errorf("summary %q, want %q", r.Summary, want)
	}
	if got := fact(r, "Application version"); got != "" {
		t.Errorf("application version %q, want none", got)
	}
	if got := fact(r, "Sites"); got != "s-1" {
		t.Errorf("sites %q, want the site's id", got)
	}
	if got := fact(r, "Device states"); got != "ONLINE 2, unknown 1" {
		t.Errorf("device states %q", got)
	}
	sameRows(t, table(t, r, "Devices"), [][]string{
		{"s-1", "", "", "", "", "", "", ""},
		{"s-1", "", "", "aa:bb:cc:00:00:22", "", "ONLINE", "", ""},
		{"s-1", "Mesh AP", "", "", "", "ONLINE", "", "aa:bb:cc:00:00:22"},
	})
	sameRows(t, table(t, r, "Clients by device"), [][]string{
		{"s-1", "(none)", "0", "0", "1"},
		{"s-1", "d-1", "0", "0", "1"},
	})
}

func TestUnreadSiteIsNoted(t *testing.T) {
	f := newFake()
	f.sites = append(f.sites, map[string]any{"id": "s-gone", "name": "Gone"})
	h := f.handler()
	srv := serve(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/sites/s-gone/") {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		h.ServeHTTP(w, r)
	}))
	useBases(t, srv.URL+prefix)
	r, err := detectWith(testKey)
	if err != nil {
		t.Fatal(err)
	}
	if got := fact(r, "Not read"); !strings.Contains(got, "devices of site Gone: HTTP 500") {
		t.Errorf("not read %q", got)
	}
	if !strings.HasPrefix(r.Summary, "UniFi Network 9.0.114: 3 sites, 4 devices") {
		t.Errorf("summary %q", r.Summary)
	}
}

func TestProbe(t *testing.T) {
	// A plain web server: it refuses every path with JSON of its own and
	// has a status page of its own
	plain := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/status", "/proxy/network/status":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"status":"ok","meta":{"version":"2.4"}}`)
		default:
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"statusCode":401,"error":"Unauthorized","message":"Unauthorized"}`)
		}
	})
	htmlEverywhere := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, "<html><body>401 Authorization Required</body></html>")
	})
	statusPage := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/status" {
			http.NotFound(w, r)
			return
		}
		fmt.Fprint(w, `{"meta":{"rc":"ok","up":true,"server_version":"9.0.114","uuid":"00000000-0000-0000-0000-000000000000"},"data":[]}`)
	})
	classicRefusal := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"meta":{"rc":"error","msg":"api.err.LoginRequired"},"data":[]}`)
	})
	// A UniFi OS console (172.15.1.2): its page titled "UniFi OS", its
	// gateway refusing the API with no key, no status page with no login
	consoleRefusal := `{"error":{"code":401,"message":"Unauthorized"}}`
	console := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/":
			fmt.Fprint(w, `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>UniFi OS</title></head><body></body></html>`)
		case strings.HasPrefix(r.URL.Path, "/proxy/network/"):
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, consoleRefusal)
		default:
			http.NotFound(w, r)
		}
	})
	// The same refusal from a web server that is no UniFi OS console
	sameRefusal := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			fmt.Fprint(w, `<html><head><title>Router admin</title></head></html>`)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, consoleRefusal)
	})
	controller := newFake()

	for _, tc := range []struct {
		name string
		h    http.Handler
		want bool
	}{
		{"integration API refusing no key", controller.handler(), true},
		{"status page", statusPage, true},
		{"older API refusing no key", classicRefusal, true},
		{"UniFi OS console", console, true},
		{"the console's refusal from another web server", sameRefusal, false},
		{"plain web server", plain, false},
		{"401 web page everywhere", htmlEverywhere, false},
		{"404 everywhere", http.NotFoundHandler(), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := serve(t, tc.h)
			useBases(t, srv.URL+prefix, closedURL(t)+prefix)
			useStatusURLs(t, srv.URL+"/status", closedURL(t)+"/proxy/network/status")
			if got := (Module{}).Probe(context.Background(), "10.9.60.5"); got != tc.want {
				t.Errorf("Probe = %v, want %v", got, tc.want)
			}
		})
	}
	keys, _, _ := controller.requests()
	if len(keys) == 0 {
		t.Error("Probe asked the controller nothing")
	}
	for _, k := range keys {
		if k != "" {
			t.Errorf("Probe sent X-API-KEY %q, want none", k)
		}
	}

	t.Run("nothing listening", func(t *testing.T) {
		useBases(t, closedURL(t)+prefix)
		useStatusURLs(t, closedURL(t)+"/status")
		if (Module{}).Probe(context.Background(), "10.9.60.5") {
			t.Error("Probe = true with nothing listening")
		}
	})
	t.Run("a server that never answers", func(t *testing.T) {
		release := make(chan struct{})
		srv := serve(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			select {
			case <-r.Context().Done():
			case <-release:
			}
		}))
		t.Cleanup(func() { close(release) }) // before srv.Close, which waits for the handlers
		useBases(t, srv.URL+prefix)
		useStatusURLs(t, srv.URL+"/status")
		start := time.Now()
		if (Module{}).Probe(context.Background(), "10.9.60.5") {
			t.Error("Probe = true for a server that never answers")
		}
		if d := time.Since(start); d > probeTimeout+time.Second {
			t.Errorf("Probe took %v, want at most %v", d, probeTimeout)
		}
	})
}

func TestModule(t *testing.T) {
	m := modules.Find("unificontroller")
	if m == nil {
		t.Fatal("the module is not registered")
	}
	if m.Label() != "UniFi Network controller" || m.Type() != "unifi-controller" || m.Protocol() != "https" {
		t.Errorf("module %q %q %q", m.Label(), m.Type(), m.Protocol())
	}
	if a := m.Actions(); len(a) != 1 || a[0].ID != "detect" || a[0].Changes {
		t.Errorf("actions %+v", a)
	}
	if _, ok := m.(modules.Prober); !ok {
		t.Error("the module is no Prober")
	}
	if _, err := m.Run(context.Background(), modules.Request{IP: "10.9.60.5", Action: "reboot", Login: modules.Login{Password: testKey}}); err == nil {
		t.Error("an unknown action ran")
	}
}
