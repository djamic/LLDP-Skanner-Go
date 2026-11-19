package keriooperator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"

	"lldp_scanner/modules"
)

// Every name, number and address here is made up.

const (
	testUser     = "auditor"
	testPassword = "test-password-0123"
	testToken    = "token-abc"
	testCookie   = "SESSION_ADMIN"
)

// fakePBX is the administration of a Kerio Operator: its login page's
// constants and its JSON-RPC API, which takes testUser/testPassword and
// then wants the token and the session cookie.
type fakePBX struct {
	extensions []map[string]any
	phones     []map[string]any
	calls      []map[string]any
	history    []map[string]any
	pageSize   int  // the most rows of a page, 0: as asked
	noFields   bool // refuses a query with fields
	noOrder    bool // refuses a query with an order
	noPhones   bool // refuses Phones.get (an account without the right)

	mu      sync.Mutex
	methods []string // every method called
	queries []map[string]any
	logins  []string
	logouts int
}

func newFakePBX() *fakePBX {
	return &fakePBX{
		extensions: []map[string]any{
			{"guid": "e1", "telNum": "101", "sipUsername": "101", "FULL_NAME": "Ali Valiyev", "description": "Reception",
				"sipStatus": "Registered (sip:101@10.9.16.21:5060)", "userAgent": "Grandstream GXP1610 1.0.4.128", "phoneGuid": "p1", "disabled": false},
			{"guid": "e2", "telNum": "102", "sipUsername": "102", "USERNAME": "vali", "sipStatus": "Not registered", "phoneGuid": "p1"},
			{"guid": "e3", "telNum": "201", "sipUsername": "201", "FULL_NAME": "Olim Karimov", "sipStatus": "Registered",
				"userAgent": "Yealink SIP-T21P_E2 52.84.0.15"},
			{"guid": "e4", "telNum": "9", "sipUsername": "fax", "description": "Fax", "sipStatus": "Not registered", "disabled": true},
			{"guid": "e5", "telNum": "305", "sipUsername": "305", "FULL_NAME": "Lola", "sipStatus": map[string]any{"status": "registered", "contact": "10.9.16.40"}},
		},
		phones: []map[string]any{
			{"id": "p1", "hwAddress": "000B82AABB01", "phoneType": "Grandstream GXP1610", "description": "Front desk", "extensions": []any{"e1"}},
			{"id": "p2", "hwAddress": "00-15-65-aa-bb-02", "phoneType": "Yealink T21P E2", "extensions": []any{map[string]any{"telNum": "201"}}},
			{"id": "p3", "hwAddress": "", "phoneType": "Snom D120", "description": "Spare"},
		},
		calls: []map[string]any{{"id": 1, "FROM": "101", "TO": "201", "STATUS": "Answered", "ANSWERED_DURATION": 30, "CALL_DURATION": 35}},
		history: []map[string]any{
			{"FROM_NUM": "201", "FROM_PEER_IP": "10.9.16.31", "TO_NUM": "+998901234567", "TO_PEER_IP": "203.0.113.5"},
			{"FROM_NUM": "201", "FROM_PEER_IP": "10.9.16.99", "TO_NUM": "101"},
		},
	}
}

func (f *fakePBX) serve(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/admin/login/constants.php", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `x_2rc.x_4v = "Kerio Operator Administration";x_2rc.x_9t = "Kerio Operator Administration";`)
	})
	mux.HandleFunc("/admin/api/jsonrpc/", f.api)
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	old := adminBase
	adminBase = func(string) string { return srv.URL + "/admin" }
	t.Cleanup(func() { adminBase = old })
	return srv
}

func (f *fakePBX) api(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID     int             `json:"id"`
		Method string          `json:"method"`
		Params json.RawMessage `json:"params"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	reply := func(result any, err *rpcError) {
		ans := map[string]any{"jsonrpc": "2.0", "id": req.ID}
		if err != nil {
			ans["error"] = err
		} else {
			ans["result"] = result
		}
		json.NewEncoder(w).Encode(ans)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.methods = append(f.methods, req.Method)
	if req.Method == "Session.login" {
		var p struct {
			UserName, Password string
			Application        map[string]string
		}
		json.Unmarshal(req.Params, &p)
		f.logins = append(f.logins, p.UserName+"/"+p.Password)
		if p.UserName != testUser || p.Password != testPassword || p.Application["name"] == "" {
			reply(nil, &rpcError{Code: 1000, Message: "Invalid user name or password."})
			return
		}
		http.SetCookie(w, &http.Cookie{Name: testCookie, Value: "s1", Path: "/admin/"})
		reply(map[string]any{"token": testToken}, nil)
		return
	}
	if c, err := r.Cookie(testCookie); err != nil || c.Value != "s1" || r.Header.Get("X-Token") != testToken {
		reply(nil, &rpcError{Code: -32001, Message: "Invalid session."})
		return
	}
	var p struct {
		Query map[string]any `json:"query"`
	}
	json.Unmarshal(req.Params, &p)
	if p.Query != nil {
		f.queries = append(f.queries, p.Query)
	}
	page := func(root string, all []map[string]any) {
		if _, ok := p.Query["fields"]; ok && f.noFields {
			reply(nil, &rpcError{Code: -32602, Message: "Invalid params."})
			return
		}
		start, limit := int(p.Query["start"].(float64)), int(p.Query["limit"].(float64))
		if f.pageSize > 0 && limit > f.pageSize {
			limit = f.pageSize
		}
		end := min(start+limit, len(all))
		rows := []map[string]any{}
		if start < end {
			rows = all[start:end]
		}
		reply(map[string]any{root: rows, "totalItems": len(all)}, nil)
	}
	switch req.Method {
	case "Session.logout":
		f.logouts++
		reply(map[string]any{}, nil)
	case "Extensions.get":
		page("sipExtensionList", f.extensions)
	case "Phones.get":
		if f.noPhones {
			reply(nil, &rpcError{Code: 1001, Message: "Access denied."})
			return
		}
		page("phones", f.phones)
	case "Status.getCalls":
		reply(map[string]any{"calls": f.calls}, nil)
	case "CallHistory.get":
		if _, ok := p.Query["orderBy"]; ok && f.noOrder {
			reply(nil, &rpcError{Code: -32602, Message: "Invalid params."})
			return
		}
		reply(map[string]any{"callHistory": f.history, "totalItems": len(f.history)}, nil)
	default:
		reply(nil, &rpcError{Code: -32601, Message: "Method not found."})
	}
}

func testRequest(action string) modules.Request {
	return modules.Request{IP: "10.9.16.97", Action: action, Login: modules.Login{Username: testUser, Password: testPassword}}
}

// checkNoSecrets fails when a method that gives passwords was called, or
// a session that was used was left open.
func (f *fakePBX) checkNoSecrets(t *testing.T) {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, m := range f.methods {
		if strings.Contains(strings.ToLower(m), "password") {
			t.Errorf("%s was called", m)
		}
	}
	used := slices.ContainsFunc(f.methods, func(m string) bool { return !strings.HasPrefix(m, "Session.") })
	if used && f.logouts == 0 {
		t.Error("the session was not closed")
	}
}

func TestModule(t *testing.T) {
	m := modules.Find("keriooperator")
	if m == nil {
		t.Fatal("the module is not registered")
	}
	if m.Label() != "Kerio Operator" || m.Type() != "kerio-operator" || m.Protocol() != "https" {
		t.Errorf("module %q %q %q", m.Label(), m.Type(), m.Protocol())
	}
	if a := m.Actions(); len(a) != 1 || a[0].ID != "detect" || a[0].Changes {
		t.Errorf("actions %+v", a)
	}
	if _, ok := m.(modules.Prober); !ok {
		t.Error("the module is no Prober")
	}
	if _, ok := m.(modules.Inventorier); !ok {
		t.Error("the module is no Inventorier")
	}
	if _, err := m.Run(context.Background(), testRequest("reboot")); err == nil {
		t.Error("an unknown action ran")
	}
}

func TestProbe(t *testing.T) {
	newFakePBX().serve(t)
	if !(Module{}).Probe(context.Background(), "10.9.16.97") {
		t.Error("the PBX was not recognized")
	}
	other := httptest.NewTLSServer(http.NotFoundHandler())
	defer other.Close()
	adminBase = func(string) string { return other.URL + "/admin" }
	if (Module{}).Probe(context.Background(), "10.9.16.98") {
		t.Error("another web server was taken for the PBX")
	}
}

// TestDetect checks the result: the extensions with their status and
// phone address (from the SIP status, else the newest call), the
// provisioned phones with their extensions, the calls in progress.
func TestDetect(t *testing.T) {
	f := newFakePBX()
	f.serve(t)
	r, err := (Module{}).Run(context.Background(), testRequest("detect"))
	if err != nil {
		t.Fatal(err)
	}
	f.checkNoSecrets(t)
	if want := "Kerio Operator: 5 extensions (3 registered), 3 provisioned phones, 1 call in progress"; r.Summary != want {
		t.Errorf("summary %q, want %q", r.Summary, want)
	}
	facts := map[string]string{}
	for _, fa := range r.Facts {
		facts[fa.Label] = fa.Value
	}
	for label, want := range map[string]string{
		"Extensions":         "5: 3 registered, 2 not registered, 1 disabled",
		"Provisioned phones": "3",
		"Calls in progress":  "1",
		"Phone addresses":    "2 from the SIP status, 1 from the call history",
		"Extension fields":   "FULL_NAME, USERNAME, description, disabled, guid, phoneGuid, sipStatus, sipUsername, telNum, userAgent",
	} {
		if facts[label] != want {
			t.Errorf("fact %s = %q, want %q", label, facts[label], want)
		}
	}
	if len(r.Tables) != 3 {
		t.Fatalf("%d tables", len(r.Tables))
	}
	wantExt := [][]string{
		{"9", "", "Fax", "fax", "disabled Not registered", "", "", ""},
		{"101", "Ali Valiyev", "Reception", "101", "Registered (sip:101@10.9.16.21:5060)", "Grandstream GXP1610 1.0.4.128", "10.9.16.21", "00:0b:82:aa:bb:01"},
		{"102", "vali", "", "102", "Not registered", "", "", "00:0b:82:aa:bb:01"},
		{"201", "Olim Karimov", "", "201", "Registered", "Yealink SIP-T21P_E2 52.84.0.15", "10.9.16.31 (call history)", "00:15:65:aa:bb:02"},
		{"305", "Lola", "", "305", "contact: 10.9.16.40, status: registered", "", "10.9.16.40", ""},
	}
	if !reflect.DeepEqual(r.Tables[0].Rows, wantExt) {
		t.Errorf("extensions\n got %q\nwant %q", r.Tables[0].Rows, wantExt)
	}
	wantPhones := [][]string{
		{"", "Snom D120", "Spare", "", "", ""},
		{"00:0b:82:aa:bb:01", "Grandstream GXP1610", "Front desk", "101, 102", "10.9.16.21", "ONLINE"},
		{"00:15:65:aa:bb:02", "Yealink T21P E2", "", "201", "10.9.16.31", "ONLINE"},
	}
	if !reflect.DeepEqual(r.Tables[1].Rows, wantPhones) {
		t.Errorf("phones\n got %q\nwant %q", r.Tables[1].Rows, wantPhones)
	}
	if want := [][]string{{"101", "201", "Answered", "30", "35"}}; !reflect.DeepEqual(r.Tables[2].Rows, want) {
		t.Errorf("calls %q", r.Tables[2].Rows)
	}
}

// TestInventory checks the phones the scanner names: a provisioned phone
// by its MAC with all its extensions, a line on no provisioned phone by
// the IP of its phone, a line with no address not at all.
func TestInventory(t *testing.T) {
	f := newFakePBX()
	f.serve(t)
	inv, err := (Module{}).Inventory(context.Background(), testRequest(""))
	if err != nil {
		t.Fatal(err)
	}
	f.checkNoSecrets(t)
	want := []modules.ManagedDevice{
		{MAC: "00:0b:82:aa:bb:01", Name: "101, 102 · Ali Valiyev", Model: "Grandstream GXP1610", IP: "10.9.16.21", State: "ONLINE", Kind: "phone"},
		{MAC: "00:15:65:aa:bb:02", Name: "201 · Olim Karimov", Model: "Yealink T21P E2", IP: "10.9.16.31", State: "ONLINE", Kind: "phone"},
		{IP: "10.9.16.40", Name: "305 · Lola", State: "ONLINE", Kind: "phone"},
	}
	if !reflect.DeepEqual(inv.Devices, want) {
		t.Errorf("devices\n got %+v\nwant %+v", inv.Devices, want)
	}
	if len(inv.Notes) != 0 {
		t.Errorf("notes %q", inv.Notes)
	}
}

func TestLoginRefused(t *testing.T) {
	f := newFakePBX()
	f.serve(t)
	req := testRequest("detect")
	req.Login.Password = "wrong-password-xyz"
	_, err := (Module{}).Run(context.Background(), req)
	if !errors.Is(err, modules.ErrLoginRejected) {
		t.Fatalf("error %v, want a refused login", err)
	}
	if strings.Contains(err.Error(), "wrong-password-xyz") {
		t.Errorf("the error carries the password: %v", err)
	}
	req.Login.Username = " "
	if _, err := (Module{}).Inventory(context.Background(), req); !errors.Is(err, modules.ErrLoginRejected) {
		t.Errorf("no user name: %v", err)
	}
	f.checkNoSecrets(t)
}

// TestPagination reads lists the PBX gives a few rows at a time.
func TestPagination(t *testing.T) {
	f := newFakePBX()
	f.pageSize = 2
	for i := range 7 {
		f.extensions = append(f.extensions, map[string]any{"telNum": fmt.Sprint(400 + i), "sipStatus": "Not registered"})
	}
	f.serve(t)
	r, err := (Module{}).Run(context.Background(), testRequest("detect"))
	if err != nil {
		t.Fatal(err)
	}
	if got := len(r.Tables[0].Rows); got != 12 {
		t.Errorf("%d extensions read, want 12", got)
	}
	// pageLimit rows asked for; the server gave 2 and said 12, so it is
	// asked again from where it stopped
	var starts []float64
	for _, q := range f.queries {
		if _, ok := q["fields"]; ok && slices.Contains(q["fields"].([]any), "telNum") {
			starts = append(starts, q["start"].(float64))
		}
	}
	if !reflect.DeepEqual(starts, []float64{0, 2, 4, 6, 8, 10}) {
		t.Errorf("extension pages from %v", starts)
	}
}

// TestRefusedQueries: a PBX that refuses the fields or the order of a
// query is asked again without them; one that refuses the phones is read
// without them, with a note.
func TestRefusedQueries(t *testing.T) {
	f := newFakePBX()
	f.noFields, f.noOrder, f.noPhones = true, true, true
	f.serve(t)
	inv, err := (Module{}).Inventory(context.Background(), testRequest(""))
	if err != nil {
		t.Fatal(err)
	}
	want := []modules.ManagedDevice{
		{IP: "10.9.16.21", Name: "101 · Ali Valiyev", Model: "Grandstream GXP1610 1.0.4.128", State: "ONLINE", Kind: "phone"},
		{IP: "10.9.16.31", Name: "201 · Olim Karimov", Model: "Yealink SIP-T21P_E2 52.84.0.15", State: "ONLINE", Kind: "phone"},
		{IP: "10.9.16.40", Name: "305 · Lola", State: "ONLINE", Kind: "phone"},
	}
	if !reflect.DeepEqual(inv.Devices, want) {
		t.Errorf("devices\n got %+v\nwant %+v", inv.Devices, want)
	}
	if len(inv.Notes) != 1 || !strings.HasPrefix(inv.Notes[0], "provisioned phones: Phones.get: Access denied.") {
		t.Errorf("notes %q", inv.Notes)
	}
	f.checkNoSecrets(t)
}

func TestReadHelpers(t *testing.T) {
	for in, want := range map[string]string{
		"Registered": "ONLINE", "registered (10.0.0.5)": "ONLINE", "Not registered": "OFFLINE", "UNREGISTERED": "OFFLINE",
		"Unreachable": "OFFLINE", "OK": "ONLINE", "": "", "Ringing": "",
	} {
		if got := regState(in); got != want {
			t.Errorf("regState(%q) = %q, want %q", in, got, want)
		}
	}
	for in, want := range map[string]string{
		"sip:101@10.9.16.21:5060": "10.9.16.21", "0.0.0.0, 127.0.0.1, 10.1.2.3": "10.1.2.3", "999.1.1.1": "", "no address": "",
	} {
		if got := firstIPv4(in); got != want {
			t.Errorf("firstIPv4(%q) = %q, want %q", in, got, want)
		}
	}
	for in, want := range map[string]string{
		"000B82AABB01": "00:0b:82:aa:bb:01", "00-0b-82-aa-bb-01": "00:0b:82:aa:bb:01", "000b.82aa.bb01": "00:0b:82:aa:bb:01",
		"00:0b:82:aa:bb": "", "zz0b82aabb01": "", "": "",
	} {
		if got := normMAC(in); got != want {
			t.Errorf("normMAC(%q) = %q, want %q", in, got, want)
		}
	}
	for in, want := range map[string]string{
		`"x "`: "x", `12`: "12", `true`: "true", `null`: "", `["a",1,null]`: "a, 1",
		`{"status":"ok","sipPassword":"s3cret","ip":"10.0.0.1"}`: "ip: 10.0.0.1, status: ok",
	} {
		if got := rawText(json.RawMessage(in)); got != want {
			t.Errorf("rawText(%s) = %q, want %q", in, got, want)
		}
	}
}
