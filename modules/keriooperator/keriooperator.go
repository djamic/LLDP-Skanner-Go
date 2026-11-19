// Package keriooperator is the device module of Kerio Operator, the IP PBX
// (GFI). Over its administration API (JSON-RPC 2.0 at
// https://IP:4021/admin/api/jsonrpc/, a login of protocol "https" with an
// Operator account; an account with the read-only Auditor role is enough)
// it detects the PBX: its extensions (number, user, SIP registration, the
// phone's User-Agent), the phones it provisions (MAC, type, extensions) and
// the calls in progress. Its inventory names the network's phones by their
// extensions: a provisioned phone by its MAC, any other by the IP its
// extension registered from or last called from (the scanner matches that
// IP to the phone's node).
//
// GFI documents the API's login only; the methods and their fields are
// those of the administration's own web client (/admin/<screen>.js:
// Extensions.get, Phones.get, Status.getCalls, CallHistory.get). The
// methods that give SIP or phone passwords (Extensions.getSipPassword,
// Phones.getPassword) are never called.
// It recognizes the PBX with no login (Probe) by its administration's
// login page.
package keriooperator

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"lldp_scanner/modules"
)

func init() { modules.Register(Module{}) }

// Module is the Kerio Operator device module.
type Module struct{}

func (Module) ID() string       { return "keriooperator" }
func (Module) Label() string    { return "Kerio Operator" }
func (Module) Type() string     { return "kerio-operator" }
func (Module) Protocol() string { return "https" }

func (Module) Actions() []modules.Action {
	return []modules.Action{{ID: "detect", Label: "🔎 Detect"}}
}

// Run logs in with the request's login and runs the action.
func (Module) Run(ctx context.Context, req modules.Request) (modules.Result, error) {
	if req.Action != "detect" {
		return modules.Result{}, fmt.Errorf("unknown action %q", req.Action)
	}
	c, err := login(ctx, req.IP, req.Login)
	if err != nil {
		return modules.Result{}, err
	}
	defer c.close()
	p, err := read(ctx, c)
	if err != nil {
		return modules.Result{}, err
	}
	return detect(c, p), nil
}

// Probe tells, with no login, whether the administration of a Kerio
// Operator answers at ip: its login page's constants name the product
// ("Kerio Operator Administration").
func (Module) Probe(ctx context.Context, ip string) bool {
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	hc := newHTTPClient(probeTimeout)
	defer hc.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, adminBase(ip)+"/login/constants.php", nil)
	if err != nil {
		return false
	}
	resp, err := hc.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	return strings.Contains(string(body), "Kerio Operator")
}

// ─── What the PBX tells ───────────────────────────────────────────────────────

// The fields the web client asks for: its extension list's columns, its
// phone editor's
var (
	extensionFields = []string{"guid", "telNum", "sipUsername", "description", "USERNAME", "FULL_NAME", "EMAIL",
		"callPermissionName", "sipStatus", "userAgent", "disabled", "userGuid", "phoneGuid", "lineType", "linesCount", "parentId"}
	phoneFields = []string{"id", "hwAddress", "phoneType", "description", "label", "maxExtensionsCount", "extensions"}
)

// line is one SIP registration of an extension (an extension has one,
// or more with "Add Another Registration").
type line struct {
	guid, num, sipUser string
	name, desc         string // the user's full name, else user name; the extension's description
	status, userAgent  string
	state              string // regState of status
	ip, ipSource       string // its phone's IP: "SIP status" or "call history"
	phoneID            string
	disabled           bool
}

// who names the line's user: "Ali Valiyev", else the description.
func (l *line) who() string { return cmp.Or(l.name, l.desc) }

// phone is one phone the PBX provisions.
type phone struct {
	id, mac, hwAddress string
	model, desc        string
	nums               []string // its extensions
}

// pbx is what the scanner read of a PBX.
type pbx struct {
	lines      []*line
	phones     []*phone
	phonesRead bool
	calls      []row
	callsRead  bool
	extTotal   int
	phoneTotal int
	fields     []string // the fields the extensions came with, but secrets
	statuses   []string // a few SIP status values, as the API words them
	notes      []string // what could not be read
}

// read reads the extensions (the PBX is not read without them), the
// provisioned phones, the calls in progress, and, for the lines with no
// address in their status, the newest calls' addresses.
func read(ctx context.Context, c *client) (*pbx, error) {
	p := &pbx{}
	rows, total, err := c.listFields(ctx, "Extensions.get", "sipExtensionList", extensionFields)
	if err != nil {
		return nil, fmt.Errorf("extensions: %w", err)
	}
	p.extTotal = total
	if total > len(rows) {
		p.notes = append(p.notes, fmt.Sprintf("only the first %d of %d extensions", len(rows), total))
	}
	fields := map[string]bool{}
	for _, r := range rows {
		for k := range r {
			if !secretKey(k) {
				fields[k] = true
			}
		}
		l := &line{guid: r.text("guid", "id"), num: r.text("telNum"), sipUser: r.text("sipUsername"),
			name: r.text("FULL_NAME", "USERNAME"), desc: r.text("description"), status: r.text("sipStatus"),
			userAgent: r.text("userAgent"), phoneID: r.text("phoneGuid"), disabled: r.flag("disabled")}
		l.state = regState(l.status)
		if l.ip = firstIPv4(l.status); l.ip != "" {
			l.ipSource = "SIP status"
		}
		if l.status != "" && len(p.statuses) < 3 && !slices.Contains(p.statuses, l.status) {
			p.statuses = append(p.statuses, l.status)
		}
		p.lines = append(p.lines, l)
	}
	p.fields = slices.Sorted(maps.Keys(fields))

	if rows, total, err := c.listFields(ctx, "Phones.get", "phones", phoneFields); err != nil {
		p.notes = append(p.notes, "provisioned phones: "+err.Error())
	} else {
		p.phonesRead, p.phoneTotal = true, total
		for _, r := range rows {
			p.phones = append(p.phones, p.phoneOf(r))
		}
	}

	var res map[string]json.RawMessage
	if err := c.call(ctx, "Status.getCalls", map[string]any{}, &res); err != nil {
		p.notes = append(p.notes, "calls in progress: "+err.Error())
	} else if err := json.Unmarshal(res["calls"], &p.calls); err != nil && len(res["calls"]) > 0 {
		p.notes = append(p.notes, "calls in progress: unexpected answer")
	} else {
		p.callsRead = true
	}

	if slices.ContainsFunc(p.lines, func(l *line) bool { return l.ip == "" }) {
		if err := p.historyAddresses(ctx, c); err != nil {
			p.notes = append(p.notes, "call history: "+err.Error())
		}
	}
	return p, nil
}

// phoneOf reads one provisioned phone: its extensions are those it lists
// (by number, by GUID, or as objects) and those that name it.
func (p *pbx) phoneOf(r row) *phone {
	ph := &phone{id: r.text("id", "guid"), hwAddress: r.text("hwAddress"), model: r.text("phoneType"),
		desc: r.text("description", "label")}
	ph.mac = normMAC(ph.hwAddress)
	add := func(num string) {
		if num != "" && !slices.Contains(ph.nums, num) {
			ph.nums = append(ph.nums, num)
		}
	}
	var items []json.RawMessage
	json.Unmarshal(r["extensions"], &items)
	for _, it := range items {
		var obj row
		if json.Unmarshal(it, &obj) == nil && obj != nil {
			if num := obj.text("telNum", "number", "extension"); num != "" {
				add(num)
			} else {
				add(p.numOf(obj.text("guid", "id")))
			}
			continue
		}
		t := rawText(it)
		if p.hasNum(t) {
			add(t)
		} else {
			add(p.numOf(t))
		}
	}
	for _, l := range p.lines {
		if ph.id != "" && l.phoneID == ph.id {
			add(l.num)
		}
	}
	return ph
}

func (p *pbx) hasNum(num string) bool {
	return num != "" && slices.ContainsFunc(p.lines, func(l *line) bool { return l.num == num })
}

// numOf is the number of the extension with guid, "" when none.
func (p *pbx) numOf(guid string) string {
	for _, l := range p.lines {
		if guid != "" && l.guid == guid {
			return l.num
		}
	}
	return ""
}

// linesOf are the lines of the numbers, in their order.
func (p *pbx) linesOf(nums []string) []*line {
	var out []*line
	for _, n := range nums {
		for _, l := range p.lines {
			if l.num == n {
				out = append(out, l)
			}
		}
	}
	return out
}

// historyAddresses reads the newest calls (CallHistory.get) and gives each
// line that has no address the peer address of its newest call, and its
// User-Agent when it has none. A PBX that refuses the order is asked
// again with no order.
func (p *pbx) historyAddresses(ctx context.Context, c *client) error {
	query := map[string]any{"start": 0, "limit": historyLimit,
		"orderBy": []map[string]any{{"columnName": "TIMESTAMP", "direction": "Desc"}}}
	var res map[string]json.RawMessage
	err := c.call(ctx, "CallHistory.get", map[string]any{"query": query}, &res)
	if re := (*rpcError)(nil); errors.As(err, &re) {
		delete(query, "orderBy")
		err = c.call(ctx, "CallHistory.get", map[string]any{"query": query}, &res)
	}
	if err != nil {
		return err
	}
	var calls []row
	if err := json.Unmarshal(res["callHistory"], &calls); err != nil {
		return errors.New("no call list in its answer")
	}
	for _, r := range calls {
		for _, side := range []string{"FROM", "TO"} {
			ip := firstIPv4(r.text(side + "_PEER_IP"))
			if ip == "" {
				continue
			}
			for _, l := range p.lines {
				if l.num != "" && l.num == r.text(side+"_NUM") && l.ip == "" {
					l.ip, l.ipSource = ip, "call history"
					l.userAgent = cmp.Or(l.userAgent, r.text(side+"_USER_AGENT"))
				}
			}
		}
	}
	return nil
}

// regState reads a SIP status as a device state: "ONLINE" when it tells a
// registration, "OFFLINE" when it tells none, "" when it tells neither
// (the status is not documented: its words are read). A word of a
// registration negated ("Not available", "unreachable") tells none.
func regState(status string) string {
	s := strings.ToLower(status)
	for _, w := range []string{"offline", "disconnect", "fail"} {
		if strings.Contains(s, w) {
			return "OFFLINE"
		}
	}
	online := []string{"regist", "online", "reachable", "available"}
	for _, w := range online {
		for _, neg := range []string{"un", "not ", "no ", "non"} {
			if strings.Contains(s, neg+w) {
				return "OFFLINE"
			}
		}
	}
	for _, w := range online {
		if strings.Contains(s, w) {
			return "ONLINE"
		}
	}
	if s == "ok" {
		return "ONLINE"
	}
	return ""
}

// stateOf is the state of a phone of lines: ONLINE when one is, else
// OFFLINE when one is, else "".
func stateOf(lines []*line) string {
	state := ""
	for _, l := range lines {
		switch l.state {
		case "ONLINE":
			return "ONLINE"
		case "OFFLINE":
			state = "OFFLINE"
		}
	}
	return state
}

var ipv4Pattern = regexp.MustCompile(`\b\d{1,3}(?:\.\d{1,3}){3}\b`)

// firstIPv4 is the first usable IPv4 address in s ("sip:101@172.20.16.150:5060"),
// "" when none.
func firstIPv4(s string) string {
	for _, m := range ipv4Pattern.FindAllString(s, -1) {
		if a, err := netip.ParseAddr(m); err == nil && a.Is4() && !a.IsUnspecified() && !a.IsLoopback() {
			return a.String()
		}
	}
	return ""
}

// normMAC is a MAC address in canonical form ("00:0b:82:12:34:56") from
// any of the usual spellings, "" when s is none.
func normMAC(s string) string {
	var hex []byte
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f':
			hex = append(hex, byte(r))
		case r == ':' || r == '-' || r == '.' || r == ' ':
		default:
			return ""
		}
	}
	if len(hex) != 12 {
		return ""
	}
	parts := make([]string, 6)
	for i := range parts {
		parts[i] = string(hex[2*i : 2*i+2])
	}
	return strings.Join(parts, ":")
}

// label names a phone by its extensions and their user: "101 · Ali
// Valiyev", "101, 102 · Ali Valiyev"; fallback when the numbers are none.
func (p *pbx) label(nums []string, fallback string) string {
	if len(nums) == 0 {
		return fallback
	}
	who := ""
	for _, l := range p.linesOf(nums) {
		if who = l.who(); who != "" {
			break
		}
	}
	return strings.Join(slices.DeleteFunc([]string{strings.Join(nums, ", "), who}, func(s string) bool { return s == "" }), " · ")
}

// ─── Inventory ────────────────────────────────────────────────────────────────

// Inventory reads the phones the PBX knows, for the scanner's graph and
// tree (modules.Inventorier): each provisioned phone by its MAC, and each
// other line whose phone's IP is known by that IP, named by its
// extensions and user, with the phone's type (or User-Agent), IP and
// registration (ONLINE or OFFLINE). A PBX whose extensions cannot be read
// fails the read, so the scanner keeps the inventory it had.
func (Module) Inventory(ctx context.Context, req modules.Request) (modules.Inventory, error) {
	var inv modules.Inventory
	c, err := login(ctx, req.IP, req.Login)
	if err != nil {
		return inv, err
	}
	defer c.close()
	p, err := read(ctx, c)
	if err != nil {
		return inv, err
	}
	inv.Devices = p.devices()
	inv.Notes = p.notes
	return inv, nil
}

// devices are the phones of the inventory, sorted by name.
func (p *pbx) devices() []modules.ManagedDevice {
	var out []modules.ManagedDevice
	onPhone := map[string]bool{} // the numbers of the provisioned phones
	for _, ph := range p.phones {
		if ph.mac == "" {
			continue
		}
		lines := p.linesOf(ph.nums)
		d := modules.ManagedDevice{MAC: ph.mac, Name: p.label(ph.nums, cmp.Or(ph.desc, ph.mac)), Model: ph.model,
			State: stateOf(lines), Kind: "phone"}
		for _, l := range lines {
			d.IP = cmp.Or(d.IP, l.ip)
			d.Model = cmp.Or(d.Model, l.userAgent)
		}
		for _, n := range ph.nums {
			onPhone[n] = true
		}
		out = append(out, d)
	}
	seen := map[string]bool{} // the IPs listed
	for _, d := range out {
		seen[d.IP] = d.IP != ""
	}
	for _, l := range p.lines {
		if l.ip == "" || onPhone[l.num] || seen[l.ip] {
			continue
		}
		seen[l.ip] = true
		out = append(out, modules.ManagedDevice{IP: l.ip, Name: p.label([]string{l.num}, l.sipUser), Model: l.userAgent,
			State: l.state, Kind: "phone"})
	}
	slices.SortFunc(out, func(a, b modules.ManagedDevice) int {
		return cmp.Or(cmp.Compare(a.Name, b.Name), cmp.Compare(a.MAC, b.MAC), cmp.Compare(a.IP, b.IP))
	})
	return out
}

// ─── Detect ───────────────────────────────────────────────────────────────────

func detect(c *client, p *pbx) modules.Result {
	var r modules.Result
	macOf := map[string]string{} // number → its provisioned phone's MAC
	for _, ph := range p.phones {
		for _, n := range ph.nums {
			if _, ok := macOf[n]; !ok {
				macOf[n] = cmp.Or(ph.mac, ph.hwAddress)
			}
		}
	}

	exts := modules.Table{Title: "Extensions", Columns: []string{"Extension", "Name", "Description", "SIP user", "Status", "User-Agent", "IP", "Phone MAC"}}
	registered, unregistered, disabled, fromStatus, fromHistory := 0, 0, 0, 0, 0
	for _, l := range p.lines {
		switch l.state {
		case "ONLINE":
			registered++
		case "OFFLINE":
			unregistered++
		}
		if l.disabled {
			disabled++
		}
		ip := l.ip
		switch l.ipSource {
		case "SIP status":
			fromStatus++
		case "call history":
			fromHistory++
			ip += " (call history)"
		}
		status := l.status
		if l.disabled {
			status = strings.TrimSpace("disabled " + status)
		}
		exts.Rows = append(exts.Rows, []string{l.num, l.name, l.desc, l.sipUser, status, l.userAgent, ip, macOf[l.num]})
	}
	slices.SortFunc(exts.Rows, func(a, b []string) int { return cmp.Or(numCompare(a[0], b[0]), cmp.Compare(a[3], b[3])) })
	if p.extTotal > len(p.lines) {
		exts.Title += fmt.Sprintf(" (the first %d of %d)", len(p.lines), p.extTotal)
	}
	r.Tables = append(r.Tables, exts)

	if len(p.phones) > 0 {
		phones := modules.Table{Title: "Provisioned phones", Columns: []string{"MAC", "Type", "Description", "Extensions", "IP", "Status"}}
		for _, ph := range p.phones {
			lines := p.linesOf(ph.nums)
			ip := ""
			for _, l := range lines {
				ip = cmp.Or(ip, l.ip)
			}
			phones.Rows = append(phones.Rows, []string{cmp.Or(ph.mac, ph.hwAddress), ph.model, ph.desc, strings.Join(ph.nums, ", "), ip, stateOf(lines)})
		}
		slices.SortFunc(phones.Rows, func(a, b []string) int { return cmp.Or(numCompare(a[3], b[3]), cmp.Compare(a[0], b[0])) })
		r.Tables = append(r.Tables, phones)
	}

	if len(p.calls) > 0 {
		calls := modules.Table{Title: "Calls in progress", Columns: []string{"From", "To", "Status", "Answered (s)", "Duration (s)"}}
		for _, cl := range p.calls {
			calls.Rows = append(calls.Rows, []string{cl.text("FROM"), cl.text("TO"), cl.text("STATUS"), cl.text("ANSWERED_DURATION"), cl.text("CALL_DURATION")})
		}
		r.Tables = append(r.Tables, calls)
	}

	r.AddFact("Administration API", c.url)
	r.AddFact("Extensions", fmt.Sprintf("%d: %d registered, %d not registered, %d disabled", len(p.lines), registered, unregistered, disabled))
	if p.phonesRead {
		r.AddFact("Provisioned phones", strconv.Itoa(len(p.phones)))
	}
	if p.callsRead {
		r.AddFact("Calls in progress", strconv.Itoa(len(p.calls)))
	}
	r.AddFact("Phone addresses", fmt.Sprintf("%d from the SIP status, %d from the call history", fromStatus, fromHistory))
	r.AddFact("Extension fields", strings.Join(p.fields, ", "))
	r.AddFact("SIP status values", strings.Join(p.statuses, " | "))
	r.AddFact("Not read", strings.Join(p.notes, "; "))

	parts := []string{plural(len(p.lines), "extension") + fmt.Sprintf(" (%d registered)", registered)}
	if p.phonesRead {
		parts = append(parts, plural(len(p.phones), "provisioned phone"))
	}
	if p.callsRead {
		parts = append(parts, plural(len(p.calls), "call")+" in progress")
	}
	r.Summary = "Kerio Operator: " + strings.Join(parts, ", ")
	return r
}

// numCompare orders extension numbers as numbers when both are, else as
// text ("9" before "10", "101" before "1A").
func numCompare(a, b string) int {
	x, errA := strconv.Atoi(a)
	y, errB := strconv.Atoi(b)
	if errA == nil && errB == nil {
		return cmp.Compare(x, y)
	}
	return cmp.Compare(a, b)
}

// plural is "1 extension", "2 extensions".
func plural(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return strconv.Itoa(n) + " " + noun + "s"
}
