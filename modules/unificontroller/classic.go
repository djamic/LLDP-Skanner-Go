package unificontroller

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"lldp_scanner/modules"
)

// ─── The older API ────────────────────────────────────────────────────────────
//
// The application's older API, the one its own web pages use
// (/api/s/<site>/stat/sta, stat/device), tells more than the Integration
// API: of each Wi-Fi client its SSID, band, channel, signal, rates,
// traffic and DHCP host name, and of each device its kind and its uplink
// (the switch port its LLDP sees, or the access point of a mesh link).
// Newer applications take the API key there too; the others want the
// login of a local user (a login with a user name), as their web page
// does: a UniFi OS console at /api/auth/login, a self-hosted application
// at /api/login.

// classicClient talks the older API of one application, with the API key
// or in a login's session.
type classicClient struct {
	http   *http.Client
	base   string // "https://10.9.60.5:443/proxy/network", "https://10.9.60.5:8443"
	key    string // the API key; "" in a session
	csrf   string // the session's CSRF token (UniFi OS), sent to log out
	logout string // where the session logs out; "" with the key
	who    string // "the API key", "user NAME"
}

// loginRetry is how long a local user's login the application refused is
// not tried again: a wrong password tried at every inventory read could
// lock the account.
const loginRetry = time.Hour

var (
	refusedMu     sync.Mutex
	refusedLogins = map[string]time.Time{} // root|user|hash of the password → when
)

func refusedKey(root string, l modules.Login) string {
	sum := sha256.Sum256([]byte(l.Password))
	return root + "|" + l.Username + "|" + hex.EncodeToString(sum[:8])
}

// refusedRecently tells whether the application at root refused login l
// less than loginRetry ago.
func refusedRecently(root string, l modules.Login) bool {
	refusedMu.Lock()
	defer refusedMu.Unlock()
	at, ok := refusedLogins[refusedKey(root, l)]
	return ok && time.Since(at) < loginRetry
}

func noteRefused(root string, l modules.Login, refused bool) {
	refusedMu.Lock()
	defer refusedMu.Unlock()
	if refused {
		refusedLogins[refusedKey(root, l)] = time.Now()
	} else {
		delete(refusedLogins, refusedKey(root, l))
	}
}

// classicOpen finds the older API of the application whose Integration API
// ic talks: with the API key first, then with each login that has a user
// name. site is the internal name of a site ("default"), whose device
// list proves the API answers. The error says why there is none.
func classicOpen(ctx context.Context, ic *apiClient, site string, logins []modules.Login) (*classicClient, error) {
	probe := "/api/s/" + url.PathEscape(site) + "/stat/device-basic"
	root := strings.TrimSuffix(ic.base, integrationPath)
	var tried []string
	for _, base := range []string{root + "/proxy/network", root} {
		c := &classicClient{http: newHTTPClient(requestTimeout), base: base, key: ic.key, who: "the API key"}
		var devs []json.RawMessage
		err := c.get(ctx, probe, &devs)
		if err == nil {
			return c, nil
		}
		c.http.CloseIdleConnections()
		if ctx.Err() != nil {
			return nil, err
		}
		if errors.Is(err, modules.ErrLoginRejected) && !slices.Contains(tried, "it refuses the API key") {
			tried = append(tried, "it refuses the API key")
		}
	}
	users := 0
	for _, l := range logins {
		if strings.TrimSpace(l.Username) == "" || l.Password == "" {
			continue
		}
		users++
		who := "user " + l.Username
		if refusedRecently(root, l) {
			tried = append(tried, who+" was refused less than an hour ago")
			continue
		}
		c, err := classicLogin(ctx, root, l)
		if errors.Is(err, modules.ErrLoginRejected) {
			noteRefused(root, l, true)
			tried = append(tried, who+" is refused")
			continue
		}
		if err != nil {
			tried = append(tried, who+": "+err.Error())
			if ctx.Err() != nil {
				break
			}
			continue
		}
		noteRefused(root, l, false)
		var devs []json.RawMessage
		if err := c.get(ctx, probe, &devs); err != nil {
			c.close()
			tried = append(tried, who+": "+err.Error())
			continue
		}
		return c, nil
	}
	if users == 0 {
		tried = append(tried, "Credentials has no login with a user name for it (a local user of the controller)")
	}
	if len(tried) == 0 {
		tried = append(tried, "no older API answers")
	}
	return nil, errors.New(strings.Join(tried, "; "))
}

// classicLogin logs in as a local user at the application at root ("https://IP:443"):
// a UniFi OS console's /api/auth/login, else a self-hosted application's
// /api/login. A refused user or password wraps modules.ErrLoginRejected.
func classicLogin(ctx context.Context, root string, l modules.Login) (*classicClient, error) {
	body, _ := json.Marshal(map[string]any{"username": l.Username, "password": l.Password, "rememberMe": false})
	var tried []string
	for _, way := range []struct{ login, logout, base string }{
		{"/api/auth/login", "/api/auth/logout", root + "/proxy/network"}, // UniFi OS
		{"/api/login", "/api/logout", root},                              // self-hosted
	} {
		jar, _ := cookiejar.New(nil)
		hc := newHTTPClient(requestTimeout)
		hc.Jar = jar
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, root+way.login, bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		resp, err := hc.Do(req)
		if err != nil {
			return nil, err
		}
		io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		resp.Body.Close()
		switch resp.StatusCode {
		case http.StatusOK:
			csrf := resp.Header.Get("X-Updated-Csrf-Token")
			if csrf == "" {
				csrf = resp.Header.Get("X-Csrf-Token")
			}
			return &classicClient{http: hc, base: way.base, csrf: csrf, logout: root + way.logout, who: "user " + l.Username}, nil
		case http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden:
			// a self-hosted application answers 400 api.err.Invalid
			return nil, fmt.Errorf("%w: HTTP %d from %s", modules.ErrLoginRejected, resp.StatusCode, root+way.login)
		case http.StatusTooManyRequests:
			return nil, fmt.Errorf("too many logins (HTTP 429 from %s)", root+way.login)
		}
		hc.CloseIdleConnections()
		tried = append(tried, fmt.Sprintf("HTTP %d from %s", resp.StatusCode, root+way.login))
	}
	return nil, fmt.Errorf("no login page (%s)", strings.Join(tried, "; "))
}

// close logs a session out.
func (c *classicClient) close() {
	if c.logout != "" {
		ctx, cancel := context.WithTimeout(context.Background(), probeTimeout)
		if req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.logout, nil); err == nil {
			if c.csrf != "" {
				req.Header.Set("X-Csrf-Token", c.csrf)
			}
			if resp, err := c.http.Do(req); err == nil {
				io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
				resp.Body.Close()
			}
		}
		cancel()
	}
	c.http.CloseIdleConnections()
}

// get reads the data of one answer of the older API,
// {"meta":{"rc":"ok"},"data":[...]}, into out. A 401 or 403, or the
// answer that a login is needed, wraps modules.ErrLoginRejected; the error
// never carries the key.
func (c *classicClient) get(ctx context.Context, path string, out any) error {
	u := c.base + path
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	if c.key != "" {
		req.Header.Set("X-API-KEY", c.key)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusUnauthorized, http.StatusForbidden:
		return fmt.Errorf("%w: HTTP %d from %s", modules.ErrLoginRejected, resp.StatusCode, u)
	default:
		return &httpError{URL: u, Status: resp.StatusCode}
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return err
	}
	var answer struct {
		Meta struct {
			RC  string `json:"rc"`
			Msg string `json:"msg"`
		} `json:"meta"`
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(data, &answer); err != nil || answer.Meta.RC == "" {
		return fmt.Errorf("no JSON answer of the older API from %s", u)
	}
	if answer.Meta.RC != "ok" {
		if answer.Meta.Msg == "api.err.LoginRequired" {
			return fmt.Errorf("%w: %s from %s", modules.ErrLoginRejected, answer.Meta.Msg, u)
		}
		return fmt.Errorf("%s from %s", answer.Meta.Msg, u)
	}
	if err := json.Unmarshal(answer.Data, out); err != nil {
		return fmt.Errorf("an unknown answer from %s: %w", u, err)
	}
	return nil
}

// number is a JSON number the API may also send as a string ("5"), or
// leave out; anything else reads as 0.
type number float64

func (n *number) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	if f, err := strconv.ParseFloat(s, 64); err == nil {
		*n = number(f)
	}
	return nil
}

// station is one connected client of stat/sta.
type station struct {
	MAC          string `json:"mac"`
	Name         string `json:"name"`     // its name in the controller, when it was given one
	Hostname     string `json:"hostname"` // the name it gave DHCP
	IP           string `json:"ip"`
	IsWired      bool   `json:"is_wired"`
	APMAC        string `json:"ap_mac"`
	ESSID        string `json:"essid"`
	Radio        string `json:"radio"`       // "ng", "na", "6e"
	RadioProto   string `json:"radio_proto"` // "ax", "ac", "n", "be"
	Channel      number `json:"channel"`
	Signal       number `json:"signal"`  // dBm
	RxRate       number `json:"rx_rate"` // kbit/s
	TxRate       number `json:"tx_rate"`
	RxBytes      number `json:"rx_bytes"`
	TxBytes      number `json:"tx_bytes"`
	Uptime       number `json:"uptime"` // seconds
	OUI          string `json:"oui"`    // its vendor
	Network      string `json:"network"`
	VLAN         number `json:"vlan"`
	Satisfaction number `json:"satisfaction"` // 0-100, -1 when unknown
}

// bands names the radios of stat/sta.
var bands = map[string]string{"ng": "2.4 GHz", "na": "5 GHz", "6e": "6 GHz"}

// standards names the Wi-Fi standards of stat/sta's radio_proto.
var standards = map[string]string{"be": "Wi-Fi 7 (be)", "ax": "Wi-Fi 6 (ax)", "ac": "Wi-Fi 5 (ac)", "n": "Wi-Fi 4 (n)",
	"g": "802.11g", "a": "802.11a", "b": "802.11b"}

// apply gives a client what the station tells of it: its DHCP host name
// and vendor, and of a Wi-Fi client its network, radio and traffic.
func (s station) apply(c *modules.ManagedClient) {
	c.Hostname = strings.TrimSpace(s.Hostname)
	c.Vendor = strings.TrimSpace(s.OUI)
	c.Network = strings.TrimSpace(s.Network)
	c.VLAN = int(s.VLAN)
	if c.IP == "" {
		c.IP = strings.TrimSpace(s.IP)
	}
	if s.IsWired {
		return
	}
	c.SSID = strings.TrimSpace(s.ESSID)
	c.Band = bands[strings.ToLower(s.Radio)]
	c.Channel = int(s.Channel)
	c.Standard = standards[strings.ToLower(s.RadioProto)]
	if c.Standard == standards["ax"] && c.Band == bands["6e"] {
		c.Standard = "Wi-Fi 6E (ax)"
	}
	if s.Signal < 0 {
		c.Signal = int(s.Signal)
	}
	c.RxRate, c.TxRate = int(s.RxRate/1000), int(s.TxRate/1000)
	c.RxBytes, c.TxBytes = int64(s.RxBytes), int64(s.TxBytes)
	c.Uptime = int64(s.Uptime)
	if s.Satisfaction > 0 {
		c.Satisfaction = int(s.Satisfaction)
	}
}

// classicDevice is one device of stat/device: its kind and its uplink.
type classicDevice struct {
	MAC    string `json:"mac"`
	Type   string `json:"type"` // "uap", "usw", "ugw", "udm", "uxg", ...
	Uplink struct {
		Type       string `json:"type"` // "wire", "wireless"
		UplinkMAC  string `json:"uplink_mac"`
		APMAC      string `json:"ap_mac"` // the parent of a mesh link, in some versions
		RemotePort number `json:"uplink_remote_port"`
		Name       string `json:"name"` // its own port, "eth0"
	} `json:"uplink"`
	LastUplink struct {
		UplinkMAC  string `json:"uplink_mac"`
		RemotePort number `json:"uplink_remote_port"`
	} `json:"last_uplink"`
	// LLDP are its LLDP neighbors: the switch of a wired access point
	LLDP []struct {
		ChassisID     string `json:"chassis_id"`
		PortID        string `json:"port_id"`
		LocalPortName string `json:"local_port_name"`
	} `json:"lldp_table"`
}

// classicKinds names the device types of stat/device.
var classicKinds = map[string]string{"uap": "access_point", "usw": "switch", "ugw": "gateway", "udm": "gateway", "uxg": "gateway"}

// uplink is the device's uplink: the parent access point of a mesh link;
// else its LLDP neighbor, which names the switch's port (the one that is
// the uplink's device, when it names one); else the uplink's device and
// port number.
func (d classicDevice) uplink() *modules.ManagedUplink {
	lower := func(s string) string { return strings.ToLower(strings.TrimSpace(s)) }
	if parent := lower(firstOf(d.Uplink.UplinkMAC, d.Uplink.APMAC)); strings.EqualFold(d.Uplink.Type, "wireless") && parent != "" {
		return &modules.ManagedUplink{MAC: parent, Wireless: true}
	}
	up := lower(firstOf(d.Uplink.UplinkMAC, d.LastUplink.UplinkMAC))
	for _, n := range d.LLDP {
		if chassis := lower(n.ChassisID); chassis != "" && (up == "" || chassis == up) {
			return &modules.ManagedUplink{MAC: chassis, Port: strings.TrimSpace(n.PortID),
				LocalPort: firstOf(n.LocalPortName, d.Uplink.Name)}
		}
	}
	if up == "" {
		return nil
	}
	u := &modules.ManagedUplink{MAC: up, LocalPort: strings.TrimSpace(d.Uplink.Name)}
	if p := max(d.Uplink.RemotePort, d.LastUplink.RemotePort); p > 0 {
		u.Port = strconv.Itoa(int(p))
	}
	return u
}

// stations reads the connected clients of a site.
func (c *classicClient) stations(ctx context.Context, site string) ([]station, error) {
	var out []station
	err := c.get(ctx, "/api/s/"+url.PathEscape(site)+"/stat/sta", &out)
	return out, err
}

// devices reads the devices of a site.
func (c *classicClient) devices(ctx context.Context, site string) ([]classicDevice, error) {
	var out []classicDevice
	err := c.get(ctx, "/api/s/"+url.PathEscape(site)+"/stat/device", &out)
	return out, err
}
